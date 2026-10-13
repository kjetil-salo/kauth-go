package auth_test

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

type confirmFixture struct {
	sqldb  *sql.DB
	q      *gen.Queries
	router chi.Router
}

func newConfirmFixture(t *testing.T) *confirmFixture {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	sqldb.SetMaxOpenConns(1)

	ctx := context.Background()
	now := time.Now().UTC().Format(time.RFC3339)
	mk := func(id, name, theme string, magic, active int64) {
		require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
			ID: id, DisplayName: name, Domain: id + ".test", CallbackUrl: "https://" + id + ".test/cb",
			Theme: theme, AccentColor: "#000", EmailFromName: name, AuthMagicLink: magic,
			JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: active, UpdatedAt: now,
		}))
	}
	mk("svca", "Tjeneste Alfa", "light", 1, 1)
	mk("svcb", "Tjeneste Beta", "dark", 1, 1)
	mk("inaktiv", "Tjeneste Inaktiv", "light", 1, 0)
	mk("utenmagic", "Tjeneste Utenmagic", "light", 0, 1)
	_, err = q.CreateUser(ctx, gen.CreateUserParams{Email: "bruker@example.com", Roles: "user", Orgs: "o", CreatedAt: now})
	require.NoError(t, err)

	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	aud := audit.NewService(q)
	h := auth.NewMagicHandlers(config.Config{}, q, mail.New(config.Config{SMTPMock: true}), token.NewIssuerForTest(),
		token.NewRefreshService(sqldb, aud), reg, aud, tmpl)
	r := chi.NewRouter()
	r.Get("/magic-login/{token}", h.ShowConfirm)
	r.Post("/magic-login/{token}", h.Redeem)
	return &confirmFixture{sqldb: sqldb, q: q, router: r}
}

func (f *confirmFixture) seed(t *testing.T, plain, serviceID string, expiresIn time.Duration) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, seedMagic(context.Background(), f.q, gen.InsertMagicTokenLimitedParams{
		TokenHash: token.HashOpaque(plain), Purpose: token.MagicPurposeService, Email: "bruker@example.com",
		ServiceID: &serviceID, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(expiresIn).Format(time.RFC3339),
	}))
}

func (f *confirmFixture) used(t *testing.T, plain string) int {
	t.Helper()
	var used int
	require.NoError(t, f.sqldb.QueryRow("SELECT used FROM magic_tokens WHERE token = ?", token.HashOpaque(plain)).Scan(&used))
	return used
}

func (f *confirmFixture) rows(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, f.sqldb.QueryRow("SELECT COUNT(*) FROM magic_tokens").Scan(&n))
	return n
}

func (f *confirmFixture) get(target string, hdr map[string]string) *httptest.ResponseRecorder {
	return f.do(http.MethodGet, target, hdr)
}

func (f *confirmFixture) do(method, target string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)
	return w
}

var sameOrigin = map[string]string{"Sec-Fetch-Site": "same-origin"}

func TestMagicConfirmGet_ValidTokenRendersButton(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "tok1", "svca", 15*time.Minute)
	before := f.rows(t)

	w := f.get("/magic-login/tok1?service=svca", nil)
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	require.Contains(t, body, `<form method="post" action="/magic-login/tok1?lang=en&amp;service=svca"`)
	require.NotContains(t, body, "bruker@example.com")
	require.NotContains(t, body, "<script")
	require.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	require.Contains(t, w.Header().Get("Vary"), "Accept-Language")
	require.Equal(t, 0, f.used(t, "tok1"), "GET skal ikke bruke opp tokenet")
	require.Equal(t, before, f.rows(t))
}

func TestMagicConfirmGet_Locales(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "tok1", "svca", 15*time.Minute)
	for lang, want := range map[string]string{"nb": "Logg inn", "en": "Sign in", "de": "Anmelden"} {
		w := f.get("/magic-login/tok1?lang="+lang, nil)
		require.Equal(t, http.StatusOK, w.Code, lang)
		require.Contains(t, w.Body.String(), `class="btn">`+want+`</button>`, lang)
		require.Contains(t, w.Body.String(), `<html lang="`+lang+`">`, lang)
	}
}

func TestMagicConfirmGet_UnknownOrExpired_RedirectsExpired(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "utlopt", "svca", -time.Minute)
	f.seed(t, "brukt", "svca", 15*time.Minute)
	_, err := f.sqldb.Exec("UPDATE magic_tokens SET used = 1 WHERE token = ?", token.HashOpaque("brukt"))
	require.NoError(t, err)
	for _, tok := range []string{"finnesikke", "utlopt", "brukt"} {
		w := f.get("/magic-login/"+tok+"?service=svca", nil)
		require.Equal(t, http.StatusFound, w.Code, tok)
		require.Contains(t, w.Header().Get("Location"), "error=expired", tok)
	}
}

func TestMagicConfirmGet_UsesStoredServiceTheme(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "tok1", "svca", 15*time.Minute)
	w := f.get("/magic-login/tok1?service=svcb", nil)
	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Tjeneste Alfa")
	require.NotContains(t, w.Body.String(), "Tjeneste Beta")
}

func TestMagicRedeem_BindsToStoredService(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "tok1", "svca", 15*time.Minute)
	req := httptest.NewRequest(http.MethodPost, "/magic-login/tok1?service=svcb", nil)
	req.Host = "svcb.test"
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "/dispatch?"), loc)
	require.Contains(t, loc, "&service=svca")
	require.NotContains(t, loc, "svcb")
	require.Equal(t, 1, f.used(t, "tok1"))

	var sid string
	require.Eventually(t, func() bool {
		return f.sqldb.QueryRow("SELECT service_id FROM audit_events WHERE event_type = 'magic_link_login'").Scan(&sid) == nil
	}, 2*time.Second, 20*time.Millisecond)
	require.Equal(t, "svca", sid)
}

func TestMagicRedeem_StoredServiceInactiveOrDisabled_Expired(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "t-inaktiv", "inaktiv", 15*time.Minute)
	f.seed(t, "t-utenmagic", "utenmagic", 15*time.Minute)
	for _, tok := range []string{"t-inaktiv", "t-utenmagic"} {
		w := f.get("/magic-login/"+tok, nil)
		require.Equal(t, http.StatusFound, w.Code, tok)
		require.Contains(t, w.Header().Get("Location"), "error=expired", tok)

		w = f.do(http.MethodPost, "/magic-login/"+tok, sameOrigin)
		require.Equal(t, http.StatusFound, w.Code, tok)
		require.Contains(t, w.Header().Get("Location"), "error=expired", tok)
		require.Empty(t, w.Result().Cookies(), tok)
	}
}

func TestMagicConfirmPost_SameOrigin_Consumes(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "tok1", "svca", 15*time.Minute)
	f.seed(t, "tok2", "svca", 15*time.Minute)

	w := f.do(http.MethodPost, "/magic-login/tok1", sameOrigin)
	require.Equal(t, http.StatusFound, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch?"))
	require.Equal(t, 1, f.used(t, "tok1"))

	// Origin uten Sec-Fetch-Site er også godkjent.
	w = f.do(http.MethodPost, "/magic-login/tok2", map[string]string{"Origin": "https://example.com"})
	require.Equal(t, http.StatusFound, w.Code)
	require.Equal(t, 1, f.used(t, "tok2"))
}

func TestMagicConfirmPost_CrossOrigin_403_NotConsumed(t *testing.T) {
	f := newConfirmFixture(t)
	f.seed(t, "tok1", "svca", 15*time.Minute)
	for name, hdr := range map[string]map[string]string{
		"cross-site":  {"Sec-Fetch-Site": "cross-site"},
		"same-site":   {"Sec-Fetch-Site": "same-site"},
		"none":        {"Sec-Fetch-Site": "none"},
		"origin-null": {"Origin": "null"},
		"ingen":       {},
	} {
		w := f.do(http.MethodPost, "/magic-login/tok1", hdr)
		require.Equal(t, http.StatusForbidden, w.Code, name)
		require.Contains(t, w.Body.String(), "Tjeneste Alfa", name)
		require.NotContains(t, w.Body.String(), "<form", name)
		require.Empty(t, w.Result().Cookies(), name)
		require.Equal(t, 0, f.used(t, "tok1"), name)
	}
}
