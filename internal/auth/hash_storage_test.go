package auth_test

import (
	"context"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"

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

// K1: magic-token lagres som SHA-256-hex, aldri som klartekst.
func TestMagicToken_StoredAsHash(t *testing.T) {
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	ctx := context.Background()
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "klarsyn", DisplayName: "Klarsyn", Domain: "klarsyn.net",
		CallbackUrl: "https://klarsyn.net/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Klarsyn",
		AuthMagicLink: 1, JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: "2026-01-01T00:00:00Z",
	}))
	_, err = q.CreateUser(ctx, gen.CreateUserParams{Email: "a@b.no", Roles: "user", Orgs: "o", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	cfg := config.Config{SMTPMock: true}
	h := auth.NewMagicHandlers(cfg, q, mail.New(cfg), token.NewIssuerForTest(), token.NewRefreshService(sqldb, audit.NewNoop()), reg, audit.NewNoop(), template.New("x"))

	req := httptest.NewRequest(http.MethodPost, "/magic-login", strings.NewReader(url.Values{"email": {"a@b.no"}, "service": {"klarsyn"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// Mock-mailen skriver lenken til stdout; klarteksten hentes derfra fordi
	// hash og klartekst er like lange.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	oldOut := os.Stdout
	os.Stdout = pw
	h.RequestLink(httptest.NewRecorder(), req)
	h.WaitForSends()
	os.Stdout = oldOut
	require.NoError(t, pw.Close())
	out, _ := io.ReadAll(pr)
	m := regexp.MustCompile(`/magic-login/([0-9a-f]+)`).FindStringSubmatch(string(out))
	require.NotNil(t, m, string(out))
	plain := m[1]

	var stored, purpose string
	require.NoError(t, sqldb.QueryRow("SELECT token, purpose FROM magic_tokens").Scan(&stored, &purpose))
	require.Equal(t, token.HashOpaque(plain), stored)
	require.NotEqual(t, plain, stored)
	require.Equal(t, token.MagicPurposeService, purpose)

	// Den lagrede hashen kan ikke brukes som lenke-token; klarteksten kan.
	r := chi.NewRouter()
	r.Get("/magic-login/{token}", h.VerifyToken)
	call := func(tok string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/magic-login/"+tok+"?service=klarsyn", nil))
		return w
	}
	require.Contains(t, call(stored).Header().Get("Location"), "error=expired")
	require.True(t, strings.HasPrefix(call(plain).Header().Get("Location"), "/dispatch?"))
}

// K20: autorisasjonskoden lagres som hash; klartekst går bare i redirecten.
func TestAuthorizationCode_StoredAsHash(t *testing.T) {
	h, q, user, iss := setupOIDCDispatchTest(t)
	svc, err := q.GetServiceByID(context.Background(), "veivakt")
	require.NoError(t, err)
	at, err := iss.IssueAccess(user, svc)
	require.NoError(t, err)

	w0 := httptest.NewRecorder()
	auth.SetOIDCAuthorizeCookie(w0, auth.OIDCAuthorizeRequest{
		ClientID: "veivakt", RedirectURI: "https://veivakt.app/auth/callback",
		State: "s", Nonce: "n", CodeChallenge: "c", CodeChallengeMethod: "S256",
	})
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at+"&service=veivakt", nil)
	for _, c := range w0.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)

	u, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	plain := u.Query().Get("code")
	require.NotEmpty(t, plain)

	row, err := q.GetAuthorizationCodeByHash(context.Background(), token.HashOpaque(plain))
	require.NoError(t, err)
	require.Len(t, row.Code, 64)
	require.NotEqual(t, plain, row.Code)
}
