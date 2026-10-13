package auth

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/admin"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

type adminFlowFixture struct {
	h       *GoogleHandlers
	svc     *gen.Service
	q       *gen.Queries
	issuer  *token.Issuer
	cfg     config.Config
	svcs    []gen.Service
	countFn func() int64
}

func newAdminFlowFixture(t *testing.T) *adminFlowFixture {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	// :memory: gir en egen tom database per tilkobling. Audit skriver fra en
	// goroutine, så poolen må holdes til én tilkobling for å se samme skjema.
	sqldb.SetMaxOpenConns(1)

	now := time.Now().UTC().Format(time.RFC3339)
	mkUser := func(email, roles string) gen.User {
		u, err := q.CreateUser(context.Background(), gen.CreateUserParams{Email: email, Roles: roles, Orgs: "lars", CreatedAt: now})
		require.NoError(t, err)
		return u
	}
	mkUser("konge@example.com", "user, konge")
	mkUser("vanlig@example.com", "user")
	mkUser("sysadmin@example.com", "sysadmin")
	deact := mkUser("deaktivert@example.com", "konge")
	require.NoError(t, q.DeactivateUser(context.Background(), gen.DeactivateUserParams{DeactivatedAt: &now, ID: deact.ID}))

	svcs := []gen.Service{{
		ID: "klarsyn", DisplayName: "Klarsyn", Domain: "klarsyn.net", IsDefault: 1,
		CallbackUrl: "https://klarsyn.net/auth/callback", AuthGoogle: 1,
		// Auto-registrering på: admin-flyten skal likevel aldri opprette brukere.
		AutoRegister: 1, Active: 1,
	}}
	issuer := token.NewIssuerForTest()
	cfg := config.Config{OIDCStateSecret: []byte("test-secret-32bytes-padded-here!")}
	auditSvc := audit.NewService(q)
	starter := admin.NewSessionStarter(issuer, auditSvc, 8*time.Hour)
	// Tjenesten må finnes i databasen for at den vanlige grenen skal kunne
	// utstede refresh-token.
	require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
		ID: "klarsyn", DisplayName: "Klarsyn", Domain: "klarsyn.net",
		CallbackUrl: "https://klarsyn.net/auth/callback", Theme: "light", AccentColor: "#000",
		EmailFromName: "Klarsyn", AuthGoogle: 1, AutoRegister: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: now,
	}))
	h := NewGoogleHandlers(cfg, q, issuer, token.NewRefreshService(q, auditSvc), service.NewRegistryForTest(svcs), auditSvc, starter)

	return &adminFlowFixture{h: h, svc: &svcs[0], q: q, issuer: issuer, cfg: cfg, svcs: svcs,
		countFn: func() int64 {
			n, err := q.CountUsers(context.Background())
			require.NoError(t, err)
			return n
		}}
}

func (f *adminFlowFixture) auditEvents(t *testing.T, wantType string, wantCount int) []gen.AuditEvent {
	t.Helper()
	var out []gen.AuditEvent
	require.Eventually(t, func() bool {
		all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
		require.NoError(t, err)
		out = out[:0]
		for _, e := range all {
			if e.EventType == wantType {
				out = append(out, e)
			}
		}
		return len(out) >= wantCount
	}, 2*time.Second, 10*time.Millisecond)
	return out
}

func cookieNamed(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestCompleteAdminLogin_ActiveKongeGetsAdminCookie(t *testing.T) {
	f := newAdminFlowFixture(t)
	before := f.countFn()

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	w := httptest.NewRecorder()
	f.h.finishCallback(w, req, f.svc, true, googleClaims{Email: "konge@example.com", EmailVerified: true})

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/admin/users", w.Header().Get("Location"))

	c := cookieNamed(w, "admin_token")
	require.NotNil(t, c)
	require.True(t, c.HttpOnly)
	require.Equal(t, "/admin", c.Path)
	claims, err := f.issuer.Verify(c.Value, token.ExpectAdmin)
	require.NoError(t, err)
	require.Equal(t, "konge@example.com", claims.Email)

	// R4: ingen JWT i noen URL i flyten.
	require.NotContains(t, w.Header().Get("Location"), c.Value)
	require.NotContains(t, w.Header().Get("Location"), "token=")
	require.Equal(t, before, f.countFn())

	ev := f.auditEvents(t, "admin_google_login", 1)
	require.Equal(t, int64(1), ev[0].Success)
	require.NotNil(t, ev[0].ServiceID)
	require.Equal(t, "klarsyn", *ev[0].ServiceID)
}

func TestCompleteAdminLogin_RejectsAndNeverCreatesUsers(t *testing.T) {
	for _, email := range []string{
		"vanlig@example.com",     // aktiv, uten konge
		"sysadmin@example.com",   // rolle som ligner men ikke eksakt match
		"ukjent@example.com",     // finnes ikke; auto_register på tjenesten må ikke slå inn
		"deaktivert@example.com", // deaktivert konge
		"",                       // tom e-post fra provider
	} {
		t.Run(email, func(t *testing.T) {
			f := newAdminFlowFixture(t)
			before := f.countFn()

			req := httptest.NewRequest(http.MethodGet, "/callback", nil)
			w := httptest.NewRecorder()
			f.h.finishCallback(w, req, f.svc, true, googleClaims{Email: email, EmailVerified: true})

			require.Equal(t, http.StatusSeeOther, w.Code)
			require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))
			require.Nil(t, cookieNamed(w, "admin_token"))
			require.Equal(t, before, f.countFn(), "admin-flyten skal aldri opprette brukere")

			require.False(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch"))
			ev := f.auditEvents(t, "admin_google_login", 1)
			require.Equal(t, int64(0), ev[0].Success)
			require.NotNil(t, ev[0].ServiceID)
			require.Equal(t, "klarsyn", *ev[0].ServiceID)
		})
	}
}

// AK2.9: init setter ikke redirect_uri-cookie (ei heller fra en query), og
// admin-formålet ligger i den signerte staten, i både cookie og Google-URL.
func TestInitiateAdminLogin_SignedAdminStateNoRedirectCookie(t *testing.T) {
	f := newAdminFlowFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/admin/google-init?redirect_uri=/admin/google-callback&purpose=admin", nil)
	req.Host = "klarsyn.net"
	w := httptest.NewRecorder()
	f.h.InitiateAdminLogin(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	require.Nil(t, cookieNamed(w, "redirect_uri"))

	sc := cookieNamed(w, "oidc_state")
	require.NotNil(t, sc)
	svc, admin, ok := parseState(f.cfg.OIDCStateSecret, sc.Value)
	require.True(t, ok)
	require.True(t, admin)
	require.Equal(t, "klarsyn", svc)

	loc, err := url.Parse(w.Header().Get("Location"))
	require.NoError(t, err)
	require.Equal(t, "accounts.google.com", loc.Host)
	require.Equal(t, sc.Value, loc.Query().Get("state"))
	require.Equal(t, "https://klarsyn.net/callback", loc.Query().Get("redirect_uri"))
}

// Vanlig init gir vanlig state; query-parametere kan ikke gjøre den til admin.
func TestInitiateLogin_StateIsNeverAdminFromQuery(t *testing.T) {
	f := newAdminFlowFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/social-login?purpose=admin&redirect_uri=/admin/google-callback", nil)
	req.Host = "klarsyn.net"
	w := httptest.NewRecorder()
	f.h.InitiateLogin(w, req)

	sc := cookieNamed(w, "oidc_state")
	require.NotNil(t, sc)
	_, admin, ok := parseState(f.cfg.OIDCStateSecret, sc.Value)
	require.True(t, ok)
	require.False(t, admin)
}

// Callbacken avgjør formål bare fra signert state: en vanlig state der
// angriperen har hektet ":admin" på payloaden, med den gamle MAC-en, gir 400
// både som cookie og som query før noe mot Google skjer.
func TestHandleCallback_ForgedAdminPurposeRejected(t *testing.T) {
	f := newAdminFlowFixture(t)
	payload := "klarsyn:nonce"
	forged := base64.RawURLEncoding.EncodeToString([]byte(payload + ":admin." + computeHMAC(f.cfg.OIDCStateSecret, payload)))

	req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state="+url.QueryEscape(forged), nil)
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: forged})
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Nil(t, cookieNamed(w, "admin_token"))
}

// Mutasjonsvern: vanlig gren (adminPurpose=false) for en konge gir /dispatch
// og aldri admin_token.
func TestFinishCallback_PlainLoginKongeGoesToDispatchWithoutAdminCookie(t *testing.T) {
	f := newAdminFlowFixture(t)
	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	w := httptest.NewRecorder()
	f.h.finishCallback(w, req, f.svc, false, googleClaims{Email: "konge@example.com", EmailVerified: true})

	require.Equal(t, http.StatusFound, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch?"), w.Header().Get("Location"))
	require.Nil(t, cookieNamed(w, "admin_token"))
}

func TestFinishCallback_Admin_EmailVerifiedRequiredAndNormalized(t *testing.T) {
	f := newAdminFlowFixture(t)

	// Ikke verifisert: avvist selv om kontoen er en konge.
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, true,
		googleClaims{Email: "konge@example.com", EmailVerified: false})
	require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))
	require.Nil(t, cookieNamed(w, "admin_token"))
	ev := f.auditEvents(t, "admin_google_login", 1)
	require.Equal(t, int64(0), ev[0].Success)

	// Store bokstaver og blanke rundt adressen normaliseres før oppslaget.
	w = httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, true,
		googleClaims{Email: "  Konge@Example.COM ", EmailVerified: true})
	require.Equal(t, "/admin/users", w.Header().Get("Location"))
	require.NotNil(t, cookieNamed(w, "admin_token"))
}

// S4: feil etter at staten er kjent som admin auditeres som mislykket
// admin-innlogging. Her via en admin-callback som feiler i kodeutvekslingen
// (ingen nett i testen; code er tom).
func TestHandleCallback_AdminFailureIsAudited(t *testing.T) {
	f := newAdminFlowFixture(t)
	st := signAdminState(f.cfg.OIDCStateSecret, "klarsyn", "n")
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+url.QueryEscape(st), nil)
	req.Host = "klarsyn.net"
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: st})
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, req)

	require.Equal(t, http.StatusUnauthorized, w.Code)
	ev := f.auditEvents(t, "admin_google_login", 1)
	require.Equal(t, int64(0), ev[0].Success)
	require.NotNil(t, ev[0].ServiceID)
	require.Equal(t, "klarsyn", *ev[0].ServiceID)
	require.NotNil(t, ev[0].Details)
}
