package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func TestGoogleInitiate_SendsNonceFromState(t *testing.T) {
	f := newAdminFlowFixture(t)
	for name, init := range map[string]func(http.ResponseWriter, *http.Request){
		"vanlig": f.h.InitiateLogin,
		"admin":  f.h.InitiateAdminLogin,
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/social-login", nil)
			req.Host = "klarsyn.net"
			w := httptest.NewRecorder()
			init(w, req)

			sc := cookieNamed(w, "oidc_state")
			require.NotNil(t, sc)
			claims, ok := parseState(f.cfg.OIDCStateSecret, sc.Value)
			require.True(t, ok)
			require.NotEmpty(t, claims.Nonce)

			loc, err := url.Parse(w.Header().Get("Location"))
			require.NoError(t, err)
			require.Equal(t, claims.Nonce, loc.Query().Get("nonce"))
		})
	}
}

func TestCheckIDTokenNonce(t *testing.T) {
	for _, tc := range []struct {
		name, tok, state string
		want             bool
	}{
		{"lik", "abc", "abc", true},
		{"ulik", "abc", "abd", false},
		{"ulik lengde", "abc", "abcd", false},
		{"tom i token", "", "abc", false},
		{"tom i state", "abc", "", false},
		{"begge tomme", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, checkIDTokenNonce(tc.tok, tc.state))
		})
	}
}

func TestGoogleCallback_BadState_RedirectsLoginFailed(t *testing.T) {
	f := newAdminFlowFixture(t)
	good := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n")
	for name, tc := range map[string]struct{ cookie, query string }{
		"uten cookie":    {"", good},
		"state ulik":     {good, good + "x"},
		"søppel":         {"søppel", "søppel"},
		"ikke signert":   {"a.b", "a.b"},
		"gammelt format": {"klarsyn:n", "klarsyn:n"},
		"tom begge":      {"", ""},
	} {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/callback?code=x&state="+url.QueryEscape(tc.query), nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "oidc_state", Value: tc.cookie})
			}
			w := httptest.NewRecorder()
			f.h.HandleCallback(w, req)

			require.Equal(t, http.StatusSeeOther, w.Code)
			require.Equal(t, "/login?error=login_failed", w.Header().Get("Location"))
			require.Empty(t, w.Result().Cookies())
			requireRedirectBodyOnly(t, w)
		})
	}
}

// Teknisk feil i vanlig gren gir generisk login_failed med tjenestens id og en
// audit-rad med årsak, uten feiltekst i responsen.
func TestGoogleCallback_ExchangeFailure_PlainBranchGeneric(t *testing.T) {
	f := newAdminFlowFixture(t)
	f.useFailingTokenEndpoint(t)
	st := SignState(f.cfg.OIDCStateSecret, "klarsyn", "n")
	req := httptest.NewRequest(http.MethodGet, "/callback?state="+url.QueryEscape(st), nil)
	req.Host = "klarsyn.net"
	req.AddCookie(&http.Cookie{Name: "oidc_state", Value: st})
	w := httptest.NewRecorder()
	f.h.HandleCallback(w, req)

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
	requireRedirectBodyOnly(t, w)
	ev := f.auditEvents(t, "google_oidc_rejected", 1)
	require.Equal(t, int64(0), ev[0].Success)
	require.NotNil(t, ev[0].Details)
	require.Equal(t, "reason=code_exchange", *ev[0].Details)
}

func TestGoogleFinish_EmailUnverified_Rejected(t *testing.T) {
	f := newAdminFlowFixture(t)
	before := f.countFn()
	for _, email := range []string{"konge@example.com", "ny@example.com"} {
		w := httptest.NewRecorder()
		f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
			googleClaims{Email: email, EmailVerified: false}, "n", "n")

		require.Equal(t, http.StatusSeeOther, w.Code)
		require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
		require.Empty(t, w.Result().Cookies())
	}
	require.Equal(t, before, f.countFn(), "ingen bruker skal opprettes")
	ev := f.auditEvents(t, "google_oidc_rejected", 2)
	require.NotNil(t, ev[0].Details)
	require.Equal(t, "reason=email_unverified", *ev[0].Details)
}

func TestGoogleFinish_NoAccountAndPolicy_IndistinguishableAccessDenied(t *testing.T) {
	f := newAdminFlowFixture(t)
	// Ingen konto: tjeneste uten auto-registrering.
	noReg := *f.svc
	noReg.AutoRegister = 0
	w1 := httptest.NewRecorder()
	f.h.finishCallback(w1, httptest.NewRequest(http.MethodGet, "/callback", nil), &noReg, false,
		googleClaims{Email: "ukjent@example.com", EmailVerified: true}, "n", "n")

	// Policybrudd: eksisterende bruker mangler påkrevd rolle.
	role := "admin"
	pol := *f.svc
	pol.RequireRole = &role
	w2 := httptest.NewRecorder()
	f.h.finishCallback(w2, httptest.NewRequest(http.MethodGet, "/callback", nil), &pol, false,
		googleClaims{Email: "vanlig@example.com", EmailVerified: true}, "n", "n")

	require.Equal(t, http.StatusSeeOther, w1.Code)
	require.Equal(t, "/login?error=access_denied&service=klarsyn", w1.Header().Get("Location"))
	require.Equal(t, w1.Code, w2.Code)
	require.Equal(t, w1.Header().Get("Location"), w2.Header().Get("Location"))
	requireRedirectBodyOnly(t, w1)
	requireRedirectBodyOnly(t, w2)
}

func TestGoogleFinish_ValidUserStillWorks(t *testing.T) {
	f := newAdminFlowFixture(t)
	w := httptest.NewRecorder()
	f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
		googleClaims{Email: "vanlig@example.com", EmailVerified: true}, "n", "n")
	require.Equal(t, http.StatusFound, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch?"))
}

// http.Redirect skriver en liten HTML-lenke til Location; alt annet i
// kroppen ville vært lekket feiltekst.
func requireRedirectBodyOnly(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	body := strings.TrimSpace(w.Body.String())
	require.True(t, body == "" || (strings.HasPrefix(body, "<a href=") && strings.HasSuffix(body, "</a>.")), body)
}

// useFailingTokenEndpoint peker kodeutvekslingen mot en lokal server som svarer
// 500, slik at testene ikke gjør nettverkskall mot Google.
func (f *adminFlowFixture) useFailingTokenEndpoint(t *testing.T) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "feil", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	f.h.endpoint = &oauth2.Endpoint{AuthURL: srv.URL + "/auth", TokenURL: srv.URL + "/token"}
}

func TestGoogleFinish_BadNonce_RejectedInBothBranches(t *testing.T) {
	for _, tc := range []struct{ name, tok, state string }{
		{"feil nonce", "annen", "n"},
		{"tom i token", "", "n"},
		{"tom i state", "n", ""},
		{"begge tomme", "", ""},
	} {
		t.Run("vanlig "+tc.name, func(t *testing.T) {
			f := newAdminFlowFixture(t)
			w := httptest.NewRecorder()
			f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, false,
				googleClaims{Email: "vanlig@example.com", EmailVerified: true}, tc.tok, tc.state)
			require.Equal(t, http.StatusSeeOther, w.Code)
			require.Equal(t, "/login?error=login_failed&service=klarsyn", w.Header().Get("Location"))
			require.Empty(t, w.Result().Cookies())
			ev := f.auditEvents(t, "google_oidc_rejected", 1)
			require.NotNil(t, ev[0].Details)
			require.Equal(t, "reason=nonce", *ev[0].Details)
		})
		t.Run("admin "+tc.name, func(t *testing.T) {
			f := newAdminFlowFixture(t)
			w := httptest.NewRecorder()
			f.h.finishCallback(w, httptest.NewRequest(http.MethodGet, "/callback", nil), f.svc, true,
				googleClaims{Email: "konge@example.com", EmailVerified: true}, tc.tok, tc.state)
			require.Equal(t, "/admin/login?err=ingen_tilgang", w.Header().Get("Location"))
			require.Nil(t, cookieNamed(w, "admin_token"))
			ev := f.auditEvents(t, "admin_google_login", 1)
			require.Equal(t, int64(0), ev[0].Success)
			require.NotNil(t, ev[0].Details)
			require.Equal(t, "reason=nonce", *ev[0].Details)
		})
	}
}
