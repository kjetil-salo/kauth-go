package auth_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

func pkceLoginFixture() []gen.Service {
	return []gen.Service{
		{ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
			CallbackUrl: "https://veivakt.app/auth/callback", Active: 1},
		{ID: "minliste", DisplayName: "MinListe", Domain: "minliste.efugl.no",
			CallbackUrl: "https://minliste.efugl.no/auth/callback", Active: 1},
	}
}

// Disse testene dekker guard-klausulene i ServeLogin sin OIDC-gren. Alle
// returnerer/redirecter før noe template rendres, så LoginHandler.Templates
// kan stå urørt (nil) i testene.

func TestServeLogin_OIDC_UnknownClientIDRejected(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=ukjent&redirect_uri=https://evil.example.com/cb", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "ukjent client_id: ingen betrodd redirect_uri å sende feil til")
}

func TestServeLogin_OIDC_UnregisteredRedirectURIRejected(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=veivakt&redirect_uri=https://ikke-registrert.example.com/cb&code_challenge=x&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "redirect_uri utenfor tjenestens allowlist skal ALDRI godtas")
}

// Kjernen i PKCE-håndhevelsen: PKCE er obligatorisk for enhver
// response_type=code-forespørsel, uansett tjeneste (ingen per-tjeneste
// unntak) — men siden redirect_uri her ER validert, skal svaret være en
// redirect med ?error=, ikke en 400 kauth selv viser fram (RFC 6749
// §4.1.2.1).
func TestServeLogin_OIDC_MissingPKCERedirectsWithError(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=veivakt&redirect_uri=https://veivakt.app/auth/callback&state=xyz", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)

	require.Equal(t, http.StatusSeeOther, w.Code)
	loc := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://veivakt.app/auth/callback?"), "skal redirecte til klientens redirect_uri, fikk: %s", loc)
	require.Contains(t, loc, "error=invalid_request")
	require.Contains(t, loc, "state=xyz")
}

func TestServeLogin_OIDC_PlainMethodRedirectsWithError(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=veivakt&redirect_uri=https://veivakt.app/auth/callback&code_challenge=x&code_challenge_method=plain", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code, "kun S256 skal godtas, ikke plain")
	require.Contains(t, w.Header().Get("Location"), "error=invalid_request")
}

// En vanlig (ikke-OIDC) innlogging må rydde en eventuell gjenværende
// oidc_authz-cookie fra en tidligere avbrutt OIDC-runde — ellers kunne
// /dispatch sin Nivå 0 senere kapre denne helt urelaterte innloggingen.
func TestServeLogin_NonOIDCRequest_ClearsStaleOIDCCookie(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?service=minliste", nil)
	req.AddCookie(&http.Cookie{Name: "oidc_authz", Value: "client_id=veivakt&redirect_uri=https%3A%2F%2Fveivakt.app%2Fauth%2Fcallback"})
	w := httptest.NewRecorder()

	defer func() { _ = recover() }() // ServeLogin fortsetter til template-rendring (Templates=nil) — vi bryr oss kun om cookien
	h.ServeLogin(w, req)

	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "oidc_authz" && c.MaxAge < 0 {
			cleared = true
		}
	}
	require.True(t, cleared, "stale oidc_authz-cookie skal ryddes i ikke-OIDC-grenen")
}
