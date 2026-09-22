package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

func pkceLoginFixture() []gen.Service {
	return []gen.Service{
		{ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
			CallbackUrl: "https://veivakt.app/auth/callback", RequiresPkce: 1, Active: 1},
		{ID: "minliste", DisplayName: "MinListe", Domain: "minliste.efugl.no",
			CallbackUrl: "https://minliste.efugl.no/auth/callback", RequiresPkce: 0, Active: 1},
	}
}

// Disse tre testene dekker guard-klausulene i ServeLogin sin OIDC-gren.
// Alle returnerer før noe template rendres, så LoginHandler.Templates kan
// stå urørt (nil) i testene.

func TestServeLogin_OIDC_UnknownClientIDRejected(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=ukjent&redirect_uri=https://evil.example.com/cb", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
}

func TestServeLogin_OIDC_UnregisteredRedirectURIRejected(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=veivakt&redirect_uri=https://ikke-registrert.example.com/cb&code_challenge=x&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "redirect_uri utenfor tjenestens allowlist skal ALDRI godtas")
}

// Kjernen i PKCE-håndhevelsen: en tjeneste med requires_pkce=1 skal avvise
// en /authorize-forespørsel uten code_challenge, FØR brukeren i det hele
// tatt får se innloggingssiden.
func TestServeLogin_OIDC_MissingPKCERejectedWhenRequired(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=veivakt&redirect_uri=https://veivakt.app/auth/callback", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "veivakt har requires_pkce=1 — manglende code_challenge skal avvises")
}

func TestServeLogin_OIDC_PlainMethodRejected(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet, "/login?response_type=code&client_id=veivakt&redirect_uri=https://veivakt.app/auth/callback&code_challenge=x&code_challenge_method=plain", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code, "kun S256 skal godtas, ikke plain")
}
