package token_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zral/kauth-go/internal/token"
)

func hentScopes(t *testing.T, iss *token.Issuer, extra ...string) []string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	w := httptest.NewRecorder()
	iss.DiscoveryHandler(extra...)(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("forventet 200, fikk %d", w.Code)
	}
	var doc struct {
		ScopesSupported []string `json:"scopes_supported"`
	}
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("discovery er ikke gyldig JSON: %v", err)
	}
	return doc.ScopesSupported
}

func likeScopes(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Et kall uten argumenter skal gi nøyaktig samme dokument som før, slik at
// eksisterende klienter ikke merker at parameteren finnes.
func TestDiscovery_UtenEkstraScopes(t *testing.T) {
	got := hentScopes(t, newTestIssuer(t))
	want := []string{"openid", "email", "profile"}
	if !likeScopes(got, want) {
		t.Errorf("scopes_supported = %v, forventet %v", got, want)
	}
}

func TestDiscovery_LeggerTilEkstraScope(t *testing.T) {
	got := hentScopes(t, newTestIssuer(t), "priser:skriv")
	want := []string{"openid", "email", "profile", "priser:skriv"}
	if !likeScopes(got, want) {
		t.Errorf("scopes_supported = %v, forventet %v", got, want)
	}
}

// Tomme verdier og duplikater av basis-scopene skal ikke gi støy i
// dokumentet — konfigurasjonen kommer fra et miljø der begge er lette å
// skrive inn ved et uhell.
func TestDiscovery_IgnorererTommeOgDuplikater(t *testing.T) {
	got := hentScopes(t, newTestIssuer(t), "", "openid", "priser:skriv", "priser:skriv")
	want := []string{"openid", "email", "profile", "priser:skriv"}
	if !likeScopes(got, want) {
		t.Errorf("scopes_supported = %v, forventet %v", got, want)
	}
}
