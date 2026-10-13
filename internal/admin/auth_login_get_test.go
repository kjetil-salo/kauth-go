package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/token"
)

// renderLoginGet kjører HandleLoginGet og returnerer HTML-responsen.
func renderLoginGet(t *testing.T, query string) string {
	t.Helper()
	t.Chdir("../..") // templates/ ligger relativt til prosjektroten

	h := NewAuthHandler(nil, token.NewIssuerForTest(), mail.New(config.Config{}), audit.NewNoop(), &config.Config{})
	w := httptest.NewRecorder()
	h.HandleLoginGet(w, httptest.NewRequest(http.MethodGet, "/admin/login"+query, nil))

	require.Equal(t, http.StatusOK, w.Code)
	return w.Body.String()
}

// HandleVerify og HandleGoogleCallback redirecter til /admin/login?err=<kode>
// ved avvist innlogging (ugyldig_token, ingen_tilgang, ingen_token), men
// HandleLoginGet ignorerte tidligere ?err= helt — brukeren ble bounce't
// tilbake til en blank innloggingsside uten noen forklaring på hvorfor.
func TestHandleLoginGet_ShowsErrorForKnownCode(t *testing.T) {
	body := renderLoginGet(t, "?err=ingen_tilgang")
	assert.Contains(t, body, "ikke tilgang til admin-panelet")
}

func TestHandleLoginGet_ShowsErrorForExpiredToken(t *testing.T) {
	body := renderLoginGet(t, "?err=ugyldig_token")
	assert.Contains(t, body, "ugyldig eller utløpt")
}

func TestHandleLoginGet_ShowsFallbackForUnknownCode(t *testing.T) {
	body := renderLoginGet(t, "?err=noe_helt_ukjent")
	assert.Contains(t, body, "Innlogging feilet")
}

func TestHandleLoginGet_NoErrParam_NoMessageShown(t *testing.T) {
	body := renderLoginGet(t, "")
	assert.NotContains(t, body, `class="msg`)
}
