package auth

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/service"
)

func TestRedirectLoginError(t *testing.T) {
	rr := httptest.NewRecorder()
	redirectLoginError(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), "klarsyn", errCodeLoginFailed)
	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/login?error=login_failed&service=klarsyn", rr.Header().Get("Location"))

	rr = httptest.NewRecorder()
	redirectLoginError(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), "a&b=c", errCodeAccessDenied)
	assert.Equal(t, "/login?error=access_denied&service=a%26b%3Dc", rr.Header().Get("Location"))

	rr = httptest.NewRecorder()
	redirectLoginError(rr, httptest.NewRequest(http.MethodGet, "/callback", nil), "", errCodeLoginFailed)
	assert.Equal(t, "/login?error=login_failed", rr.Header().Get("Location"))
}

func TestRedirectAdminLoginError(t *testing.T) {
	rr := httptest.NewRecorder()
	redirectAdminLoginError(rr, httptest.NewRequest(http.MethodGet, "/callback", nil))
	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login?err=ingen_tilgang", rr.Header().Get("Location"))
}

// M1 (008 F8): ugyldig eller utløpt state skal ikke gi intern tekst som
// «ugyldig HMAC», og skal ikke ende i en ny runde mot IdP-en.
func TestCallback_InvalidOrExpiredState_GenericRedirect(t *testing.T) {
	f := newAdminFlowFixture(t)
	secret := f.cfg.OIDCStateSecret

	orig := now
	t.Cleanup(func() { now = orig })
	now = func() time.Time { return orig().Add(-time.Hour) }
	expired := SignState(secret, "klarsyn", "n3")
	now = orig

	states := map[string]string{
		"utløpt":           expired,
		"søppel":           "soppel",
		"feil hemmelighet": SignState([]byte("annen-hemmelighet-32-bytes-long!!"), "klarsyn", "n"),
	}
	for name, st := range states {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/callback?state="+st+"&code=x", nil)
			req.AddCookie(&http.Cookie{Name: "oidc_state", Value: st})
			rr := httptest.NewRecorder()
			f.h.HandleCallback(rr, req)

			require.Equal(t, http.StatusSeeOther, rr.Code)
			assert.Equal(t, "/login?error=login_failed", rr.Header().Get("Location"))
			assert.NotContains(t, rr.Body.String(), "HMAC")
			assert.Empty(t, rr.Header().Values("Set-Cookie"))
		})

		t.Run("microsoft "+name, func(t *testing.T) {
			ms := NewMicrosoftHandlers(f.cfg, f.q, f.issuer, nil, service.NewRegistryForTest(f.svcs), nil)
			req := httptest.NewRequest(http.MethodGet, "/ms-callback?state="+st+"&code=x", nil)
			req.AddCookie(&http.Cookie{Name: "ms_state", Value: st})
			rr := httptest.NewRecorder()
			ms.HandleCallback(rr, req)

			require.Equal(t, http.StatusSeeOther, rr.Code)
			assert.Equal(t, "/login?error=login_failed", rr.Header().Get("Location"))
			assert.NotContains(t, rr.Body.String(), "HMAC")
			assert.Empty(t, rr.Header().Values("Set-Cookie"))
		})
	}
}

func renderPage(t *testing.T, name, locale, errCode string) string {
	t.Helper()
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	data := testPageData(t, "light", locale, "/login?service=test")
	data.Error = errCode
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, name, data))
	return out.String()
}

// K9: ukjent ?error= er innholdsforfalskning hvis den speiles; den skal gi
// den generiske teksten i begge malene.
func TestLoginPage_UnknownErrorNotReflected(t *testing.T) {
	for _, page := range []string{"login.html", "magic-login.html"} {
		for _, evil := range []string{"<script>x", "Kontakt support på evil.example", "ugyldig HMAC"} {
			out := renderPage(t, page, "nb", evil)
			assert.NotContains(t, out, "evil.example", page)
			assert.NotContains(t, out, "<script>x", page)
			assert.NotContains(t, out, "ugyldig HMAC", page)
			assert.Contains(t, out, i18n.Get("nb").ErrLoginFailed, page)
		}
	}
}

func TestLoginPage_LoginFailedText(t *testing.T) {
	want := map[string]string{
		"nb": "Innloggingen feilet.",
		"en": "Sign-in failed.",
		"de": "Anmeldung fehlgeschlagen.",
	}
	for locale, text := range want {
		for _, page := range []string{"login.html", "magic-login.html"} {
			assert.Contains(t, renderPage(t, page, locale, "login_failed"), text, "%s %s", page, locale)
		}
	}
	assert.Contains(t, renderPage(t, "login.html", "en", "access_denied"), "Access denied.")
	assert.Contains(t, renderPage(t, "login.html", "en", "invalid_redirect"), "Invalid return address")
}
