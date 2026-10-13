package auth

import (
	"net/http"
	"net/url"
)

// loginErrorCode er en lukket mengde: typen gjør det umulig å sende
// IdP-/bibliotekstekst eller brukerstyrt innhold som ?error=-verdi.
type loginErrorCode string

const (
	// errCodeLoginFailed dekker alle tekniske feil i OIDC-flyten. Årsaken
	// hører hjemme i loggen, ikke i responsen.
	errCodeLoginFailed loginErrorCode = "login_failed"
	// errCodeAccessDenied brukes både for «ingen konto» og policybrudd, så de
	// ikke kan skilles fra hverandre utenfra.
	errCodeAccessDenied loginErrorCode = "access_denied"
)

// redirectLoginError sender brukeren tilbake til /login med en kjent feilkode.
// Den starter aldri IdP-en på nytt. Tom svcID utelater service-parameteren
// (f.eks. når staten er ugyldig og tjenesten dermed ikke er til å stole på).
func redirectLoginError(w http.ResponseWriter, r *http.Request, svcID string, code loginErrorCode) {
	q := url.Values{}
	q.Set("error", string(code))
	if svcID != "" {
		q.Set("service", svcID)
	}
	http.Redirect(w, r, "/login?"+q.Encode(), http.StatusSeeOther)
}

// redirectAdminLoginError sender admin tilbake til /admin/login med en fast
// feilkode som ikke avslører hvorfor innloggingen feilet.
func redirectAdminLoginError(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/login?err=ingen_tilgang", http.StatusSeeOther)
}
