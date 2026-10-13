package auth

import (
	"crypto/subtle"
	"regexp"
	"strings"
)

// msPersonalTenantID er tenant-ID for personlige Microsoft-kontoer (MSA).
// MSA gjenkjennes bare på dette; en manglende xms_edov gjør aldri et token
// til MSA.
const msPersonalTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

var msGUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Årsakskoder i audit-details. Lukket mengde, aldri IdP-tekst.
const (
	msReasonNonce        = "nonce"
	msReasonIssuer       = "issuer"
	msReasonEdov         = "edov"
	msReasonEmailMissing = "email_missing"
	msReasonClaimsDecode = "claims_decode"
)

// msClaims er det vi leser fra et signaturverifisert MS-id_token.
// Brukernavn-claimen er bevisst utelatt: den er ikke verifisert eier av
// en postadresse og kan ikke brukes som identitet.
type msClaims struct {
	Email   string `json:"email"`
	Name    string `json:"name"`
	Tid     string `json:"tid"`
	Iss     string `json:"iss"`
	Nonce   string `json:"nonce"`
	XmsEdov *bool  `json:"xms_edov"`
}

// validateMSClaims erstatter go-oidc sin issuer-sjekk (skrudd av fordi
// /common gir per-tenant iss). Signaturen er allerede verifisert. Rekkefølgen
// er nonce, issuer/tid, domeneverifisering, e-post. Ved avslag er reason ikke
// tom og email tom.
func validateMSClaims(cl msClaims, stateNonce string) (email string, reason string) {
	if stateNonce == "" || cl.Nonce == "" ||
		subtle.ConstantTimeCompare([]byte(cl.Nonce), []byte(stateNonce)) != 1 {
		return "", msReasonNonce
	}
	if !msGUIDPattern.MatchString(cl.Tid) || cl.Iss != "https://login.microsoftonline.com/"+cl.Tid+"/v2.0" {
		return "", msReasonIssuer
	}
	// Org-kontoer kan ha en e-postadresse tenant-admin har satt uten at
	// domenet er verifisert; bare xms_edov == true (JSON-bool) godtas.
	if !strings.EqualFold(cl.Tid, msPersonalTenantID) && (cl.XmsEdov == nil || !*cl.XmsEdov) {
		return "", msReasonEdov
	}
	if strings.TrimSpace(cl.Email) == "" {
		return "", msReasonEmailMissing
	}
	return cl.Email, ""
}
