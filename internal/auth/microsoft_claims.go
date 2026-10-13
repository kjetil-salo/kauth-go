package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
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
	Email string `json:"email"`
	Name  string `json:"name"`
	Tid   string `json:"tid"`
	Iss   string `json:"iss"`
	Nonce string `json:"nonce"`
	// XmsEdov settes fra XmsEdovRaw etter dekoding (parseEdov). Microsoft
	// dokumenterer claimen som boolean, men formatet er ikke garantert likt for
	// alle kontotyper; et typeavvik skal ikke stenge ute personlige kontoer,
	// som uansett ikke bruker claimen.
	XmsEdov    *bool           `json:"-"`
	XmsEdovRaw json.RawMessage `json:"xms_edov"`
}

// parseEdov tolker xms_edov. Bare en entydig sann verdi (true, "true", "1",
// 1) gir true; alt annet, også ukjente formater, gir false. Verdien er
// signert av Microsoft, så dette er formattoleranse, ikke tillit til klienten.
func parseEdov(raw json.RawMessage) *bool {
	if len(raw) == 0 {
		return nil
	}
	v := false
	switch string(bytes.TrimSpace(raw)) {
	case "true", `"true"`, `"1"`, "1":
		v = true
	}
	return &v
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
	// domenet er verifisert; bare en entydig sann xms_edov godtas (parseEdov).
	if !strings.EqualFold(cl.Tid, msPersonalTenantID) && (cl.XmsEdov == nil || !*cl.XmsEdov) {
		return "", msReasonEdov
	}
	if strings.TrimSpace(cl.Email) == "" {
		return "", msReasonEmailMissing
	}
	return cl.Email, ""
}
