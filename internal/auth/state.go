package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// statePurposeAdmin markerer at OIDC-flyten skal ende i en admin-sesjon, ikke
// en vanlig tjenesteinnlogging.
const statePurposeAdmin = "admin"

// stateMaxAge og stateMaxSkew avgrenser hvor lenge en signert state er gyldig.
// Skjevheten tåler små klokkeavvik mellom instanser uten å akseptere state
// som er utstedt i fremtiden.
const (
	stateMaxAge  = 10 * time.Minute
	stateMaxSkew = 60 * time.Second
)

// now er injiserbar slik at utløp kan testes uten sleep.
var now = time.Now

// stateClaims er innholdet i en verifisert state.
type stateClaims struct {
	ServiceID string
	Nonce     string
	Admin     bool
}

// SignState lager en HMAC-SHA256-signert state for en vanlig innlogging.
// payload = "serviceID:nonce:iat"
// state   = base64RawURL( payload + "." + hmacHex )
func SignState(secret []byte, serviceID, nonce string) string {
	return signStatePayload(secret, serviceID+":"+nonce+":"+issuedAt())
}

// signAdminState er SignState med formålet admin i den signerte payloaden.
// Formålet kan dermed aldri komme fra query, cookie eller redirect_uri: bare
// den som kan signere med OIDCStateSecret kan lage det.
// payload = "serviceID:nonce:iat:admin"
func signAdminState(secret []byte, serviceID, nonce string) string {
	return signStatePayload(secret, serviceID+":"+nonce+":"+issuedAt()+":"+statePurposeAdmin)
}

func issuedAt() string {
	return strconv.FormatInt(now().Unix(), 10)
}

func signStatePayload(secret []byte, payload string) string {
	mac := computeHMAC(secret, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + mac))
}

// VerifyState verifiserer en HMAC-signert state for en vanlig innlogging og
// returnerer serviceID. En admin-state avvises her, slik at den ikke kan
// gjenbrukes i en flyt som ikke kjenner til admin-formålet.
func VerifyState(secret []byte, state string) (serviceID string, ok bool) {
	c, ok := parseState(secret, state)
	if !ok || c.Admin {
		return "", false
	}
	return c.ServiceID, true
}

// parseState verifiserer HMAC (tidskonstant, hmac.Equal mot timing-angrep),
// utstedelsestid og formål. Payloaden leses fra høyre: valgfritt ":admin",
// så iat, så nonce; resten er tjeneste-ID, som dermed kan inneholde ":".
// Admin gjelder bare når siste segment er nøyaktig "admin" og payloaden har
// minst fire segmenter. State uten gyldig iat (inkludert eldre format uten
// iat) avvises, og et ukjent formål havner i iat-posisjonen og avvises også.
func parseState(secret []byte, state string) (stateClaims, bool) {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return stateClaims{}, false
	}
	raw := string(b)
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		return stateClaims{}, false
	}
	payload, gotMAC := raw[:dot], raw[dot+1:]
	if !hmac.Equal([]byte(gotMAC), []byte(computeHMAC(secret, payload))) {
		return stateClaims{}, false
	}
	var c stateClaims
	if rest, found := strings.CutSuffix(payload, ":"+statePurposeAdmin); found && strings.Count(rest, ":") >= 2 {
		payload, c.Admin = rest, true
	}
	// iat og nonce er hex/tall og har aldri ":".
	i := strings.LastIndex(payload, ":")
	if i < 0 {
		return stateClaims{}, false
	}
	iat, err := strconv.ParseInt(payload[i+1:], 10, 64)
	if err != nil {
		return stateClaims{}, false
	}
	payload = payload[:i]
	n := strings.LastIndex(payload, ":")
	if n < 0 {
		return stateClaims{}, false
	}
	c.ServiceID, c.Nonce = payload[:n], payload[n+1:]

	issued := time.Unix(iat, 0)
	t := now()
	if t.Sub(issued) > stateMaxAge || issued.Sub(t) > stateMaxSkew {
		return stateClaims{}, false
	}
	return c, true
}

func computeHMAC(secret []byte, payload string) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func generateNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
