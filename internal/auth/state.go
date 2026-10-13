package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// statePurposeAdmin markerer at OIDC-flyten skal ende i en admin-sesjon, ikke
// en vanlig tjenesteinnlogging.
const statePurposeAdmin = "admin"

// SignState lager en HMAC-SHA256-signert state for en vanlig innlogging.
// payload = "serviceID:nonce"
// state   = base64RawURL( payload + "." + hmacHex )
func SignState(secret []byte, serviceID, nonce string) string {
	return signStatePayload(secret, serviceID+":"+nonce)
}

// signAdminState er SignState med formålet admin i den signerte payloaden.
// Formålet kan dermed aldri komme fra query, cookie eller redirect_uri: bare
// den som kan signere med OIDCStateSecret kan lage det.
// payload = "serviceID:nonce:admin"
func signAdminState(secret []byte, serviceID, nonce string) string {
	return signStatePayload(secret, serviceID+":"+nonce+":"+statePurposeAdmin)
}

func signStatePayload(secret []byte, payload string) string {
	mac := computeHMAC(secret, payload)
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + mac))
}

// VerifyState verifiserer en HMAC-signert state for en vanlig innlogging og
// returnerer serviceID. En admin-state avvises her, slik at den ikke kan
// gjenbrukes i en flyt som ikke kjenner til admin-formålet.
// Bruker hmac.Equal (tidskonstant) mot timing-angrep.
func VerifyState(secret []byte, state string) (serviceID string, ok bool) {
	serviceID, admin, ok := parseState(secret, state)
	if !ok || admin {
		return "", false
	}
	return serviceID, true
}

// parseState verifiserer HMAC og leser formålet. Formålet leses fra høyre:
// admin bare hvis siste segment er nøyaktig "admin" og payloaden har minst tre
// segmenter (serviceID, nonce, purpose). En tjeneste-ID som inneholder ":" kan
// dermed aldri forveksles med et formål. Eldre state uten purpose (utstedt før
// formål fantes, og fortsatt i omløp ved deploy) tolkes som vanlig innlogging.
func parseState(secret []byte, state string) (serviceID string, admin bool, ok bool) {
	b, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return "", false, false
	}
	raw := string(b)
	dot := strings.LastIndex(raw, ".")
	if dot < 0 {
		return "", false, false
	}
	payload, gotMAC := raw[:dot], raw[dot+1:]
	if !hmac.Equal([]byte(gotMAC), []byte(computeHMAC(secret, payload))) {
		return "", false, false
	}
	if rest, found := strings.CutSuffix(payload, ":"+statePurposeAdmin); found && strings.Contains(rest, ":") {
		payload, admin = rest, true
	}
	// Nonce er hex og har aldri ":", så siste ":" skiller tjeneste fra nonce.
	colon := strings.LastIndex(payload, ":")
	if colon < 0 {
		return "", false, false
	}
	return payload[:colon], admin, true
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
