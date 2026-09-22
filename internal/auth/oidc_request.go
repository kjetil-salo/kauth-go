package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"os"
)

// OIDCAuthorizeRequest samler parameterne fra en standard OIDC authorization
// request (RFC 6749 §4.1 + PKCE, RFC 7636). Bæres videre gjennom hele
// innloggingsreisen (magic link, Google, Microsoft, passord) i en cookie,
// slik redirect_uri-cookien allerede bærer callback-mål for Google-flyten.
// Trust boundary: verdiene her stoles ikke på i seg selv — dispatch.go
// verifiserer RedirectURI mot tjenestens registrerte allowlist før bruk, og
// /token verifiserer CodeChallenge mot en client-oppgitt code_verifier før
// koden løses inn. Cookien er derfor ikke signert, samme tillitsmodell som
// den eksisterende redirect_uri-cookien.
type OIDCAuthorizeRequest struct {
	ClientID            string
	RedirectURI         string
	State               string
	Nonce               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
}

const oidcAuthzCookieName = "oidc_authz"

// IsOIDCAuthorizeRequest gjenkjenner en standard OIDC authorization request:
// response_type=code og client_id er begge påkrevd av spec.
func IsOIDCAuthorizeRequest(q url.Values) bool {
	return q.Get("response_type") == "code" && q.Get("client_id") != ""
}

// ParseOIDCAuthorizeRequest leser OIDC-parametre fra query-strengen.
func ParseOIDCAuthorizeRequest(q url.Values) OIDCAuthorizeRequest {
	return OIDCAuthorizeRequest{
		ClientID:            q.Get("client_id"),
		RedirectURI:         q.Get("redirect_uri"),
		State:               q.Get("state"),
		Nonce:               q.Get("nonce"),
		Scope:               q.Get("scope"),
		CodeChallenge:       q.Get("code_challenge"),
		CodeChallengeMethod: q.Get("code_challenge_method"),
	}
}

// SetOIDCAuthorizeCookie lagrer forespørselen i en kortlevd cookie som
// overlever resten av innloggingsreisen (samme origin gjennom hele flyten,
// fram til den eksterne redirect_uri-en til slutt).
func SetOIDCAuthorizeCookie(w http.ResponseWriter, req OIDCAuthorizeRequest) {
	v := url.Values{}
	v.Set("client_id", req.ClientID)
	v.Set("redirect_uri", req.RedirectURI)
	v.Set("state", req.State)
	v.Set("nonce", req.Nonce)
	v.Set("scope", req.Scope)
	v.Set("code_challenge", req.CodeChallenge)
	v.Set("code_challenge_method", req.CodeChallengeMethod)

	http.SetCookie(w, &http.Cookie{
		Name:     oidcAuthzCookieName,
		Value:    url.QueryEscape(v.Encode()),
		Path:     "/",
		MaxAge:   600, // 10 min — nok til å fullføre magic link/OIDC-runde
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	})
}

// ReadOIDCAuthorizeCookie leser og parser cookien satt av SetOIDCAuthorizeCookie.
// ok=false hvis cookien mangler eller ikke lar seg parse.
func ReadOIDCAuthorizeCookie(r *http.Request) (OIDCAuthorizeRequest, bool) {
	c, err := r.Cookie(oidcAuthzCookieName)
	if err != nil {
		return OIDCAuthorizeRequest{}, false
	}
	raw, err := url.QueryUnescape(c.Value)
	if err != nil {
		return OIDCAuthorizeRequest{}, false
	}
	v, err := url.ParseQuery(raw)
	if err != nil {
		return OIDCAuthorizeRequest{}, false
	}
	req := OIDCAuthorizeRequest{
		ClientID:            v.Get("client_id"),
		RedirectURI:         v.Get("redirect_uri"),
		State:               v.Get("state"),
		Nonce:               v.Get("nonce"),
		Scope:               v.Get("scope"),
		CodeChallenge:       v.Get("code_challenge"),
		CodeChallengeMethod: v.Get("code_challenge_method"),
	}
	if req.ClientID == "" || req.RedirectURI == "" {
		return OIDCAuthorizeRequest{}, false
	}
	return req, true
}

// ClearOIDCAuthorizeCookie fjerner cookien etter at den er konsumert (eller
// forkastet pga. en ugyldig forespørsel).
func ClearOIDCAuthorizeCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcAuthzCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	})
}

// VerifyPKCE sjekker at verifier hasher til challenge iht. RFC 7636 §4.6.
// Kun S256 støttes — "plain"-metoden gir ingen reell beskyttelse og tilbys
// bevisst ikke.
func VerifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method != "S256" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return computed == challenge
}

// GenerateAuthorizationCode lager en kryptografisk tilfeldig, urlsafe
// autorisasjonskode (32 byte / 256 bit entropi).
func GenerateAuthorizationCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
