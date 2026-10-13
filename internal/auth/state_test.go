package auth

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

var stateSecret = []byte("test-secret-32bytes-padded-here!")

func TestParseState_AdminRoundtrip(t *testing.T) {
	st := signAdminState(stateSecret, "klarsyn", "abc123")
	svc, admin, ok := parseState(stateSecret, st)
	require.True(t, ok)
	require.True(t, admin)
	require.Equal(t, "klarsyn", svc)
}

func TestParseState_LoginRoundtripIsNotAdmin(t *testing.T) {
	st := SignState(stateSecret, "klarsyn", "abc123")
	svc, admin, ok := parseState(stateSecret, st)
	require.True(t, ok)
	require.False(t, admin)
	require.Equal(t, "klarsyn", svc)
}

// Eldre state-format ("service:nonce", uten purpose) kan fortsatt ligge i
// oidc_state-cookies fra flyter som pågår ved deploy. De skal tolkes som
// vanlig login og ikke krasje.
func TestParseState_LegacyFormatIsPlainLogin(t *testing.T) {
	payload := "klarsyn:legacynonce"
	legacy := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + computeHMAC(stateSecret, payload)))
	svc, admin, ok := parseState(stateSecret, legacy)
	require.True(t, ok)
	require.False(t, admin)
	require.Equal(t, "klarsyn", svc)
}

func TestParseState_UnknownPurposeIsNeverAdmin(t *testing.T) {
	payload := "klarsyn:nonce:superuser"
	st := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + computeHMAC(stateSecret, payload)))
	_, admin, ok := parseState(stateSecret, st)
	require.True(t, ok)
	require.False(t, admin)
}

// Å legge til eller fjerne purpose uten å kunne signere skal gi ugyldig HMAC.
func TestParseState_TamperedPurposeFailsHMAC(t *testing.T) {
	// Vanlig state der angriperen hekter på ":admin" uten ny signatur.
	payload := "klarsyn:nonce"
	forged := base64.RawURLEncoding.EncodeToString([]byte(payload + ":admin." + computeHMAC(stateSecret, payload)))
	_, _, ok := parseState(stateSecret, forged)
	require.False(t, ok)

	// Admin-state der purpose strippes.
	adminPayload := "klarsyn:nonce:admin"
	stripped := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + computeHMAC(stateSecret, adminPayload)))
	_, _, ok = parseState(stateSecret, stripped)
	require.False(t, ok)
}

func TestParseState_WrongSecretFails(t *testing.T) {
	st := signAdminState(stateSecret, "klarsyn", "n")
	_, _, ok := parseState([]byte("annen-secret-32bytes-padded-!!!!"), st)
	require.False(t, ok)
}

// En admin-state skal ikke kunne gjenbrukes av flyter som bare kjenner
// VerifyState (Microsoft-callbacken): den gir ikke en vanlig innlogging.
func TestVerifyState_RejectsAdminState(t *testing.T) {
	_, ok := VerifyState(stateSecret, signAdminState(stateSecret, "klarsyn", "n"))
	require.False(t, ok)
}

// Tjeneste-ID med ":" skal rundturs riktig, og aldri forveksles med et formål.
func TestParseState_ServiceIDWithColon(t *testing.T) {
	svc, admin, ok := parseState(stateSecret, signAdminState(stateSecret, "a:b", "n1"))
	require.True(t, ok)
	require.True(t, admin)
	require.Equal(t, "a:b", svc)

	svc, admin, ok = parseState(stateSecret, SignState(stateSecret, "a:b", "n1"))
	require.True(t, ok)
	require.False(t, admin)
	require.Equal(t, "a:b", svc)

	// Tjeneste-ID "x:admin" i en vanlig state (x:admin:nonce) er ikke admin.
	svc, admin, ok = parseState(stateSecret, SignState(stateSecret, "x:admin", "n1"))
	require.True(t, ok)
	require.False(t, admin)
	require.Equal(t, "x:admin", svc)
}

// Færre enn tre segmenter kan aldri være admin.
func TestParseState_TwoSegmentsNamedAdminIsNotAdmin(t *testing.T) {
	payload := "klarsyn:admin"
	st := base64.RawURLEncoding.EncodeToString([]byte(payload + "." + computeHMAC(stateSecret, payload)))
	_, admin, ok := parseState(stateSecret, st)
	require.True(t, ok)
	require.False(t, admin)
}
