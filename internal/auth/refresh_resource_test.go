package auth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db/gen"
)

// fornyToken bytter inn et refresh-token på /token. Uten grant_type faller
// endepunktet til refresh-grant, slik eldre klienter gjør det.
func fornyToken(t *testing.T, h *auth.PasswordHandlers, refreshToken string, ekstra url.Values) map[string]any {
	t.Helper()
	form := url.Values{"refresh_token": {refreshToken}}
	for k, v := range ekstra {
		form[k] = v
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)
	require.Equal(t, http.StatusOK, w.Code, "fornyelse feilet: %s", w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// vekslKodeMedRessurs kjører en full code-runde mot en ressursindikator og
// returnerer svaret — utgangspunktet for fornyelsene under.
func vekslKodeMedRessurs(t *testing.T, h *auth.PasswordHandlers, q *gen.Queries, user gen.User, kode, scope, ressurs string) map[string]any {
	t.Helper()
	verifier, challenge := pkcePair()
	insertAuthCodeMedRessurs(t, q, kode, user.Email, "https://veivakt.app/auth/callback", challenge, scope, ressurs)

	w := vekslKode(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {kode},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, w.Code, "code-grant feilet: %s", w.Body.String())

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	return body
}

// Kjernen i feilen som stoppet Veivakt: fornyelsen ga et gyldig token uten
// aud og uten scope, så den delegerte fullmakten døde når det første
// access-tokenet utløp etter 15 minutter. Ressursserveren avviste alt
// etterpå, mens token-byttet selv svarte 200.
func TestRefreshGrant_BeholderAudOgScope(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	første := vekslKodeMedRessurs(t, h, q, user, "kode-ref-1", "openid priser:skriv", drivstoffRessurs)

	fornyet := fornyToken(t, h, første["refresh_token"].(string), nil)

	claims := jwtPayload(t, fornyet["access_token"].(string))
	require.Equal(t, []any{drivstoffRessurs}, claims["aud"], "fornyet token må bære samme aud som det første")
	require.Equal(t, "openid priser:skriv", claims["scope"], "scope skal ikke falle bort ved fornyelse")
	require.Equal(t, "openid priser:skriv", fornyet["scope"], "klienten skal kunne lese scopet uten å dekode tokenet")
}

// Bespoke-flyten (magic link, passord, Google, Microsoft) har aldri satt aud
// på access-tokens, og drivstoffprisene godtar aud-løse tokens på
// innloggingsveien nettopp derfor. Et refresh-token uten lagret resource må
// derfor fornyes som før — ellers låses all vanlig innlogging ut.
func TestRefreshGrant_UtenRessursGirIngenAud(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	første := vekslKodeMedRessurs(t, h, q, user, "kode-ref-2", "openid", "")

	fornyet := fornyToken(t, h, første["refresh_token"].(string), nil)

	claims := jwtPayload(t, fornyet["access_token"].(string))
	require.Nil(t, claims["aud"], "uten lagret resource skal fornyelsen være uendret: ingen aud")
	_, harScope := fornyet["scope"]
	require.False(t, harScope, "ingen fullmakt lagret gir ingen scope i svaret")
}

// Fullmakten følger hele token-familien, ikke bare første fornyelse: en
// widget som står på i dagevis roterer mange ganger, og nummer femten må
// være like gyldig som nummer én.
func TestRefreshGrant_FullmaktArvesGjennomFlereRotasjoner(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	første := vekslKodeMedRessurs(t, h, q, user, "kode-ref-3", "openid priser:skriv", drivstoffRessurs)

	rt := første["refresh_token"].(string)
	for runde := 1; runde <= 3; runde++ {
		fornyet := fornyToken(t, h, rt, nil)
		claims := jwtPayload(t, fornyet["access_token"].(string))
		require.Equal(t, []any{drivstoffRessurs}, claims["aud"], "runde %d mistet aud", runde)
		require.Equal(t, "openid priser:skriv", claims["scope"], "runde %d mistet scope", runde)
		rt = fornyet["refresh_token"].(string)
	}
}

// Fullmakten leses fra raden, aldri fra request-en. Ellers kunne den som
// sitter på et refresh-token utstedt for én ressurs veksle det inn til et
// token for en annen — eller skrive seg selv et bredere scope.
func TestRefreshGrant_KlientKanIkkeUtvideFullmakt(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	første := vekslKodeMedRessurs(t, h, q, user, "kode-ref-4", "openid", drivstoffRessurs)

	fornyet := fornyToken(t, h, første["refresh_token"].(string), url.Values{
		"resource": {"https://en-annen-tjeneste.example.com"},
		"scope":    {"openid priser:skriv admin"},
	})

	claims := jwtPayload(t, fornyet["access_token"].(string))
	require.Equal(t, []any{drivstoffRessurs}, claims["aud"], "aud skal komme fra raden, ikke fra formfeltet")
	require.Equal(t, "openid", claims["scope"], "scope skal komme fra raden, ikke fra formfeltet")
}

// Et refresh-token utstedt gjennom bespoke-flyten skal ikke kunne hente seg
// en aud ved å oppgi resource i fornyelsen.
func TestRefreshGrant_FormResourceGirIkkeAudUtenLagretFullmakt(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	første := vekslKodeMedRessurs(t, h, q, user, "kode-ref-5", "openid", "")

	fornyet := fornyToken(t, h, første["refresh_token"].(string), url.Values{
		"resource": {drivstoffRessurs},
	})

	require.Nil(t, jwtPayload(t, fornyet["access_token"].(string))["aud"])
}
