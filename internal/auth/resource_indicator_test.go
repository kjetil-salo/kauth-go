package auth_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

const drivstoffRessurs = "https://drivstoffprisene.no"

// insertAuthCodeMedRessurs er insertAuthCode med resource satt — det
// dispatch.go skriver når klienten ba om en ressursindikator på /login.
func insertAuthCodeMedRessurs(t *testing.T, q *gen.Queries, code, email, redirectURI, challenge, scope, resource string) {
	t.Helper()
	expiresAt := time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z")
	var scopePtr, resPtr *string
	if scope != "" {
		scopePtr = &scope
	}
	if resource != "" {
		resPtr = &resource
	}
	require.NoError(t, q.InsertAuthorizationCode(context.Background(), gen.InsertAuthorizationCodeParams{
		Code: code, ServiceID: "veivakt", Email: email, RedirectUri: redirectURI,
		CodeChallenge: challenge, CodeChallengeMethod: "S256", Scope: scopePtr,
		Resource:  resPtr,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"), ExpiresAt: expiresAt,
	}))
}

// jwtPayload dekoder payloaden uten signaturverifisering. Signaturen er
// dekket av token-pakkens egne tester; her er det claims-innholdet som
// token-endepunktet faktisk produserte som skal inspiseres.
func jwtPayload(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3)
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(raw, &claims))
	return claims
}

func vekslKode(t *testing.T, h *auth.PasswordHandlers, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)
	return w
}

// K5: ba klienten om en ressurs, er det ressursen som står i aud — ikke
// client_id. Det er denne claimen drivstoffprisene håndhever for å vite at
// tokenet var ment for oss.
func TestTokenGrant_ResourceBlirAud(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	verifier, challenge := pkcePair()
	insertAuthCodeMedRessurs(t, q, "kode-res-1", user.Email, "https://veivakt.app/auth/callback", challenge, "openid priser:skriv", drivstoffRessurs)

	w := vekslKode(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {"kode-res-1"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	claims := jwtPayload(t, body["access_token"].(string))
	require.Equal(t, []any{drivstoffRessurs}, claims["aud"])
	require.Equal(t, "openid priser:skriv", claims["scope"])
	require.Equal(t, "access", claims["token_use"])
	require.Equal(t, "openid priser:skriv", body["scope"], "klienten skal kunne lese scopet uten å dekode tokenet")

	// id_token beholder client_id som aud selv når access-tokenet peker på en
	// ressurs — de to tokenene har ulike mottakere, og OIDC Core §2 er
	// tydelig på at et id_token tilhører klienten.
	idClaims := jwtPayload(t, body["id_token"].(string))
	require.Equal(t, []any{"veivakt"}, idClaims["aud"])
}

// Uten resource er oppførselen uendret: aud = client_id, som før etappe 2.
func TestTokenGrant_UtenResourceBeholderClientIDSomAud(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	verifier, challenge := pkcePair()
	insertAuthCodeMedRessurs(t, q, "kode-res-2", user.Email, "https://veivakt.app/auth/callback", challenge, "openid", "")

	w := vekslKode(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {"kode-res-2"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, []any{"veivakt"}, jwtPayload(t, body["access_token"].(string))["aud"])
}

// RFC 8707 §2.2: resource i token-requesten må være den koden ble utstedt
// for. Dette er selve grunnen til at verdien bæres i koden og ikke bare i
// formfeltet — ellers kunne den som fanget opp en kode selv valgt hvilken
// ressursserver tokenet skulle gjelde for.
func TestTokenGrant_FeilResourceIFormAvvises(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	verifier, challenge := pkcePair()
	insertAuthCodeMedRessurs(t, q, "kode-res-3", user.Email, "https://veivakt.app/auth/callback", challenge, "openid", drivstoffRessurs)

	w := vekslKode(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {"kode-res-3"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier}, "resource": {"https://en-annen-tjeneste.example.com"},
	})
	require.Equal(t, http.StatusBadRequest, w.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "invalid_target", body["error"])
}

// Sender klienten samme resource som koden ble utstedt for, går det gjennom.
func TestTokenGrant_MatchendeResourceIFormGodtas(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	verifier, challenge := pkcePair()
	insertAuthCodeMedRessurs(t, q, "kode-res-4", user.Email, "https://veivakt.app/auth/callback", challenge, "openid", drivstoffRessurs)

	w := vekslKode(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {"kode-res-4"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier}, "resource": {drivstoffRessurs},
	})
	require.Equal(t, http.StatusOK, w.Code)
}

// K6 gjennom ekte kodestier: sub i tokenene er brukerens subject_id fra
// CreateUser, ikke e-postadressen.
func TestTokenGrant_SubErOpakIkkeEpost(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t)
	verifier, challenge := pkcePair()
	insertAuthCodeMedRessurs(t, q, "kode-res-5", user.Email, "https://veivakt.app/auth/callback", challenge, "openid", drivstoffRessurs)

	w := vekslKode(t, h, url.Values{
		"grant_type": {"authorization_code"}, "code": {"kode-res-5"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	})
	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotNil(t, user.SubjectID, "CreateUser skal gi hver bruker en subject_id")
	require.NotEmpty(t, *user.SubjectID)

	for _, navn := range []string{"access_token", "id_token"} {
		claims := jwtPayload(t, body[navn].(string))
		require.Equal(t, *user.SubjectID, claims["sub"], "%s: sub skal være subject_id", navn)
		require.Equal(t, user.Email, claims["email"], "%s: e-post beholdes som egen claim", navn)
	}
}

// /login avviser en ugyldig ressursindikator per spec — med en redirect til
// klienten (redirect_uri er allerede validert på det punktet), ikke en 400.
func TestServeLogin_OIDC_UgyldigResourceGirInvalidTarget(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet,
		"/login?response_type=code&client_id=veivakt&redirect_uri=https://veivakt.app/auth/callback&code_challenge=x&code_challenge_method=S256&state=xyz&resource=https://drivstoffprisene.no/%23frag", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)

	require.Equal(t, http.StatusSeeOther, w.Code)
	loc := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://veivakt.app/auth/callback?"), "fikk: %s", loc)
	require.Contains(t, loc, "error=invalid_target")
	require.Contains(t, loc, "state=xyz")
}

// To resource-parametre: kauth utsteder ett token med én aud, så å godta
// begge og droppe den ene i stillhet ville gitt klienten et token den tror
// dekker mer enn det gjør.
func TestServeLogin_OIDC_FlereResourceAvvises(t *testing.T) {
	h := &auth.LoginHandler{Registry: service.NewRegistryForTest(pkceLoginFixture())}
	req := httptest.NewRequest(http.MethodGet,
		"/login?response_type=code&client_id=veivakt&redirect_uri=https://veivakt.app/auth/callback&code_challenge=x&code_challenge_method=S256&resource=https://a.example.com&resource=https://b.example.com", nil)
	w := httptest.NewRecorder()
	h.ServeLogin(w, req)

	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Contains(t, w.Header().Get("Location"), "error=invalid_target")
}

func TestValidResourceIndicator(t *testing.T) {
	gyldige := []string{"", "https://drivstoffprisene.no", "https://drivstoffprisene.no/api", "urn:eksempel:ressurs"}
	for _, res := range gyldige {
		require.True(t, auth.ValidResourceIndicator(res), "skulle vært gyldig: %q", res)
	}
	ugyldige := []string{
		"drivstoffprisene.no",               // ikke absolutt
		"/api/share/prices",                 // relativ
		"https://drivstoffprisene.no/#frag", // fragment (RFC 8707 §2)
		"https://drivstoffprisene.no#frag",  // fragment uten skråstrek
	}
	for _, res := range ugyldige {
		require.False(t, auth.ValidResourceIndicator(res), "skulle vært ugyldig: %q", res)
	}
}
