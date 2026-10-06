package token_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
)

// jwtHeader dekoder JWT-headeren uten å verifisere signaturen — headeren er
// det vi tester her (typ), ikke gyldigheten.
func jwtHeader(t *testing.T, tok string) map[string]any {
	t.Helper()
	parts := strings.Split(tok, ".")
	require.Len(t, parts, 3, "et JWT har tre deler")
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var h map[string]any
	require.NoError(t, json.Unmarshal(raw, &h))
	return h
}

func userWithSubject(subjectID string) gen.User {
	u := testUser()
	u.SubjectID = &subjectID
	return u
}

// K4: access-tokenet fra authorization_code-flyten bærer scope fra koden, så
// en ressursserver kan håndheve minste privilegium på tokenet selv.
func TestIssueAccessForAudience_ScopeClaim(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccessForAudience(userWithSubject("abc123"), testService(), "https://drivstoffprisene.no", "openid priser:skriv")
	require.NoError(t, err)

	claims, err := iss.Verify(tok)
	require.NoError(t, err)
	require.Equal(t, "openid priser:skriv", claims.Scope)
	require.Equal(t, "access", claims.TokenUse)
}

// K4: RFC 9068 §2.1 — et access-token merkes at+jwt, slik at en
// ressursserver kan avvise et id_token som forsøkes brukt som adgangstoken.
func TestIssueAccessForAudience_TypHeaderAtJWT(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccessForAudience(userWithSubject("abc123"), testService(), "https://drivstoffprisene.no", "priser:skriv")
	require.NoError(t, err)
	require.Equal(t, "at+jwt", jwtHeader(t, tok)["typ"])
}

// Et id_token er ikke et access-token: det skal IKKE merkes at+jwt, og det
// skal ikke bære scope.
func TestIssueIDToken_IkkeAtJWTOgUtenScope(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueIDToken(userWithSubject("abc123"), testService(), "nonce-1")
	require.NoError(t, err)
	require.NotEqual(t, "at+jwt", jwtHeader(t, tok)["typ"])

	claims, err := iss.Verify(tok)
	require.NoError(t, err)
	require.Empty(t, claims.Scope)
	require.Equal(t, "id", claims.TokenUse)
	require.Equal(t, []string{"testsvc"}, []string(claims.Audience), "id_token sin aud er alltid client_id (OIDC Core §2)")
}

// K5: aud settes til ressursen klienten ba om, ikke client_id.
func TestIssueAccessForAudience_AudErRessursen(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccessForAudience(userWithSubject("abc123"), testService(), "https://drivstoffprisene.no", "priser:skriv")
	require.NoError(t, err)

	claims, err := iss.Verify(tok)
	require.NoError(t, err)
	require.Equal(t, []string{"https://drivstoffprisene.no"}, []string(claims.Audience))
}

// K6: sub er den opake subject_id-en, ikke e-postadressen — og e-posten
// ligger fortsatt i sin egen claim.
func TestSub_ErSubjectIDIkkeEpost(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccess(userWithSubject("f3a9c0d1e2b4a5968778695a4b3c2d1e"), testService())
	require.NoError(t, err)

	claims, err := iss.Verify(tok)
	require.NoError(t, err)
	require.Equal(t, "f3a9c0d1e2b4a5968778695a4b3c2d1e", claims.Subject)
	require.Equal(t, "test@example.com", claims.Email)
	require.NotEqual(t, claims.Email, claims.Subject, "sub skal ikke være e-post — den kan endres og gjenbrukes")
}

// K6: verifiseringsmetoden fra kravtabellen — sub endres ikke når brukerens
// e-post endres. Samme subject_id, ny e-post, samme sub.
func TestSub_UendretNaarEpostEndres(t *testing.T) {
	iss := newTestIssuer(t)
	foer := userWithSubject("stabil-id-1")
	etter := userWithSubject("stabil-id-1")
	etter.Email = "ny-adresse@example.com"

	tokFoer, err := iss.IssueAccess(foer, testService())
	require.NoError(t, err)
	tokEtter, err := iss.IssueAccess(etter, testService())
	require.NoError(t, err)

	cFoer, err := iss.Verify(tokFoer)
	require.NoError(t, err)
	cEtter, err := iss.Verify(tokEtter)
	require.NoError(t, err)

	require.Equal(t, cFoer.Subject, cEtter.Subject)
	require.NotEqual(t, cFoer.Email, cEtter.Email)
}

// En bruker uten subject_id (rad satt inn utenom CreateUser, eller før
// migrasjon 008) faller tilbake til e-post. Da er oppførselen identisk med
// før endringen — ikke dårligere.
func TestSub_FallerTilbakeTilEpostUtenSubjectID(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccess(testUser(), testService())
	require.NoError(t, err)

	claims, err := iss.Verify(tok)
	require.NoError(t, err)
	require.Equal(t, "test@example.com", claims.Subject)
}
