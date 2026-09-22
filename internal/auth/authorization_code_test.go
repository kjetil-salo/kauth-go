package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// pkcePair genererer et verifier/challenge-par slik en ekte OIDC-klient ville.
func pkcePair() (verifier, challenge string) {
	verifier = "test-code-verifier-som-er-lang-nok-til-a-vaere-realistisk-43-tegn"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return
}

func setupAuthCodeTest(t *testing.T, requiresPkce int64) (*auth.PasswordHandlers, *gen.Queries, gen.User, gen.Service) {
	t.Helper()
	ctx := context.Background()

	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
		CallbackUrl: "https://veivakt.app/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Veivakt",
		AutoRegister: 1, AuthGoogle: 1, AuthMagicLink: 1, RequiresPkce: requiresPkce,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))

	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "sjafor@example.com", Roles: "user", Orgs: "drivstoffprisene", CreatedAt: now,
	})
	require.NoError(t, err)
	svc, err := q.GetServiceByID(ctx, "veivakt")
	require.NoError(t, err)

	iss := token.NewIssuerForTest()
	aud := audit.NewNoop()
	refSvc := token.NewRefreshService(q, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))

	h := auth.NewPasswordHandlers(q, iss, refSvc, reg, aud)
	return h, q, user, svc
}

func insertAuthCode(t *testing.T, q *gen.Queries, code, email, redirectURI, challenge, method, nonce string) {
	t.Helper()
	expiresAt := time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z")
	var chPtr, methodPtr, noncePtr *string
	if challenge != "" {
		chPtr = &challenge
	}
	if method != "" {
		methodPtr = &method
	}
	if nonce != "" {
		noncePtr = &nonce
	}
	require.NoError(t, q.InsertAuthorizationCode(context.Background(), gen.InsertAuthorizationCodeParams{
		Code: code, ServiceID: "veivakt", Email: email, RedirectUri: redirectURI,
		CodeChallenge: chPtr, CodeChallengeMethod: methodPtr, Nonce: noncePtr,
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"), ExpiresAt: expiresAt,
	}))
}

// Happy path: en PKCE-krevende offentlig klient (som Veivakt) løser inn en
// gyldig kode med riktig code_verifier og får access_token + id_token +
// refresh_token tilbake.
func TestAuthorizationCodeGrant_ValidPKCE(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t, 1)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "test-code-1", user.Email, "https://veivakt.app/auth/callback", challenge, "S256", "nonce-abc")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"test-code-1"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var body map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.NotEmpty(t, body["access_token"])
	require.NotEmpty(t, body["id_token"], "id_token må være med i respons for en OIDC-klient")
	require.NotEmpty(t, body["refresh_token"])
	require.Equal(t, "Bearer", body["token_type"])
}

// En feil code_verifier (feil klient, eller angriper som fanget opp koden)
// skal avvises — nettopp det PKCE finnes for å hindre (RFC 7636).
func TestAuthorizationCodeGrant_WrongVerifierRejected(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t, 1)
	_, challenge := pkcePair()
	insertAuthCode(t, q, "test-code-2", user.Email, "https://veivakt.app/auth/callback", challenge, "S256", "")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"test-code-2"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {"feil-verifier"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	require.Equal(t, "invalid_grant", body["error"])
}

// En kode kan kun løses inn én gang (RFC 6749 §4.1.2) — andre forsøk skal
// avvises selv med riktig verifier.
func TestAuthorizationCodeGrant_CodeCannotBeReused(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t, 1)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "test-code-3", user.Email, "https://veivakt.app/auth/callback", challenge, "S256", "")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"test-code-3"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	}
	req1 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req1.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w1 := httptest.NewRecorder()
	h.Token(w1, req1)
	require.Equal(t, http.StatusOK, w1.Code)

	req2 := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w2 := httptest.NewRecorder()
	h.Token(w2, req2)
	require.Equal(t, http.StatusBadRequest, w2.Code)
}

// redirect_uri på /token må matche eksakt det koden ble utstedt for
// (RFC 6749 §4.1.3) — ellers kunne en kode avlyttet ett sted løses inn med
// en annen redirect_uri.
func TestAuthorizationCodeGrant_RedirectURIMismatchRejected(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t, 1)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "test-code-4", user.Email, "https://veivakt.app/auth/callback", challenge, "S256", "")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"test-code-4"},
		"redirect_uri": {"https://evil.example.com/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)
}

// En tjeneste uten requires_pkce (interne apper, back-compat) skal fungere
// uten code_verifier i det hele tatt.
func TestAuthorizationCodeGrant_NonPKCEServiceWorksWithoutVerifier(t *testing.T) {
	h, q, user, _ := setupAuthCodeTest(t, 0)
	insertAuthCode(t, q, "test-code-5", user.Email, "https://veivakt.app/auth/callback", "", "", "")

	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {"test-code-5"},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)

	require.Equal(t, http.StatusOK, w.Code)
}
