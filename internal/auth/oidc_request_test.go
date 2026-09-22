package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

func TestVerifyPKCE(t *testing.T) {
	verifier := "en-realistisk-lang-code-verifier-streng-her"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	require.True(t, auth.VerifyPKCE(verifier, challenge, "S256"), "riktig verifier skal godkjennes")
	require.False(t, auth.VerifyPKCE("feil-verifier", challenge, "S256"), "feil verifier skal avvises")
	require.False(t, auth.VerifyPKCE(verifier, challenge, "plain"), "plain-metoden støttes bevisst ikke")
	require.False(t, auth.VerifyPKCE("", challenge, "S256"), "tom verifier skal avvises")
	require.False(t, auth.VerifyPKCE(verifier, "", "S256"), "tom challenge skal avvises")
}

func TestOIDCAuthorizeCookie_RoundTrip(t *testing.T) {
	w := httptest.NewRecorder()
	original := auth.OIDCAuthorizeRequest{
		ClientID: "veivakt", RedirectURI: "https://veivakt.app/auth/callback",
		State: "xyz123", Nonce: "n-1", Scope: "openid email",
		CodeChallenge: "abc", CodeChallengeMethod: "S256",
	}
	auth.SetOIDCAuthorizeCookie(w, original)

	req := httptest.NewRequest(http.MethodGet, "/dispatch", nil)
	for _, c := range w.Result().Cookies() {
		req.AddCookie(c)
	}

	got, ok := auth.ReadOIDCAuthorizeCookie(req)
	require.True(t, ok)
	require.Equal(t, original, got)
}

func TestReadOIDCAuthorizeCookie_MissingReturnsFalse(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/dispatch", nil)
	_, ok := auth.ReadOIDCAuthorizeCookie(req)
	require.False(t, ok)
}

// setupOIDCDispatchTest kobler DispatchHandler til en ekte (in-memory)
// database, siden Nivå 0 (autorisasjonskode-utstedelse) faktisk skriver en
// rad — i motsetning til resten av dispatch-testene, som kun leser
// service.Registry.
func setupOIDCDispatchTest(t *testing.T) (*auth.DispatchHandler, *gen.Queries, gen.User, *token.Issuer) {
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
		AutoRegister: 1, AuthGoogle: 1, RequiresPkce: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "sjafor@example.com", Roles: "user", Orgs: "drivstoffprisene", CreatedAt: now,
	})
	require.NoError(t, err)

	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	iss := token.NewIssuerForTest()

	h := &auth.DispatchHandler{Registry: reg, Issuer: iss, Queries: q, DefaultSvcID: "veivakt"}
	return h, q, user, iss
}

// End-to-end for Nivå 0: en gyldig oidc_authz-cookie (satt av ServeLogin) skal
// gi en redirect med ?code=&state=, IKKE et token i klartekst i URL-en.
func TestDispatch_OIDCCookiePresent_IssuesAuthorizationCode(t *testing.T) {
	h, q, user, iss := setupOIDCDispatchTest(t)
	svc, err := q.GetServiceByID(context.Background(), "veivakt")
	require.NoError(t, err)
	at, err := iss.IssueAccess(user, svc)
	require.NoError(t, err)

	w0 := httptest.NewRecorder()
	auth.SetOIDCAuthorizeCookie(w0, auth.OIDCAuthorizeRequest{
		ClientID: "veivakt", RedirectURI: "https://veivakt.app/auth/callback",
		State: "state-abc", Nonce: "nonce-xyz", CodeChallenge: "c", CodeChallengeMethod: "S256",
	})

	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at, nil)
	for _, c := range w0.Result().Cookies() {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)

	require.Equal(t, http.StatusSeeOther, w.Code)
	loc := w.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://veivakt.app/auth/callback?code="), "skal redirecte med ?code=, fikk: %s", loc)
	require.Contains(t, loc, "state=state-abc", "state skal ekkoes tilbake uendret")
	require.NotContains(t, loc, at, "det rå access-tokenet skal ALDRI havne i redirect-URL-en for en OIDC-klient")

	// oidc_authz-cookien skal være ryddet (MaxAge < 0) etter bruk.
	cleared := false
	for _, c := range w.Result().Cookies() {
		if c.Name == "oidc_authz" && c.MaxAge < 0 {
			cleared = true
		}
	}
	require.True(t, cleared, "oidc_authz-cookien skal slettes etter at koden er utstedt")
}
