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

func strPtrPolicy(s string) *string { return &s }

// Regresjonstest for angrepet Lars beskrev i PR-diskusjonen
// (github.com/zral/kauth-go/pull/1): ?service= på /dispatch er en
// URL-parameter angriperen selv styrer — ikke en verdi bundet til tokenet
// (vanlige access-tokens har ingen aud). En bruker med et GYLDIG token for
// tjeneste B (som de har lovlig tilgang til) kan derfor, mens de har en
// legitim oidc_authz-cookie for tjeneste A liggende (fra å ha klikket
// "logg inn" i partner-app A), hoppe forbi A sin egen login-handler helt
// og gå rett til /dispatch?token=<B-token>&service=A.
//
// service-ID-sjekken i dispatch.go (lagt til i forrige revisjon) stopper
// IKKE dette — den sjekker bare at URL-en er intern konsistent
// (?service=A == cookiens client_id), ikke at brukeren faktisk har rett
// til A. Det er derfor /token MÅ håndheve svc.RequireRole/EnforceOrg for
// A på nytt (via checkPolicy) idet koden løses inn — det er det eneste
// stedet i hele flyten som faktisk kan vite hvilken tjeneste som skal
// autorisere brukeren.
func TestAuthorizationCodeGrant_RejectsUserWithoutRequiredRoleEvenWithValidCodeAndPKCE(t *testing.T) {
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	now := time.Now().UTC().Format(time.RFC3339)
	// Tjeneste A: veivakt, krever rollen "partner" — det brukeren i dette
	// scenarioet IKKE har.
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
		CallbackUrl: "https://veivakt.app/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Veivakt",
		AuthGoogle: 1, RequireRole: strPtrPolicy("partner"),
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	// Tjeneste B: minliste, ingen rollekrav — brukeren har lovlig tilgang.
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "minliste", DisplayName: "MinListe", Domain: "minliste.efugl.no",
		CallbackUrl: "https://minliste.efugl.no/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "MinListe",
		AuthGoogle: 1, JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "angriper@example.com", Roles: "user", Orgs: "drivstoffprisene", CreatedAt: now,
	})
	require.NoError(t, err)

	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	iss := token.NewIssuerForTest()
	aud := audit.NewNoop()
	refSvc := token.NewRefreshService(q, aud)
	dispatchH := &auth.DispatchHandler{Registry: reg, Issuer: iss, Queries: q, DefaultSvcID: "minliste"}
	tokenH := auth.NewPasswordHandlers(q, iss, refSvc, reg, aud)

	svcB, err := q.GetServiceByID(ctx, "minliste")
	require.NoError(t, err)

	// Steg 1: brukeren har et helt legitimt token for B (de logget faktisk
	// inn der, og har rett til det).
	tokenForB, err := iss.IssueAccess(user, svcB)
	require.NoError(t, err)

	// Steg 2: en legitim oidc_authz-cookie for A ligger fra tidligere
	// (klikket "logg inn med kauth" i partner-app A).
	verifier := "angriperens-egen-lovlige-pkce-verifier-for-tjeneste-a-her"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	cookieWriter := httptest.NewRecorder()
	auth.SetOIDCAuthorizeCookie(cookieWriter, auth.OIDCAuthorizeRequest{
		ClientID: "veivakt", RedirectURI: "https://veivakt.app/auth/callback",
		State: "s1", CodeChallenge: challenge, CodeChallengeMethod: "S256",
	})

	// Steg 3: angrepet — B sitt token + ?service=veivakt, rett til /dispatch,
	// UTEN å noensinne ha gått via veivakt sin egen login-handler (der
	// checkPolicy ville stoppet dem).
	dispatchReq := httptest.NewRequest(http.MethodGet, "/dispatch?token="+url.QueryEscape(tokenForB)+"&service=veivakt", nil)
	for _, c := range cookieWriter.Result().Cookies() {
		dispatchReq.AddCookie(c)
	}
	dispatchW := httptest.NewRecorder()
	dispatchH.ServeDispatch(dispatchW, dispatchReq)

	// Dispatch alene kan ikke oppdage dette (den vet bare at URL-en er
	// internt konsistent) — den utsteder en kode. Det er FORVENTET og
	// dokumenterer nettopp hvorfor sjekken må ligge i /token.
	require.Equal(t, http.StatusSeeOther, dispatchW.Code)
	loc := dispatchW.Header().Get("Location")
	require.True(t, strings.HasPrefix(loc, "https://veivakt.app/auth/callback?"))
	redirectURL, err := url.Parse(loc)
	require.NoError(t, err)
	code := redirectURL.Query().Get("code")
	require.NotEmpty(t, code, "dispatch utsteder en kode her — det er selve poenget med testen")

	// Steg 4: angriperen løser inn koden hos veivakt med korrekt PKCE
	// verifier (de kontrollerer jo klienten sin egen side av flyten helt
	// fint). Dette MÅ likevel avvises, fordi de mangler "partner"-rollen
	// veivakt krever.
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://veivakt.app/auth/callback"}, "client_id": {"veivakt"},
		"code_verifier": {verifier},
	}
	tokenReq := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenW := httptest.NewRecorder()
	tokenH.Token(tokenW, tokenReq)

	require.Equal(t, http.StatusBadRequest, tokenW.Code, "må avvises: brukeren mangler veivakt sin påkrevde rolle, uansett hvor gyldig koden/PKCE er")
	var body map[string]string
	require.NoError(t, json.Unmarshal(tokenW.Body.Bytes(), &body))
	require.Equal(t, "invalid_grant", body["error"])
}
