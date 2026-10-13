package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func newTestIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generere RSA-nøkkel: %v", err)
	}
	iss, err := token.NewIssuer(key, &key.PublicKey, "https://auth.example.com", 30*24*time.Hour, 1*time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func testUser() gen.User {
	name := "Test Bruker"
	return gen.User{ID: 1, Email: "test@example.com", Name: &name, Roles: "bruker", Orgs: "testorg,annenorg"}
}

func testService() gen.Service {
	return gen.Service{ID: "testsvc", AccessTokenTtl: "P1D", JwtCookieName: "kauth_token"}
}

func TestIssueAccess_VerifyRoundtrip(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	claims, err := iss.Verify(tok, token.ExpectAccess)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Email != "test@example.com" {
		t.Errorf("feil email: %q", claims.Email)
	}
	if len(claims.Org) != 2 {
		t.Errorf("forventet 2 orger, fikk %d", len(claims.Org))
	}
	if claims.TokenUse != "access" {
		t.Errorf("forventet token_use=access, fikk %q", claims.TokenUse)
	}
}

func TestIssueAdmin_HasAdminTokenUse(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAdmin(testUser(), 1*time.Hour)
	if err != nil {
		t.Fatalf("IssueAdmin: %v", err)
	}
	claims, err := iss.Verify(tok, token.ExpectAdmin)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TokenUse != "admin" {
		t.Errorf("forventet token_use=admin, fikk %q", claims.TokenUse)
	}
}

func TestVerify_RejectsExpiredToken(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueWithTTL(testUser(), testService(), -1*time.Second)
	if err != nil {
		t.Fatalf("IssueWithTTL: %v", err)
	}
	_, err = iss.Verify(tok, token.ExpectAccess)
	if err == nil {
		t.Fatal("forventet feil for utløpt token, fikk nil")
	}
}

func TestJWKSHandler_ReturnsJSON(t *testing.T) {
	iss := newTestIssuer(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	w := httptest.NewRecorder()
	iss.JWKSHandler(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("forventet 200, fikk %d", w.Code)
	}
	var jwks map[string]any
	if err := json.NewDecoder(w.Body).Decode(&jwks); err != nil {
		t.Fatalf("JWKS er ikke gyldig JSON: %v", err)
	}
	keysRaw, ok := jwks["keys"]
	if !ok {
		t.Fatalf("JWKS mangler 'keys'-felt")
	}
	keysSlice, ok := keysRaw.([]any)
	if !ok {
		t.Fatalf("JWKS 'keys' er ikke et array, fikk %T", keysRaw)
	}
	if len(keysSlice) == 0 {
		t.Fatalf("JWKS 'keys' er tomt array, forventet minst ett element")
	}
	firstKey, ok := keysSlice[0].(map[string]any)
	if !ok {
		t.Fatalf("JWKS første nøkkel er ikke et objekt, fikk %T", keysSlice[0])
	}
	if v, _ := firstKey["kty"].(string); v != "RSA" {
		t.Errorf("forventet kty=RSA, fikk %q", v)
	}
	if v, _ := firstKey["alg"].(string); v != "RS256" {
		t.Errorf("forventet alg=RS256, fikk %q", v)
	}
	if v, _ := firstKey["use"].(string); v != "sig" {
		t.Errorf("forventet use=sig, fikk %q", v)
	}
	if v, _ := firstKey["kid"].(string); v == "" {
		t.Errorf("forventet ikke-tomt kid-felt")
	}
	if v, _ := firstKey["n"].(string); v == "" {
		t.Errorf("forventet ikke-tomt n-felt (RSA modulus)")
	}
	if v, _ := firstKey["e"].(string); v == "" {
		t.Errorf("forventet ikke-tomt e-felt (RSA eksponent)")
	}
}

func TestIssueAdmin_HasAdminAudience(t *testing.T) {
	iss := newTestIssuer(t)
	tok, err := iss.IssueAdmin(testUser(), time.Hour)
	if err != nil {
		t.Fatalf("IssueAdmin: %v", err)
	}
	claims, err := iss.Verify(tok, token.ExpectAdmin)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.TokenUse != "admin" || !slices.Equal(claims.Audience, []string{"kauth-admin"}) {
		t.Errorf("forventet token_use=admin og aud=[kauth-admin], fikk %q / %v", claims.TokenUse, claims.Audience)
	}
}

// R6: access- og id-token skal ha uendrede claims i Fase 0.
func TestIssueAccessAndID_ClaimsUnchanged(t *testing.T) {
	iss := newTestIssuer(t)

	at, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	ac, err := iss.Verify(at, token.ExpectAccess)
	if err != nil {
		t.Fatalf("Verify access: %v", err)
	}
	if ac.TokenUse != "access" || len(ac.Audience) != 0 || ac.Nonce != "" {
		t.Errorf("access-token skal ikke ha aud/nonce: use=%q aud=%v nonce=%q", ac.TokenUse, ac.Audience, ac.Nonce)
	}

	idt, err := iss.IssueIDToken(testUser(), testService(), "n-123")
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	ic, err := iss.Verify(idt, token.Expect{TokenUse: "id"})
	if err != nil {
		t.Fatalf("Verify id: %v", err)
	}
	if ic.TokenUse != "id" || !slices.Equal(ic.Audience, []string{"testsvc"}) || ic.Nonce != "n-123" {
		t.Errorf("id-token: use=%q aud=%v nonce=%q", ic.TokenUse, ic.Audience, ic.Nonce)
	}
}

func TestVerify_TokenUseAndAudience(t *testing.T) {
	iss := newTestIssuer(t)
	access, err := iss.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	idTok, err := iss.IssueIDToken(testUser(), testService(), "n")
	if err != nil {
		t.Fatalf("IssueIDToken: %v", err)
	}
	admin, err := iss.IssueAdmin(testUser(), time.Hour)
	if err != nil {
		t.Fatalf("IssueAdmin: %v", err)
	}
	// aud=kauth-admin men feil token_use: aud alene er ikke nok.
	audAsAccess := iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  jwt.ClaimStrings{token.AdminAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "test@example.com", TokenUse: "access",
	})
	audAsID := iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Audience:  jwt.ClaimStrings{token.AdminAudience},
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "test@example.com", TokenUse: "id",
	})
	noAud := iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "test@example.com", Groups: []string{"konge"}, TokenUse: "admin",
	})
	noUse := iss.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "test@example.com",
	})

	tests := []struct {
		name   string
		tok    string
		expect token.Expect
		ok     bool
	}{
		{"access som access", access, token.ExpectAccess, true},
		{"admin som admin med aud", admin, token.ExpectAdmin, true},
		{"id som id", idTok, token.Expect{TokenUse: "id"}, true},
		{"access som admin", access, token.ExpectAdmin, false},
		{"admin som access", admin, token.ExpectAccess, false},
		{"id som access", idTok, token.ExpectAccess, false},
		{"manglende token_use", noUse, token.ExpectAccess, false},
		{"admin uten aud krevd aud", noAud, token.ExpectAdmin, false},
		{"admin uten aud uten aud-krav", noAud, token.Expect{TokenUse: "admin"}, true},
		{"feil aud", admin, token.Expect{TokenUse: "admin", Audience: "annen"}, false},
		{"aud=kauth-admin men token_use=access som admin", audAsAccess, token.ExpectAdmin, false},
		{"aud=kauth-admin men token_use=id som admin", audAsID, token.ExpectAdmin, false},
		{"tom expect avvises", access, token.Expect{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := iss.Verify(tc.tok, tc.expect)
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v, fikk err=%v", tc.ok, err)
			}
		})
	}
}

func TestVerify_RejectsWrongSignatureAndAlgNone(t *testing.T) {
	iss := newTestIssuer(t)
	other := newTestIssuer(t) // annen nøkkel, samme issuer
	foreign, err := other.IssueAccess(testUser(), testService())
	if err != nil {
		t.Fatalf("IssueAccess: %v", err)
	}
	if _, err := iss.Verify(foreign, token.ExpectAccess); err == nil {
		t.Fatal("token signert med annen nøkkel skal avvises")
	}

	claims := token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "test@example.com", TokenUse: "access",
	}
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, claims).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("lage alg=none-token: %v", err)
	}
	if _, err := iss.Verify(none, token.ExpectAccess); err == nil {
		t.Fatal("alg=none skal avvises")
	}
}

// Algoritmen er låst til RS256: RS384 med riktig nøkkel avvises også.
func TestVerify_RejectsRS384(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generere RSA-nøkkel: %v", err)
	}
	iss, err := token.NewIssuer(key, &key.PublicKey, "https://auth.example.com", time.Hour, time.Hour)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	claims := token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "test@example.com", TokenUse: "access",
	}
	rs384, err := jwt.NewWithClaims(jwt.SigningMethodRS384, claims).SignedString(key)
	if err != nil {
		t.Fatalf("signere RS384: %v", err)
	}
	if _, err := iss.Verify(rs384, token.ExpectAccess); err == nil {
		t.Fatal("RS384 skal avvises")
	}
	rs256, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		t.Fatalf("signere RS256: %v", err)
	}
	if _, err := iss.Verify(rs256, token.ExpectAccess); err != nil {
		t.Fatalf("RS256 skal godtas: %v", err)
	}
}
