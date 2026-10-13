package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stretchr/testify/assert"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func TestAdminAuthMiddleware_NoCookie_HTML_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	mw := AdminAuthMiddleware(issuer)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "text/html")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/admin/login", rr.Header().Get("Location"))
}

func TestAdminAuthMiddleware_NoCookie_JSON_Returns401(t *testing.T) {
	issuer := token.NewIssuerForTest()
	mw := AdminAuthMiddleware(issuer)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "application/json")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.Contains(t, rr.Header().Get("Content-Type"), "application/json")
}

func TestAdminAuthMiddleware_ValidToken_PassesThrough(t *testing.T) {
	issuer := token.NewIssuerForTest()
	adminToken := issuer.IssueAdminForTest("test@example.com", "konge")
	mw := AdminAuthMiddleware(issuer)

	called := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: adminToken})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestAdminAuthMiddleware_WrongRole_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	// Token med admin token_use men feil rolle
	adminToken := issuer.IssueAdminForTest("test@example.com", "vanlig")
	mw := AdminAuthMiddleware(issuer)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: adminToken})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
}

// serveWithCookie kjører en request med gitt admin_token-cookie gjennom
// middleware og returnerer (statuskode, Location, om handleren ble nådd).
func serveWithCookie(issuer *token.Issuer, cookieValue string) (int, string, bool) {
	called := false
	handler := AdminAuthMiddleware(issuer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "text/html")
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: cookieValue})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code, rr.Header().Get("Location"), called
}

// R5: et access-token for en konge er gyldig signert, men skal ikke gi
// admin-tilgang når det legges i admin_token-cookien.
func TestAdminAuthMiddleware_AccessTokenAsCookie_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	access, err := issuer.IssueAccess(gen.User{Email: "konge@example.com", Roles: "konge"}, gen.Service{ID: "klarsyn", AccessTokenTtl: "PT15M"})
	assert.NoError(t, err)

	code, loc, called := serveWithCookie(issuer, access)
	assert.Equal(t, http.StatusSeeOther, code)
	assert.Equal(t, "/admin/login", loc)
	assert.False(t, called)
}

// En admin-sesjon utstedt før aud=kauth-admin ble innført skal avvises.
func TestAdminAuthMiddleware_AdminTokenWithoutAud_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	legacy := issuer.SignForTest(token.Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://test.example.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Email: "konge@example.com", Groups: []string{"konge"}, TokenUse: "admin",
	})

	code, loc, called := serveWithCookie(issuer, legacy)
	assert.Equal(t, http.StatusSeeOther, code)
	assert.Equal(t, "/admin/login", loc)
	assert.False(t, called)
}

// aud=kauth-admin alene er ikke nok: token_use må også være admin.
func TestAdminAuthMiddleware_AdminAudWithWrongTokenUse_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	for _, use := range []string{"access", "id"} {
		tok := issuer.SignForTest(token.Claims{
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:    "https://test.example.com",
				Audience:  jwt.ClaimStrings{token.AdminAudience},
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			Email: "konge@example.com", Groups: []string{"konge"}, TokenUse: use,
		})
		code, loc, called := serveWithCookie(issuer, tok)
		assert.Equal(t, http.StatusSeeOther, code, use)
		assert.Equal(t, "/admin/login", loc, use)
		assert.False(t, called, use)
	}
}
