package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func TestAdminAuthMiddleware_NoCookie_HTML_Redirects(t *testing.T) {
	issuer := token.NewIssuerForTest()
	mw := AdminAuthMiddleware(issuer, adminDB(t, "test@example.com", "konge"))
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
	mw := AdminAuthMiddleware(issuer, adminDB(t, "test@example.com", "konge"))
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
	mw := AdminAuthMiddleware(issuer, adminDB(t, "test@example.com", "konge"))

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
	mw := AdminAuthMiddleware(issuer, adminDB(t, "test@example.com", "konge"))

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
func serveWithCookie(t *testing.T, issuer *token.Issuer, cookieValue string) (int, string, bool) {
	called := false
	handler := AdminAuthMiddleware(issuer, adminDB(t, "konge@example.com", "konge"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	code, loc, called := serveWithCookie(t, issuer, access)
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

	code, loc, called := serveWithCookie(t, issuer, legacy)
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
		code, loc, called := serveWithCookie(t, issuer, tok)
		assert.Equal(t, http.StatusSeeOther, code, use)
		assert.Equal(t, "/admin/login", loc, use)
		assert.False(t, called, use)
	}
}

// adminDB gir en minnebasert DB med én bruker; middlewaren slår opp brukeren der.
func adminDB(t *testing.T, email, roles string) *gen.Queries {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	sqldb.SetMaxOpenConns(1)
	t.Cleanup(func() { sqldb.Close() })
	_, err = q.CreateUser(context.Background(), gen.CreateUserParams{
		Email: email, Roles: roles, Orgs: "", CreatedAt: "2026-10-01T10:00:00Z",
	})
	require.NoError(t, err)
	return q
}

type failingLookup struct{}

func (failingLookup) GetActiveUserByEmail(context.Context, string) (gen.User, error) {
	return gen.User{}, errors.New("db nede")
}

// serveAdmin kjører en gyldig admin-JWT for e-posten gjennom middlewaren.
func serveAdmin(t *testing.T, users adminUserLookup, accept string) (code int, body string, called bool, actor string) {
	t.Helper()
	issuer := token.NewIssuerForTest()
	tok := issuer.IssueAdminForTest("konge@example.com", "konge")
	handler := AdminAuthMiddleware(issuer, users)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		actor = ActorFromContext(r.Context())
	}))
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", accept)
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: tok})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)
	return rr.Code, rr.Body.String(), called, actor
}

func assertRejected(t *testing.T, users adminUserLookup) {
	t.Helper()
	code, _, called, _ := serveAdmin(t, users, "text/html")
	assert.Equal(t, http.StatusSeeOther, code)
	assert.False(t, called)
	code, _, called, _ = serveAdmin(t, users, "application/json")
	assert.Equal(t, http.StatusUnauthorized, code)
	assert.False(t, called)
}

func TestAdminAuthMiddleware_DeactivatedUser_Rejected(t *testing.T) {
	q := adminDB(t, "konge@example.com", "konge")
	now := "2026-10-02T10:00:00Z"
	u, err := q.GetActiveUserByEmail(context.Background(), "konge@example.com")
	require.NoError(t, err)
	_, err = q.DeactivateUser(context.Background(), gen.DeactivateUserParams{DeactivatedAt: &now, ID: u.ID})
	require.NoError(t, err)
	assertRejected(t, q)
}

func TestAdminAuthMiddleware_KongeRemovedInDB_Rejected(t *testing.T) {
	assertRejected(t, adminDB(t, "konge@example.com", "user"))
}

func TestAdminAuthMiddleware_UnknownUser_Rejected(t *testing.T) {
	assertRejected(t, adminDB(t, "annen@example.com", "konge"))
}

func TestAdminAuthMiddleware_DBError_Rejected(t *testing.T) {
	assertRejected(t, failingLookup{})
}

func TestAdminAuthMiddleware_ActorInContext(t *testing.T) {
	// Mixed case i DB: aktøren er e-posten slik raden har den.
	q := adminDB(t, "Konge@Example.com", "user,konge")
	code, _, called, actor := serveAdmin(t, q, "text/html")
	assert.Equal(t, http.StatusOK, code)
	assert.True(t, called)
	assert.Equal(t, "Konge@Example.com", actor)
	assert.Equal(t, "", ActorFromContext(context.Background()))
}
