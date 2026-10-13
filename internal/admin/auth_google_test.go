package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// R3: /admin/google-callback er ikke lenger en sesjonsinngang. Uansett hva
// som ligger i query (access-, id- eller admin-JWT, tomt eller søppel) skal
// svaret være 303 til /admin/login uten Set-Cookie.
func TestHandleGoogleCallback_NeverSetsCookie(t *testing.T) {
	issuer := token.NewIssuerForTest()
	user := gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}
	svc := gen.Service{ID: "klarsyn", AccessTokenTtl: "PT15M"}
	access, err := issuer.IssueAccess(user, svc)
	require.NoError(t, err)
	idTok, err := issuer.IssueIDToken(user, svc, "n")
	require.NoError(t, err)
	adminTok, err := issuer.IssueAdmin(user, time.Hour)
	require.NoError(t, err)

	h := &AuthHandler{issuer: issuer}
	for name, query := range map[string]string{
		"access": "?token=" + access,
		"id":     "?token=" + idTok,
		"admin":  "?token=" + adminTok,
		"tom":    "",
		"søppel": "?token=ikke-et-jwt&err=x",
	} {
		t.Run(name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.HandleGoogleCallback(w, httptest.NewRequest(http.MethodGet, "/admin/google-callback"+query, nil))

			assert.Equal(t, http.StatusSeeOther, w.Code)
			assert.Equal(t, "/admin/login", w.Header().Get("Location"))
			assert.Empty(t, w.Result().Cookies())
			assert.Empty(t, w.Header().Get("Set-Cookie"))
		})
	}
}

func TestSessionStarter_SetsAdminCookieWithAudience(t *testing.T) {
	issuer := token.NewIssuerForTest()
	starter := NewSessionStarter(issuer, audit.NewNoop(), 8*time.Hour)

	w := httptest.NewRecorder()
	err := starter.StartAdminSession(w, httptest.NewRequest(http.MethodGet, "/callback", nil),
		gen.User{Email: "konge@example.com", Roles: "konge", Orgs: "lars"}, "klarsyn")
	require.NoError(t, err)

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	c := cookies[0]
	assert.Equal(t, "admin_token", c.Name)
	assert.True(t, c.HttpOnly)
	assert.Equal(t, "/admin", c.Path)
	assert.Equal(t, int((8 * time.Hour).Seconds()), c.MaxAge)

	claims, err := issuer.Verify(c.Value, token.ExpectAdmin)
	require.NoError(t, err)
	assert.Equal(t, "konge@example.com", claims.Email)
}
