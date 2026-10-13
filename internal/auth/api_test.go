package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// R5: /api/me godtar bare access-tokens. Id-token og admin-token er gyldig
// signert av kauth, men har feil formål og skal gi 401.
func TestServeMe_OnlyAccessTokenAccepted(t *testing.T) {
	iss := token.NewIssuerForTest()
	user := gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}
	svc := gen.Service{ID: "klarsyn", AccessTokenTtl: "PT15M"}

	access, err := iss.IssueAccess(user, svc)
	require.NoError(t, err)
	idTok, err := iss.IssueIDToken(user, svc, "n")
	require.NoError(t, err)
	adminTok, err := iss.IssueAdmin(user, time.Hour)
	require.NoError(t, err)

	h := &auth.MeHandler{Issuer: iss, CookieName: "auth_token"}
	call := func(tok string) int {
		req := httptest.NewRequest(http.MethodGet, "/api/me", nil)
		req.AddCookie(&http.Cookie{Name: "auth_token", Value: tok})
		w := httptest.NewRecorder()
		h.ServeMe(w, req)
		return w.Code
	}

	require.Equal(t, http.StatusOK, call(access))
	require.Equal(t, http.StatusUnauthorized, call(idTok))
	require.Equal(t, http.StatusUnauthorized, call(adminTok))
	require.Equal(t, http.StatusUnauthorized, call("søppel"))
}
