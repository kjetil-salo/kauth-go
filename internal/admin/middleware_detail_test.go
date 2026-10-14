package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/token"
)

func TestAdminMiddleware_NoErrorDetailInResponse(t *testing.T) {
	issuer := token.NewIssuerForTest()
	const garbage = "ikke.en.jwt"
	_, verr := issuer.Verify(garbage, token.ExpectAdmin)
	require.Error(t, verr)

	handler := AdminAuthMiddleware(issuer, adminDB(t, "konge@example.com", "konge"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.Header.Set("Accept", "application/json")
	req.AddCookie(&http.Cookie{Name: "admin_token", Value: garbage})
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusUnauthorized, rr.Code)
	assert.NotContains(t, rr.Body.String(), verr.Error())
	assert.JSONEq(t, `{"error":"unauthorized","reason":"unauthorized"}`, rr.Body.String())
}
