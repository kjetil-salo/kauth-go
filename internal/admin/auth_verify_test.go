package admin

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func newVerifyFixture(t *testing.T) (*AuthHandler, *gen.Queries, *token.Issuer) {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	sqldb.SetMaxOpenConns(1)

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = q.CreateUser(context.Background(), gen.CreateUserParams{Email: "konge@example.com", Roles: "konge", Orgs: "lars", CreatedAt: now})
	require.NoError(t, err)

	issuer := token.NewIssuerForTest()
	h := &AuthHandler{queries: q, issuer: issuer, auditor: audit.NewNoop(),
		cfg: &config.Config{AdminTokenTTL: 8 * time.Hour}}
	return h, q, issuer
}

func insertMagic(t *testing.T, q *gen.Queries, tok string, serviceID *string) {
	t.Helper()
	now := time.Now().UTC()
	require.NoError(t, q.InsertMagicToken(context.Background(), gen.InsertMagicTokenParams{
		Token: tok, Email: "konge@example.com", ServiceID: serviceID,
		CreatedAt: now.Format("2006-01-02T15:04:05Z"),
		ExpiresAt: now.Add(15 * time.Minute).Format("2006-01-02T15:04:05Z"),
	}))
}

func verify(h *AuthHandler, tok string) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.HandleVerify(w, httptest.NewRequest(http.MethodGet, "/admin/verify?token="+tok, nil))
	return w
}

func TestHandleVerify_AdminMagicTokenGivesAdminCookie(t *testing.T) {
	h, q, issuer := newVerifyFixture(t)
	insertMagic(t, q, "admin-tok", nil)

	w := verify(h, "admin-tok")
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/admin/users", w.Header().Get("Location"))

	cookies := w.Result().Cookies()
	require.Len(t, cookies, 1)
	require.Equal(t, "admin_token", cookies[0].Name)
	require.True(t, cookies[0].HttpOnly)
	require.Equal(t, "/admin", cookies[0].Path)
	_, err := issuer.Verify(cookies[0].Value, token.ExpectAdmin)
	require.NoError(t, err)
}

// Formålsbinding: et magic-token utstedt for en tjeneste gir ikke admin.
func TestHandleVerify_ServiceBoundTokenRejected(t *testing.T) {
	h, q, _ := newVerifyFixture(t)
	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
		ID: "klarsyn", DisplayName: "Klarsyn", Domain: "klarsyn.net",
		CallbackUrl: "https://klarsyn.net/auth/callback", Theme: "light", AccentColor: "#000",
		EmailFromName: "Klarsyn", JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	svc := "klarsyn"
	insertMagic(t, q, "svc-tok", &svc)

	w := verify(h, "svc-tok")
	require.Equal(t, http.StatusSeeOther, w.Code)
	require.Equal(t, "/admin/login?err=ugyldig_token", w.Header().Get("Location"))
	require.Empty(t, w.Result().Cookies())
}
