package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// Formålsbinding av magic-tokens (ADN 9): tokens uten tjeneste er utstedt til
// admin-panelet og skal ikke gi en tjenesteinnlogging via /magic-login.
func TestMagicVerifyToken_PurposeBinding(t *testing.T) {
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	sqldb.SetMaxOpenConns(1)

	ctx := context.Background()
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "klarsyn", DisplayName: "Klarsyn", Domain: "klarsyn.net",
		CallbackUrl: "https://klarsyn.net/auth/callback", Theme: "light", AccentColor: "#000",
		EmailFromName: "Klarsyn", AuthMagicLink: 1, IsDefault: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: nowStr,
	}))
	_, err = q.CreateUser(ctx, gen.CreateUserParams{Email: "konge@example.com", Roles: "konge", Orgs: "lars", CreatedAt: nowStr})
	require.NoError(t, err)

	svcID := "klarsyn"
	for tok, sid := range map[string]*string{"tjeneste-tok": &svcID, "admin-tok": nil} {
		require.NoError(t, q.InsertMagicToken(ctx, gen.InsertMagicTokenParams{
			Token: tok, Email: "konge@example.com", ServiceID: sid,
			CreatedAt: nowStr, ExpiresAt: now.Add(15 * time.Minute).Format(time.RFC3339),
		}))
	}

	reg := service.NewRegistryForTest([]gen.Service{{
		ID: "klarsyn", Domain: "klarsyn.net", IsDefault: 1, Active: 1, AuthMagicLink: 1,
		CallbackUrl: "https://klarsyn.net/auth/callback", AccessTokenTtl: "PT15M",
	}})
	aud := audit.NewNoop()
	iss := token.NewIssuerForTest()
	h := auth.NewMagicHandlers(config.Config{}, q, mail.New(config.Config{SMTPMock: true}), iss,
		token.NewRefreshService(q, aud), reg, aud, nil)

	r := chi.NewRouter()
	r.Get("/magic-login/{token}", h.VerifyToken)
	call := func(tok string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/magic-login/"+tok+"?service=klarsyn", nil))
		return w
	}

	// Admin-token: samme oppførsel som et ugyldig token, ingen innlogging.
	w := call("admin-tok")
	require.Equal(t, http.StatusFound, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/magic-login?"), w.Header().Get("Location"))
	require.Contains(t, w.Header().Get("Location"), "error=expired")
	require.Empty(t, w.Result().Cookies())

	// Tjeneste-token: fortsatt vanlig innlogging.
	w = call("tjeneste-tok")
	require.Equal(t, http.StatusFound, w.Code)
	require.True(t, strings.HasPrefix(w.Header().Get("Location"), "/dispatch?"), w.Header().Get("Location"))
}
