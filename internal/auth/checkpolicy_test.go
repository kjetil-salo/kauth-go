package auth_test

import (
	"context"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// Regresjonstester for github.com/zral/kauth-go/issues/2 (checkPolicy brukte
// substring-match på CSV-felter — "sysadmin" besto feilaktig et
// "admin"-krav) og issues/3 (passord- og magic-link-login håndhevet aldri
// require_role/enforce_org i det hele tatt, i motsetning til Google/
// Microsoft). Begge testene under bruker rollen "sysadmin" mot kravet
// "admin" nettopp for å dekke begge regresjonene i samme oppsett: hadde
// substring-matchen fortsatt vært der, ville "sysadmin" feilaktig bestått,
// og hadde checkPolicy fortsatt ikke vært kalt fra disse to handlerne i det
// hele tatt, ville testene aldri kunnet feile uansett rolleverdi.

func strPtrCP(s string) *string { return &s }

func setupCheckPolicyService(t *testing.T, q *gen.Queries, id string, requireRole *string) {
	t.Helper()
	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
		ID: id, DisplayName: id, Domain: id + ".test",
		CallbackUrl: "https://" + id + ".test/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: id,
		AuthPassword: 1, RequireRole: requireRole,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
}

func TestDoLogin_RejectsUserWithoutRequiredRole(t *testing.T) {
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	setupCheckPolicyService(t, q, "restricted", strPtrCP("admin"))

	hashBytes, err := bcrypt.GenerateFromPassword([]byte("hunter2"), bcrypt.DefaultCost)
	require.NoError(t, err)
	hash := string(hashBytes)

	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "bruker@example.com", PasswordHash: &hash,
		Roles: "sysadmin", // inneholder "admin" som substring, men er IKKE rollen "admin"
		Orgs:  "test", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)

	iss := token.NewIssuerForTest()
	aud := audit.NewNoop()
	refSvc := token.NewRefreshService(q, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	h := auth.NewPasswordHandlers(q, iss, refSvc, reg, aud)

	form := url.Values{"email": {user.Email}, "password": {"hunter2"}, "service_id": {"restricted"}}
	req := httptest.NewRequest("POST", "/do-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.DoLogin(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, "riktig passord, men mangler rollen 'admin' (har kun 'sysadmin', som ikke skal telle som substring-match)")
}

func TestMagicLinkVerify_RejectsUserWithoutRequiredRole(t *testing.T) {
	ctx := context.Background()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	setupCheckPolicyService(t, q, "restricted", strPtrCP("admin"))
	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "bruker@example.com", Roles: "sysadmin", Orgs: "test",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)

	plainToken := "test-magic-token-12345"
	require.NoError(t, q.InsertMagicToken(ctx, gen.InsertMagicTokenParams{
		Token: plainToken, Email: user.Email, ServiceID: strPtrCP("restricted"),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute).Format(time.RFC3339),
	}))

	iss := token.NewIssuerForTest()
	aud := audit.NewNoop()
	refSvc := token.NewRefreshService(q, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	mailSvc := mail.New(config.Config{SMTPMock: true})
	tmpl := template.New("empty") // aldri utført på avvisningsstien (redirect, ikke render)

	h := auth.NewMagicHandlers(config.Config{}, q, mailSvc, iss, refSvc, reg, aud, tmpl)

	req := httptest.NewRequest(http.MethodGet, "/magic-login/"+plainToken+"?service=restricted", nil)
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("token", plainToken)
	req = req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rctx))

	w := httptest.NewRecorder()
	h.VerifyToken(w, req)

	require.Equal(t, http.StatusFound, w.Code)
	loc := w.Header().Get("Location")
	require.Contains(t, loc, "error=access_denied", "skal sendes tilbake med access_denied, ikke logges inn, fikk: %s", loc)
}
