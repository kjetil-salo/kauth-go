package admin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/mail"
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
		Token: token.HashOpaque(tok), Purpose: purposeFor(serviceID), Email: "konge@example.com", ServiceID: serviceID,
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

	// Motstridende rader: purpose=admin men med tjeneste, og purpose=service uten
	// tjeneste. Ingen av dem skal gi admin-cookie.
	now2 := time.Now().UTC()
	for tok, row := range map[string]struct {
		purpose string
		sid     *string
	}{"admin-med-tjeneste": {token.MagicPurposeAdmin, &svc}, "service-uten-tjeneste": {token.MagicPurposeService, nil}} {
		require.NoError(t, q.InsertMagicToken(context.Background(), gen.InsertMagicTokenParams{
			Token: token.HashOpaque(tok), Purpose: row.purpose, Email: "konge@example.com", ServiceID: row.sid,
			CreatedAt: now2.Format("2006-01-02T15:04:05Z"),
			ExpiresAt: now2.Add(15 * time.Minute).Format("2006-01-02T15:04:05Z"),
		}))
		w = verify(h, tok)
		require.Equal(t, "/admin/login?err=ugyldig_token", w.Header().Get("Location"), tok)
		require.Empty(t, w.Result().Cookies(), tok)
	}
}

func purposeFor(serviceID *string) string {
	if serviceID == nil {
		return token.MagicPurposeAdmin
	}
	return token.MagicPurposeService
}

// K1: admin-magic-token lagres som SHA-256-hex med purpose=admin. Klarteksten
// hentes fra lenken i den sendte e-posten, slik at testen skiller hash fra
// klartekst (begge er 64 hex-tegn).
func TestAdminMagicToken_StoredAsHash(t *testing.T) {
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	_, err = q.CreateUser(context.Background(), gen.CreateUserParams{
		Email: "konge@example.com", Roles: "konge", Orgs: "lars",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)

	mcfg := config.Config{SMTPMock: true}
	h := &AuthHandler{queries: q, issuer: token.NewIssuerForTest(), auditor: audit.NewNoop(),
		mailer: mail.New(mcfg), cfg: &config.Config{BaseURL: "https://kauth.test", AdminTokenTTL: 8 * time.Hour}}

	req := httptest.NewRequest(http.MethodPost, "/admin/login",
		strings.NewReader(url.Values{"email": {"konge@example.com"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out := captureStdout(t, func() { require.NoError(t, h.tryIssueMagicLink(req)) })
	m := regexp.MustCompile(`/admin/verify\?token=([0-9a-f]+)`).FindStringSubmatch(out)
	require.NotNil(t, m, out)
	plain := m[1]

	var stored, purpose string
	require.NoError(t, sqldb.QueryRow("SELECT token, purpose FROM magic_tokens").Scan(&stored, &purpose))
	require.Equal(t, token.HashOpaque(plain), stored)
	require.NotEqual(t, plain, stored)
	require.Equal(t, token.MagicPurposeAdmin, purpose)

	// Den lagrede hashen er ikke selv en gyldig lenke-hemmelighet.
	w := verify(h, stored)
	require.Equal(t, "/admin/login?err=ugyldig_token", w.Header().Get("Location"))
	// Klartekst fra lenken virker.
	w = verify(h, plain)
	require.Equal(t, "/admin/users", w.Header().Get("Location"))
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	old := os.Stdout
	os.Stdout = pw
	defer func() { os.Stdout = old }()
	fn()
	os.Stdout = old
	require.NoError(t, pw.Close())
	b, _ := io.ReadAll(pr)
	return string(b)
}
