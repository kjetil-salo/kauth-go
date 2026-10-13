package admin

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func TestCsvEsc_Empty(t *testing.T) {
	assert.Equal(t, "", csvEsc(""))
}

func TestCsvEsc_Clean(t *testing.T) {
	assert.Equal(t, "hello", csvEsc("hello"))
}

func TestCsvEsc_Comma(t *testing.T) {
	// csv.Writer håndterer quoting — csvEsc gjør ingenting med komma.
	assert.Equal(t, "a,b", csvEsc("a,b"))
}

func TestCsvEsc_Quote(t *testing.T) {
	// csv.Writer håndterer quoting — csvEsc gjør ingenting med anførselstegn.
	assert.Equal(t, `he said "hi"`, csvEsc(`he said "hi"`))
}

func TestCsvEsc_Newline(t *testing.T) {
	// csv.Writer håndterer quoting — csvEsc gjør ingenting med newline.
	assert.Equal(t, "line1\nline2", csvEsc("line1\nline2"))
}

func TestCsvEsc_FormulaPrefix(t *testing.T) {
	assert.Equal(t, "'=A1", csvEsc("=A1"))
}

func TestCsvEsc_CarriageReturnPrefix(t *testing.T) {
	assert.Equal(t, "'\rcell", csvEsc("\rcell"))
}

func TestCsvEsc_TabPrefix(t *testing.T) {
	assert.Equal(t, "'\tcell", csvEsc("\tcell"))
}

func TestCsvEsc_PlusPrefix(t *testing.T) {
	assert.Equal(t, "'+1", csvEsc("+1"))
}

type deactEnv struct {
	sqldb *sql.DB
	q     *gen.Queries
	refSv *token.RefreshService
	mux   http.Handler
}

func setupDeactEnv(t *testing.T) *deactEnv {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	// :memory: gir en egen database per tilkobling; audit skriver fra en goroutine.
	sqldb.SetMaxOpenConns(1)
	t.Cleanup(func() { sqldb.Close() })
	t.Chdir("../..") // templates/ ligger relativt til prosjektroten

	for _, id := range []string{"svca", "svcb"} {
		require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
			ID: id, DisplayName: id, Domain: id + ".test", CallbackUrl: "https://" + id + ".test/cb",
			Theme: "light", AccentColor: "#000", EmailFromName: id, JwtCookieName: id + "_tok",
			AccessTokenTtl: "PT30M", Active: 1, UpdatedAt: "2026-10-01T10:00:00Z",
		}))
	}

	aud := audit.NewService(q)
	h := NewUsersHandler(q, aud)
	r := chi.NewRouter()
	r.Post("/admin/users/{id}/deactivate", h.HandleDeactivate)
	return &deactEnv{sqldb: sqldb, q: q, refSv: token.NewRefreshService(sqldb, aud), mux: r}
}

func (e *deactEnv) deactivate(id string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+id+"/deactivate", nil)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *deactEnv) mkUser(t *testing.T, email string) gen.User {
	t.Helper()
	u, err := e.q.CreateUser(context.Background(), gen.CreateUserParams{
		Email: email, Roles: "user", Orgs: "", CreatedAt: "2026-10-01T10:00:00Z",
	})
	require.NoError(t, err)
	return u
}

func (e *deactEnv) rtState(t *testing.T, plain string) (revoked int64, reason sql.NullString) {
	t.Helper()
	sum := sha256.Sum256([]byte(plain))
	require.NoError(t, e.sqldb.QueryRow(
		"SELECT revoked, revoked_reason FROM refresh_tokens WHERE token_hash = ?", hex.EncodeToString(sum[:])).
		Scan(&revoked, &reason))
	return
}

// Brukeren er lagret med blandet case; refresh_tokens.email har samme case og
// matches eksakt, så e-posten må komme fra brukerraden.
func TestDeactivate_RevokesAllUserRefreshTokens(t *testing.T) {
	e := setupDeactEnv(t)
	ctx := context.Background()
	user := e.mkUser(t, "Ola.Nordmann@Example.com")
	other := e.mkUser(t, "kari@example.com")

	t1, err := e.refSv.Issue(ctx, user, gen.Service{ID: "svca"}, "", "")
	require.NoError(t, err)
	t2, err := e.refSv.Issue(ctx, user, gen.Service{ID: "svcb"}, "", "")
	require.NoError(t, err)
	old, err := e.refSv.Issue(ctx, user, gen.Service{ID: "svca"}, "", "")
	require.NoError(t, err)
	tOther, err := e.refSv.Issue(ctx, other, gen.Service{ID: "svca"}, "", "")
	require.NoError(t, err)
	_, err = e.sqldb.Exec("UPDATE refresh_tokens SET revoked = 1, revoked_reason = 'reuse_detected' WHERE token_hash = ?",
		func() string { s := sha256.Sum256([]byte(old)); return hex.EncodeToString(s[:]) }())
	require.NoError(t, err)

	w := e.deactivate(strconv.FormatInt(user.ID, 10))
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	for _, p := range []string{t1, t2} {
		rv, reason := e.rtState(t, p)
		assert.EqualValues(t, 1, rv)
		assert.Equal(t, "user_deactivated", reason.String)
	}
	rv, reason := e.rtState(t, old)
	assert.EqualValues(t, 1, rv)
	assert.Equal(t, "reuse_detected", reason.String)
	rv, _ = e.rtState(t, tOther)
	assert.EqualValues(t, 0, rv)

	// Refresh rett etter gir ingen nye tokens.
	res, err := e.refSv.Rotate(ctx, t1, "", "")
	assert.Nil(t, res)
	assert.ErrorIs(t, err, token.ErrTokenRevoked)

	// Audit har e-post fra raden og antall revokerte.
	require.Eventually(t, func() bool {
		var n int
		_ = e.sqldb.QueryRow(
			"SELECT COUNT(*) FROM audit_events WHERE event_type = 'user_deactivated' AND email = ? AND details = ?",
			"Ola.Nordmann@Example.com", fmt.Sprintf("id=%d revoked=2", user.ID)).Scan(&n)
		return n == 1
	}, 2*time.Second, 10*time.Millisecond)
}

func TestDeactivate_UnknownID_404_NoRevoke(t *testing.T) {
	e := setupDeactEnv(t)
	user := e.mkUser(t, "ola@example.com")
	tok, err := e.refSv.Issue(context.Background(), user, gen.Service{ID: "svca"}, "", "")
	require.NoError(t, err)

	w := e.deactivate("99999")
	assert.Equal(t, http.StatusNotFound, w.Code)

	rv, _ := e.rtState(t, tok)
	assert.EqualValues(t, 0, rv)
	time.Sleep(50 * time.Millisecond)
	var n int
	require.NoError(t, e.sqldb.QueryRow("SELECT COUNT(*) FROM audit_events WHERE event_type = 'user_deactivated'").Scan(&n))
	assert.Equal(t, 0, n)
}

func TestDeactivate_DBError_NoErrorText(t *testing.T) {
	e := setupDeactEnv(t)
	user := e.mkUser(t, "ola@example.com")
	require.NoError(t, e.sqldb.Close())

	w := e.deactivate(strconv.FormatInt(user.ID, 10))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Equal(t, "databasefeil\n", w.Body.String())
}

// hookDB lar testen gripe inn rett før revoke-spørringen kjører.
type hookDB struct {
	*sql.DB
	onRevoke func(ctx context.Context) error
}

func (d hookDB) ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error) {
	if strings.Contains(query, "UPDATE refresh_tokens") && d.onRevoke != nil {
		if err := d.onRevoke(ctx); err != nil {
			return nil, err
		}
	}
	return d.DB.ExecContext(ctx, query, args...)
}

func (e *deactEnv) deactivateVia(t *testing.T, ctx context.Context, hook func(context.Context) error, id int64) *httptest.ResponseRecorder {
	t.Helper()
	h := NewUsersHandler(gen.New(hookDB{DB: e.sqldb, onRevoke: hook}), audit.NewService(e.q))
	r := chi.NewRouter()
	r.Post("/admin/users/{id}/deactivate", h.HandleDeactivate)
	req := httptest.NewRequest(http.MethodPost, "/admin/users/"+strconv.FormatInt(id, 10)+"/deactivate", nil).WithContext(ctx)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

// Klienten kobler fra mellom deaktiveringen og revokeringen: tokens skal likevel revokeres.
func TestDeactivate_CancelledRequestContext_StillRevokes(t *testing.T) {
	e := setupDeactEnv(t)
	user := e.mkUser(t, "Ola.Nordmann@Example.com")
	tok, err := e.refSv.Issue(context.Background(), user, gen.Service{ID: "svca"}, "", "")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := e.deactivateVia(t, ctx, func(c context.Context) error {
		cancel()
		return nil
	}, user.ID)
	require.Equal(t, http.StatusSeeOther, w.Code)

	rv, reason := e.rtState(t, tok)
	assert.EqualValues(t, 1, rv)
	assert.Equal(t, "user_deactivated", reason.String)
}

func TestDeactivate_RevokeFails_StillSucceedsWithAudit(t *testing.T) {
	e := setupDeactEnv(t)
	user := e.mkUser(t, "ola@example.com")

	w := e.deactivateVia(t, context.Background(), func(context.Context) error {
		return errors.New("simulert feil")
	}, user.ID)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.NotContains(t, w.Body.String(), "simulert")

	var deact *string
	require.NoError(t, e.sqldb.QueryRow("SELECT deactivated_at FROM users WHERE id = ?", user.ID).Scan(&deact))
	assert.NotNil(t, deact)
	require.Eventually(t, func() bool {
		var n int
		_ = e.sqldb.QueryRow(
			"SELECT COUNT(*) FROM audit_events WHERE event_type = 'user_deactivated' AND email = 'ola@example.com' AND details = ?",
			fmt.Sprintf("id=%d revoke_failed", user.ID)).Scan(&n)
		return n == 1
	}, 2*time.Second, 10*time.Millisecond)
}
