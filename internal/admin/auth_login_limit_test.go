package admin

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

type countingMailer struct {
	mu    sync.Mutex
	n     int
	delay time.Duration
}

func (m *countingMailer) SendMagicLink(_, _, _, _, _ string) error {
	time.Sleep(m.delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.n++
	return nil
}

func (m *countingMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.n
}

func newLoginFixture(t *testing.T) (*AuthHandler, *countingMailer, func(string) int) {
	h, m, count, _ := newLoginFixtureDB(t)
	return h, m, count
}

func newLoginFixtureDB(t *testing.T) (*AuthHandler, *countingMailer, func(string) int, *sql.DB) {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	now := time.Now().UTC().Format(time.RFC3339)
	for email, roles := range map[string]string{"konge@example.com": "konge", "vanlig@example.com": "user"} {
		_, err = q.CreateUser(context.Background(), gen.CreateUserParams{Email: email, Roles: roles, Orgs: "o", CreatedAt: now})
		require.NoError(t, err)
	}
	m := &countingMailer{}
	h := &AuthHandler{queries: q, mailer: m, auditor: audit.NewNoop(),
		cfg: &config.Config{BaseURL: "https://auth.test"}, loginTpl: template.Must(template.New("l").Parse("{{.Message}}"))}
	return h, m, func(where string) int {
		var n int
		require.NoError(t, sqldb.QueryRow("SELECT COUNT(*) FROM magic_tokens WHERE "+where).Scan(&n))
		return n
	}, sqldb
}

func postLogin(h *AuthHandler, email string) (*httptest.ResponseRecorder, time.Duration) {
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(url.Values{"email": {email}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	start := time.Now()
	h.HandleLoginPost(w, req)
	d := time.Since(start)
	h.sendWG.Wait()
	return w, d
}

func TestAdminLoginPost_LimitThree(t *testing.T) {
	h, m, count := newLoginFixture(t)
	for _, e := range []string{"konge@example.com", " Konge@Example.com", "KONGE@example.com", "konge@example.com"} {
		postLogin(h, e)
	}
	require.Equal(t, 3, count("email = 'konge@example.com' AND purpose = 'admin' AND service_id IS NULL"))
	require.Equal(t, 3, m.count())
}

func TestMagicInsert_PurposeConsistency(t *testing.T) {
	h, _, count := newLoginFixture(t)
	postLogin(h, "konge@example.com")
	require.Equal(t, 1, count("purpose = 'admin' AND service_id IS NULL"))
	require.Zero(t, count("purpose != 'admin' OR service_id IS NOT NULL"))
}

func TestAdminLoginPost_ConstantResponse(t *testing.T) {
	h, m, _ := newLoginFixture(t)
	type res struct {
		code int
		body string
		d    time.Duration
	}
	var got []res
	for _, e := range []string{
		"konge@example.com", // suksess
		"ukjent@example.com",
		"vanlig@example.com", // ikke konge
	} {
		w, d := postLogin(h, e)
		got = append(got, res{w.Code, w.Body.String(), d})
	}
	for i := 0; i < 3; i++ { // 4. bestilling for konge er begrenset
		w, d := postLogin(h, "konge@example.com")
		got = append(got, res{w.Code, w.Body.String(), d})
	}
	for _, r := range got {
		require.Equal(t, got[0].code, r.code)
		require.Equal(t, got[0].body, r.body)
		require.GreaterOrEqual(t, r.d, 200*time.Millisecond)
	}
	require.Equal(t, 3, m.count())
}

// M1: tregt SMTP skal ikke avsløre konge-brukere via responstiden.
func TestAdminLoginPost_SlowMailerDoesNotDelayResponse(t *testing.T) {
	h, m, _ := newLoginFixture(t)
	m.delay = time.Second
	start := time.Now()
	req := httptest.NewRequest(http.MethodPost, "/admin/login", strings.NewReader(url.Values{"email": {"konge@example.com"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.HandleLoginPost(httptest.NewRecorder(), req)
	require.Less(t, time.Since(start), 350*time.Millisecond)

	done := make(chan struct{})
	go func() { h.sendWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendingen ble aldri fullført")
	}
	require.Equal(t, 1, m.count())
}

func TestAdminLoginPost_InvalidEmail_NoRowNoMail(t *testing.T) {
	h, m, count, sqldb := newLoginFixtureDB(t)
	// Brukere med ugyldige adresser (f.eks. importert tull) skal likevel ikke få lenke.
	_, err := gen.New(sqldb).CreateUser(context.Background(), gen.CreateUserParams{
		Email: "a@b@x.no", Roles: "konge", Orgs: "o", CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	require.NoError(t, err)
	for _, e := range []string{"", "a@@x.no", "a@b@x.no", "konge@example.com\r\nBcc: x@y.no", "@x.no", strings.Repeat("a", 250) + "@x.no"} {
		postLogin(h, e)
	}
	require.Zero(t, count("1=1"))
	require.Zero(t, m.count())
}

func TestAdminLoginPost_QuotaAuditedAsFailure(t *testing.T) {
	h, _, _, sqldb := newLoginFixtureDB(t)
	q := gen.New(sqldb)
	h.auditor = audit.NewService(q)
	for i := 0; i < 4; i++ {
		postLogin(h, "konge@example.com")
	}
	require.Eventually(t, func() bool {
		var n int
		err := sqldb.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='admin_magic_link_requested' AND success=0 AND details='kvote overskredet'`).Scan(&n)
		return err == nil && n == 1
	}, 3*time.Second, 20*time.Millisecond)
}
