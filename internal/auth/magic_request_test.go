package auth

import (
	"context"
	"database/sql"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

type stubMailer struct {
	mu    sync.Mutex
	links []string
	to    []string
	delay time.Duration
}

func (m *stubMailer) SendMagicLink(to, _, linkURL, _, _ string) error {
	time.Sleep(m.delay)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.to = append(m.to, to)
	m.links = append(m.links, linkURL)
	return nil
}

func (m *stubMailer) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.links)
}

func magicSvc(id string, isDefault, magic int64) gen.CreateServiceParams {
	return gen.CreateServiceParams{
		ID: id, DisplayName: id, Domain: id + ".test", CallbackUrl: "https://" + id + ".test/cb",
		Theme: "light", AccentColor: "#000", EmailFromName: id, AuthMagicLink: magic, IsDefault: isDefault,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: "2026-01-01T00:00:00Z",
	}
}

type magicFixture struct {
	h      *MagicHandlers
	sqldb  *sql.DB
	q      *gen.Queries
	mailer *stubMailer
	path   string
}

func newMagicFixture(t *testing.T, svcs ...gen.CreateServiceParams) *magicFixture {
	t.Helper()
	path := filepath.Join(t.TempDir(), "k.db")
	sqldb, q, err := db.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	ctx := context.Background()
	for _, s := range svcs {
		require.NoError(t, q.CreateService(ctx, s))
	}
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	f := &magicFixture{sqldb: sqldb, q: q, mailer: &stubMailer{}, path: path}
	f.h = f.newHandlers(reg)
	return f
}

// newHandlers lager nye handlere mot samme DB, som en omstart av prosessen.
func (f *magicFixture) newHandlers(reg *service.Registry) *MagicHandlers {
	h := NewMagicHandlers(config.Config{BaseURL: "https://auth.test"}, f.q, nil, nil, nil, reg, nil, template.New("x"))
	h.mailer = f.mailer
	return h
}

// request venter på asynkrone sendinger slik at tellingen er deterministisk.
func (f *magicFixture) request(h *MagicHandlers, email, svcID string) (*httptest.ResponseRecorder, time.Duration) {
	w, d := f.requestNoWait(h, email, svcID)
	h.sendWG.Wait()
	return w, d
}

func (f *magicFixture) requestNoWait(h *MagicHandlers, email, svcID string) (*httptest.ResponseRecorder, time.Duration) {
	form := url.Values{"email": {email}}
	if svcID != "" {
		form.Set("service", svcID)
	}
	req := httptest.NewRequest(http.MethodPost, "/magic-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	start := time.Now()
	h.RequestLink(w, req)
	return w, time.Since(start)
}

func (f *magicFixture) rows(t *testing.T, where string, args ...any) int {
	t.Helper()
	var n int
	require.NoError(t, f.sqldb.QueryRow("SELECT COUNT(*) FROM magic_tokens WHERE "+where, args...).Scan(&n))
	return n
}

func TestMagicRequest_NormalizesEmail(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	for _, e := range []string{" Lars@X.no", "lars@x.no", "LARS@x.NO "} {
		f.request(f.h, e, "klarsyn")
	}
	require.Equal(t, 3, f.rows(t, "email = 'lars@x.no'"))
	f.request(f.h, " LARS@X.no", "klarsyn")
	require.Equal(t, 3, f.rows(t, "email = 'lars@x.no'"), "case-variant skal dele kvote")
	require.Equal(t, 3, f.mailer.count())
	require.Equal(t, "lars@x.no", f.mailer.to[0])
}

func TestMagicRequest_LimitThreePerWindow(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	var bodies []string
	for i := 0; i < 4; i++ {
		w, _ := f.request(f.h, "a@x.no", "klarsyn")
		require.Equal(t, http.StatusOK, w.Code)
		bodies = append(bodies, w.Body.String())
	}
	require.Equal(t, 3, f.rows(t, "email = 'a@x.no'"))
	require.Equal(t, 3, f.mailer.count())
	require.Equal(t, bodies[0], bodies[3])

	// Andre adresser har egen kvote.
	f.request(f.h, "b@x.no", "klarsyn")
	require.Equal(t, 1, f.rows(t, "email = 'b@x.no'"))
}

func TestMagicRequest_LimitSurvivesRestart(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	for i := 0; i < 3; i++ {
		f.request(f.h, "a@x.no", "klarsyn")
	}
	reg := service.NewRegistry(f.q)
	require.NoError(t, reg.Warmup(context.Background()))
	h2 := f.newHandlers(reg)
	f.request(h2, "a@x.no", "klarsyn")
	require.Equal(t, 3, f.rows(t, "email = 'a@x.no'"))
	require.Equal(t, 3, f.mailer.count())
}

func TestMagicRequest_LimitParallel(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f.requestNoWait(f.h, "a@x.no", "klarsyn")
		}()
	}
	wg.Wait()
	f.h.sendWG.Wait()
	require.Equal(t, 3, f.rows(t, "email = 'a@x.no'"))
	require.Equal(t, 3, f.mailer.count())
}

func TestMagicRequest_StoreFailure_NoMail(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	okW, _ := f.request(f.h, "a@x.no", "klarsyn")
	require.Equal(t, 1, f.mailer.count())

	require.NoError(t, f.sqldb.Close())
	w, _ := f.request(f.h, "b@x.no", "klarsyn")
	require.Equal(t, 1, f.mailer.count(), "lagringsfeil skal ikke sende e-post")
	require.Equal(t, okW.Code, w.Code)
	require.Equal(t, okW.Body.String(), w.Body.String())
}

func TestMagicRequest_UnknownServiceStoredAsResolvedID(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1), magicSvc("annen", 0, 1))
	f.request(f.h, "a@x.no", "finnes-ikke")
	var sid, purpose string
	require.NoError(t, f.sqldb.QueryRow("SELECT service_id, purpose FROM magic_tokens").Scan(&sid, &purpose))
	require.Equal(t, "klarsyn", sid)
	require.Equal(t, "service", purpose)
	require.Contains(t, f.mailer.links[0], "service=klarsyn")
}

func TestMagicRequest_MagicLinkDisabled_NoRowNoMail(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1), magicSvc("uten", 0, 0))
	w, _ := f.request(f.h, "a@x.no", "uten")
	require.Equal(t, http.StatusOK, w.Code)
	require.Zero(t, f.rows(t, "1=1"))
	require.Zero(t, f.mailer.count())
}

func TestMagicRequest_LinkEscapesServiceAndLang(t *testing.T) {
	const id = "a&b#c=d"
	f := newMagicFixture(t, magicSvc(id, 1, 1))
	f.request(f.h, "a@x.no", id)
	require.Equal(t, 1, f.mailer.count())
	u, err := url.Parse(f.mailer.links[0])
	require.NoError(t, err)
	require.Equal(t, id, u.Query().Get("service"))
	require.NotEmpty(t, u.Query().Get("lang"))
	require.Empty(t, u.Fragment)
}

func TestMagicRequest_ConstantResponse(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1), magicSvc("uten", 0, 0))
	type res struct {
		code int
		body string
		d    time.Duration
	}
	var got []res
	run := func(email, svc string) {
		w, d := f.request(f.h, email, svc)
		got = append(got, res{w.Code, w.Body.String(), d})
	}
	run("a@x.no", "klarsyn") // suksess
	run("b@x.no", "uten")    // avslått metode
	for i := 0; i < 4; i++ { // 4. er begrenset
		run("c@x.no", "klarsyn")
	}
	require.Equal(t, 4, f.mailer.count(), "1 for a + 3 for c; ingen for avslått og begrenset")
	require.Equal(t, 3, f.rows(t, "email = 'c@x.no'"))

	require.NoError(t, f.sqldb.Close())
	run("d@x.no", "klarsyn") // lagringsfeil
	require.Equal(t, 4, f.mailer.count())

	for _, r := range got {
		require.Equal(t, got[0].code, r.code)
		require.Equal(t, got[0].body, r.body)
		require.GreaterOrEqual(t, r.d, 200*time.Millisecond)
	}
}

// M1: tregt SMTP skal ikke synes i responstiden, ellers skiller svaret
// «fikk lenke» fra «ukjent adresse».
func TestMagicRequest_SlowMailerDoesNotDelayResponse(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1), magicSvc("uten", 0, 0))
	f.mailer.delay = time.Second
	_, dSent := f.requestNoWait(f.h, "a@x.no", "klarsyn")
	_, dUnknown := f.requestNoWait(f.h, "b@x.no", "uten")
	require.Less(t, dSent, 200*time.Millisecond+150*time.Millisecond)
	require.Less(t, dUnknown, 200*time.Millisecond+150*time.Millisecond)

	done := make(chan struct{})
	go func() { f.h.sendWG.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("sendingen ble aldri fullført")
	}
	require.Equal(t, 1, f.mailer.count())
}

func TestMagicRequest_InvalidEmail_NoRowNoMail(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	okW, _ := f.request(f.h, "a@x.no", "klarsyn")
	for _, e := range []string{"", "a@@x.no", "a@b@x.no", "a\r\nBcc: x@y.no@x.no", "ingenalfa", "@x.no", "a@",
		strings.Repeat("a", 250) + "@x.no"} {
		w, _ := f.request(f.h, e, "klarsyn")
		require.Equal(t, okW.Code, w.Code, e)
		require.Equal(t, okW.Body.String(), w.Body.String(), e)
	}
	require.Equal(t, 1, f.rows(t, "1=1"))
	require.Equal(t, 1, f.mailer.count())
}

func TestMagicInsert_PurposeConsistency(t *testing.T) {
	f := newMagicFixture(t, magicSvc("klarsyn", 1, 1))
	f.request(f.h, "a@x.no", "klarsyn")
	require.Equal(t, 1, f.rows(t, "purpose = 'service' AND service_id = 'klarsyn'"))
	require.Zero(t, f.rows(t, "purpose = 'admin' OR service_id IS NULL"))
}
