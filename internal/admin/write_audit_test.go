package admin

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// K18: admin-skriving auditeres synkront med aktør, og audit-feil gir synlig advarsel.

const testActor = "admin@example.com"

// failingAudit lar LogSync feile; Log er en no-op.
type failingAudit struct{}

func (failingAudit) Log(context.Context, audit.Event) {}
func (failingAudit) LogSync(context.Context, audit.Event) error {
	return errors.New("audit nede")
}

// withActor etterligner middlewaren som legger admin-e-posten i konteksten.
func withActor(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorCtxKey{}, testActor)))
	})
}

func formPost(path string, vals url.Values) *http.Request {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestAdminWriteAudit_SyncWithActor(t *testing.T) {
	e := setupDeactEnv(t)
	svcs := &svcEnv{sqldb: e.sqldb, q: e.q, reg: service.NewRegistry(e.q)}
	aud := audit.NewService(e.q)
	uh := NewUsersHandler(e.q, aud)
	sh := NewServicesHandler(e.q, svcs.reg, aud)
	r := chi.NewRouter()
	r.Use(withActor)
	r.Post("/admin/users", uh.HandleCreate)
	r.Post("/admin/users/{id}", uh.HandleUpdate)
	r.Post("/admin/users/{id}/deactivate", uh.HandleDeactivate)
	r.Post("/admin/services", sh.HandleCreate)
	r.Get("/admin/services/{id}/edit", sh.HandleEdit)
	r.Post("/admin/services/{id}", sh.HandleUpdate)

	run := func(req *http.Request) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/admin/users", w.Header().Get("Location"))
		assert.NotContains(t, w.Header().Get("Location"), "warn=")
	}
	// Raden skal finnes når handleren har returnert; ingen venting.
	details := func(typ string) string {
		var d string
		require.NoError(t, e.sqldb.QueryRow(
			`SELECT details FROM audit_events WHERE event_type = ? ORDER BY id DESC LIMIT 1`, typ).Scan(&d), typ)
		return d
	}

	run(formPost("/admin/users", url.Values{"email": {"ny@example.com"}, "password": {"langtpassord123"}, "roles": {"user"}}))
	assert.Contains(t, details("user_created"), "actor="+testActor)

	u, err := e.q.GetUserByEmail(context.Background(), "ny@example.com")
	require.NoError(t, err)
	id := strconv.FormatInt(u.ID, 10)
	run(formPost("/admin/users/"+id, url.Values{"name": {"Ny"}, "roles": {"user"}}))
	d := details("user_edited")
	assert.Contains(t, d, "id="+id)
	assert.Contains(t, d, "actor="+testActor)

	run(formPost("/admin/users/"+id+"/deactivate", nil))
	d = details("user_deactivated")
	assert.Contains(t, d, "revoked=")
	assert.Contains(t, d, "actor="+testActor)

	post := func(req *http.Request) {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusSeeOther, w.Code)
		assert.Equal(t, "/admin/services", w.Header().Get("Location"))
	}
	post(formPost("/admin/services", url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "domain": {"gamma.test"},
		"callback_url": {"https://gamma.test/cb"}, "auth_google": {"1"}, "active": {"1"},
	}))
	assert.Contains(t, details("service_created"), "actor="+testActor)

	svcs.mux = r
	vals, _ := svcs.renderedFormValues(t, "gamma")
	vals.Set("display_name", "Endret")
	post(formPost("/admin/services/gamma", vals))
	assert.Contains(t, details("service_edited"), "actor="+testActor)
}

// Audit feiler etter lagring: endringen står, og redirecten bærer warn=audit.
func TestAdminWriteAudit_FailureKeepsChangeAndWarns(t *testing.T) {
	e := setupDeactEnv(t)
	reg := service.NewRegistry(e.q)
	uh := NewUsersHandler(e.q, failingAudit{})
	sh := NewServicesHandler(e.q, reg, failingAudit{})
	r := chi.NewRouter()
	r.Use(withActor)
	r.Get("/admin/users", uh.HandleList)
	r.Get("/admin/services", sh.HandleList)
	r.Post("/admin/users", uh.HandleCreate)
	r.Post("/admin/users/{id}", uh.HandleUpdate)
	r.Post("/admin/users/{id}/deactivate", uh.HandleDeactivate)
	r.Post("/admin/services", sh.HandleCreate)

	do := func(req *http.Request) string {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		require.Equal(t, http.StatusSeeOther, w.Code)
		return w.Header().Get("Location")
	}

	assert.Equal(t, "/admin/users?warn=audit", do(formPost("/admin/users",
		url.Values{"email": {"ny@example.com"}, "password": {"langtpassord123"}, "roles": {"user"}})))
	u, err := e.q.GetUserByEmail(context.Background(), "ny@example.com")
	require.NoError(t, err, "brukeren er lagret selv om audit feilet")
	id := strconv.FormatInt(u.ID, 10)

	assert.Equal(t, "/admin/users?warn=audit", do(formPost("/admin/users/"+id, url.Values{"name": {"Endret"}, "roles": {"user"}})))
	u, _ = e.q.GetUserByEmail(context.Background(), "ny@example.com")
	require.NotNil(t, u.Name)
	assert.Equal(t, "Endret", *u.Name)

	assert.Equal(t, "/admin/users?warn=audit", do(formPost("/admin/users/"+id+"/deactivate", nil)))
	_, err = e.q.GetActiveUserByEmail(context.Background(), "ny@example.com")
	assert.Error(t, err, "brukeren er deaktivert")

	assert.Equal(t, "/admin/services?warn=audit", do(formPost("/admin/services", url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "domain": {"gamma.test"},
		"callback_url": {"https://gamma.test/cb"}, "auth_google": {"1"}, "active": {"1"},
	})))
	_, err = e.q.GetServiceByID(context.Background(), "gamma")
	assert.NoError(t, err)

	const msg = "Lagret, men ikke auditert."
	get := func(path string) string {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		require.Equal(t, http.StatusOK, rec.Code)
		return rec.Body.String()
	}
	assert.Contains(t, get("/admin/users?warn=audit"), msg)
	assert.Contains(t, get("/admin/services?warn=audit"), msg)
	assert.Contains(t, get("/admin/services?warn=cache&warn=audit"), "Lagret, men ikke aktivert.")
	assert.Contains(t, get("/admin/services?warn=cache&warn=audit"), msg)
}

func TestAdminList_UnknownWarnIgnored(t *testing.T) {
	e := setupDeactEnv(t)
	uh := NewUsersHandler(e.q, audit.NewNoop())
	sh := NewServicesHandler(e.q, service.NewRegistry(e.q), audit.NewNoop())
	r := chi.NewRouter()
	r.Get("/admin/users", uh.HandleList)
	r.Get("/admin/services", sh.HandleList)
	for _, path := range []string{"/admin/users", "/admin/services"} {
		for _, q := range []string{"?warn=annet", "?warn=%3Cscript%3Ex", ""} {
			rec := httptest.NewRecorder()
			r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path+q, nil))
			require.Equal(t, http.StatusOK, rec.Code)
			assert.NotContains(t, rec.Body.String(), "Lagret, men ikke", path+q)
			assert.NotContains(t, rec.Body.String(), "<script>x")
		}
	}
}

// spyAudit kansellerer request-konteksten rett før skrivingen og husker fristen
// LogSync fikk. Uten WithoutCancel i logAdminWrite feiler skrivingen og raden uteblir.
type spyAudit struct {
	inner    *audit.Service
	cancel   context.CancelFunc
	deadline time.Time
	hasDL    bool
}

func (s *spyAudit) Log(ctx context.Context, e audit.Event) { s.inner.Log(ctx, e) }
func (s *spyAudit) LogSync(ctx context.Context, e audit.Event) error {
	s.deadline, s.hasDL = ctx.Deadline()
	if s.cancel != nil {
		s.cancel()
	}
	return s.inner.LogSync(ctx, e)
}

func auditCount(t *testing.T, e *deactEnv, typ string) (n int) {
	t.Helper()
	require.NoError(t, e.sqldb.QueryRow(`SELECT count(*) FROM audit_events WHERE event_type = ?`, typ).Scan(&n))
	return
}

func TestAdminWriteAudit_SurvivesCancelledRequestContext(t *testing.T) {
	e := setupDeactEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	spy := &spyAudit{inner: audit.NewService(e.q), cancel: cancel}
	uh := NewUsersHandler(e.q, spy)
	r := chi.NewRouter()
	r.Use(withActor)
	r.Post("/admin/users", uh.HandleCreate)
	r.Post("/admin/users/{id}/deactivate", uh.HandleDeactivate)

	req := formPost("/admin/users", url.Values{"email": {"ny@example.com"}, "password": {"langtpassord123"}, "roles": {"user"}}).WithContext(ctx)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/users", w.Header().Get("Location"))
	assert.Equal(t, 1, auditCount(t, e, "user_created"))

	// Deaktivering: audit-fristen er satt (maks 5 s), og raden skrives selv om requesten er kansellert.
	u, err := e.q.GetUserByEmail(context.Background(), "ny@example.com")
	require.NoError(t, err)
	ctx2, cancel2 := context.WithCancel(context.Background())
	defer cancel2()
	spy.cancel = cancel2
	w = httptest.NewRecorder()
	r.ServeHTTP(w, formPost("/admin/users/"+strconv.FormatInt(u.ID, 10)+"/deactivate", nil).WithContext(ctx2))
	require.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, 1, auditCount(t, e, "user_deactivated"))

	require.True(t, spy.hasDL, "LogSync skal få en frist")
	assert.LessOrEqual(t, time.Until(spy.deadline), 5*time.Second)
	assert.Greater(t, time.Until(spy.deadline), 0*time.Second)
}

func TestAdminWriteAudit_DeactivateRevokeFailed_KeepsActorAndDetail(t *testing.T) {
	e := setupDeactEnv(t)
	u := e.mkUser(t, "ola@example.com")
	hook := func(context.Context) error { return errors.New("revoke nede") }
	h := NewUsersHandler(gen.New(hookDB{DB: e.sqldb, onRevoke: hook}), audit.NewService(e.q))
	r := chi.NewRouter()
	r.Use(withActor)
	r.Post("/admin/users/{id}/deactivate", h.HandleDeactivate)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, formPost("/admin/users/"+strconv.FormatInt(u.ID, 10)+"/deactivate", nil))
	require.Equal(t, http.StatusSeeOther, w.Code)

	var d string
	require.NoError(t, e.sqldb.QueryRow(`SELECT details FROM audit_events WHERE event_type = 'user_deactivated'`).Scan(&d))
	assert.Contains(t, d, "revoke_failed")
	assert.Contains(t, d, "actor="+testActor)
}
