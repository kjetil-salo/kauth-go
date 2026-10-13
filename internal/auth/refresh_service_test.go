package auth_test

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

type refreshFx struct {
	h      *auth.PasswordHandlers
	q      *gen.Queries
	sqldb  *sql.DB
	refSvc *token.RefreshService
	reg    *service.Registry
	user   gen.User
}

func mkService(t *testing.T, q *gen.Queries, id, cookie, ttl string, active int64, role *string, enforceOrg int64, org *string) gen.Service {
	t.Helper()
	require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
		ID: id, DisplayName: id, Domain: id + ".test",
		CallbackUrl: "https://" + id + ".test/cb",
		Theme:       "light", AccentColor: "#000", EmailFromName: id,
		AutoRegister: 1, AuthMagicLink: 1,
		JwtCookieName: cookie, AccessTokenTtl: ttl,
		RequireRole: role, EnforceOrg: enforceOrg, DefaultOrg: org,
		Active: active, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	}))
	// GetServiceByID filtrerer på active; inaktive tjenester returneres uten oppslag.
	if active == 0 {
		return gen.Service{ID: id}
	}
	svc, err := q.GetServiceByID(context.Background(), id)
	require.NoError(t, err)
	return svc
}

// newRefreshFx lager tjenestene A (30 min, cookie a_tok) og B (15 min, cookie b_tok).
func newRefreshFx(t *testing.T, aRole *string, aEnforce int64, aOrg *string) (*refreshFx, gen.Service, gen.Service) {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	// :memory: gir en egen database per tilkobling, og audit skriver fra en goroutine.
	sqldb.SetMaxOpenConns(1)
	a := mkService(t, q, "svca", "a_tok", "PT30M", 1, aRole, aEnforce, aOrg)
	b := mkService(t, q, "svcb", "b_tok", "PT15M", 1, nil, 0, nil)
	user, err := q.CreateUser(context.Background(), gen.CreateUserParams{
		Email: "alice@example.com", Roles: "user", Orgs: "org1", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(context.Background()))
	refSvc := token.NewRefreshService(q, audit.NewService(q))
	h := auth.NewPasswordHandlers(q, token.NewIssuerForTest(), refSvc, reg, audit.NewService(q), true)
	return &refreshFx{h: h, q: q, sqldb: sqldb, refSvc: refSvc, reg: reg, user: user}, a, b
}

func (f *refreshFx) post(plain, serviceID string) *httptest.ResponseRecorder {
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {plain}}
	if serviceID != "" {
		form.Set("service_id", serviceID)
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	f.h.RefreshToken(w, req)
	return w
}

func (f *refreshFx) auditCount(t *testing.T, typ string) int {
	t.Helper()
	all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 1000})
	require.NoError(t, err)
	n := 0
	for _, e := range all {
		if e.EventType == typ {
			n++
		}
	}
	return n
}

func (f *refreshFx) waitAudit(t *testing.T, typ string, want int) {
	t.Helper()
	require.Eventually(t, func() bool { return f.auditCount(t, typ) == want }, 2*time.Second, 10*time.Millisecond, typ)
}

func cookieByName(w *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range w.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func assertDenied(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	require.Equal(t, http.StatusBadRequest, w.Code, w.Body.String())
	assert.JSONEq(t, `{"error":"invalid_grant"}`, w.Body.String())
	assert.NotContains(t, w.Body.String(), "access_token")
	for _, c := range w.Result().Cookies() {
		assert.Empty(t, c.Value, "cookie %s skal være tom", c.Name)
	}
	rc := cookieByName(w, "refresh_token")
	require.NotNil(t, rc)
	assert.Less(t, rc.MaxAge, 0)
}

// AK8.2 + tenant-isolasjon: lagret tjeneste vinner over skjemafeltet.
func TestRefreshService_StoredServiceWinsOverFormField(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	plain, err := f.refSvc.Issue(context.Background(), f.user, a, "127.0.0.1", "t")
	require.NoError(t, err)

	w := f.post(plain, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"expires_in":1800`)
	require.NotNil(t, cookieByName(w, "a_tok"))
	assert.Nil(t, cookieByName(w, "b_tok"))
	f.waitAudit(t, "refresh_service_mismatch", 0)

	// Samsvar: ingen mismatch-event.
	next := extractRefresh(t, w)
	w = f.post(next, "svca")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, f.auditCount(t, "refresh_service_mismatch"))

	// Avvik: B oppgitt, A utstedes, ett event med begge verdier.
	next = extractRefresh(t, w)
	w = f.post(next, "svcb")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), `"expires_in":1800`)
	require.NotNil(t, cookieByName(w, "a_tok"))
	assert.Nil(t, cookieByName(w, "b_tok"))
	f.waitAudit(t, "refresh_service_mismatch", 1)
	all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 1000})
	require.NoError(t, err)
	for _, e := range all {
		if e.EventType == "refresh_service_mismatch" {
			require.NotNil(t, e.Details)
			assert.Contains(t, *e.Details, "stored=svca")
			assert.Contains(t, *e.Details, "given=svcb")
		}
	}
}

func extractRefresh(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	body := w.Body.String()
	const k = `"refresh_token":"`
	i := strings.Index(body, k)
	require.GreaterOrEqual(t, i, 0, body)
	rest := body[i+len(k):]
	return rest[:strings.Index(rest, `"`)]
}

func insertRaw(t *testing.T, q *gen.Queries, plain, email, family string, svcID *string) {
	t.Helper()
	sum := sha256.Sum256([]byte(plain))
	now := time.Now().UTC()
	require.NoError(t, q.InsertRefreshToken(context.Background(), gen.InsertRefreshTokenParams{
		TokenHash: hex.EncodeToString(sum[:]), Email: email, ServiceID: svcID, FamilyID: family,
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}))
}

// AK8.3: NULL, ukjent (ikke i cache) og inaktiv tjeneste avvises og familien revokeres.
func TestRefreshService_InvalidStoredServiceDenied(t *testing.T) {
	f, _, _ := newRefreshFx(t, nil, 0, nil)
	inactive := mkService(t, f.q, "svcdead", "d_tok", "PT15M", 0, nil, 0, nil)
	// Aktiv i DB, men ikke i registry-cachen (Warmup kjørt før opprettelse).
	unknown := mkService(t, f.q, "svcnew", "n_tok", "PT15M", 1, nil, 0, nil)

	cases := map[string]*string{"null": nil, "inactive": &inactive.ID, "unknown": &unknown.ID}
	for name, sid := range cases {
		t.Run(name, func(t *testing.T) {
			plain, child := "plain-"+name, "child-"+name
			insertRaw(t, f.q, plain, f.user.Email, "fam-"+name, sid)
			// Et søsken-token i samme familie skal også revokeres.
			insertRaw(t, f.q, child, f.user.Email, "fam-"+name, sid)

			before := f.auditCount(t, "refresh_service_invalid")
			w := f.post(plain, "svca")
			assertDenied(t, w)
			f.waitAudit(t, "refresh_service_invalid", before+1)
			var failed int
			require.NoError(t, f.sqldb.QueryRow(
				"SELECT COUNT(*) FROM audit_events WHERE event_type = 'refresh_service_invalid' AND success = 0").Scan(&failed))
			assert.Equal(t, before+1, failed)

			w2 := f.post(child, "svca")
			require.Equal(t, http.StatusUnauthorized, w2.Code)
			assert.NotContains(t, w2.Body.String(), "access_token")
		})
	}
}

func familyRevoked(t *testing.T, f *refreshFx, newToken string) {
	t.Helper()
	w := f.post(newToken, "")
	require.Equal(t, http.StatusUnauthorized, w.Code, w.Body.String())
	assert.NotContains(t, w.Body.String(), "access_token")
}

// AK8.4: policybrudd (require_role, enforce_org).
func TestRefreshService_PolicyDeniedRevokesFamily(t *testing.T) {
	role, org := "admin", "orgX"
	cases := []struct {
		name    string
		role    *string
		enforce int64
		org     *string
	}{
		{"require_role", &role, 0, nil},
		{"enforce_org", nil, 1, &org},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, a, _ := newRefreshFx(t, c.role, c.enforce, c.org)
			plain, err := f.refSvc.Issue(context.Background(), f.user, a, "127.0.0.1", "t")
			require.NoError(t, err)

			w := f.post(plain, "")
			assertDenied(t, w)
			f.waitAudit(t, "refresh_policy_denied", 1)

			// Barnet fra rotasjonen er revokert: finn det via familien.
			fam, err := f.q.GetRefreshTokenByHash(context.Background(), sha(plain))
			require.NoError(t, err)
			var live, revoked int
			require.NoError(t, f.sqldb.QueryRow(
				"SELECT COALESCE(SUM(used=0 AND revoked=0),0), COALESCE(SUM(revoked=1),0) FROM refresh_tokens WHERE family_id = ?",
				fam.FamilyID).Scan(&live, &revoked))
			assert.Equal(t, 0, live)
			// Familie-revokering tar også den brukte forelderen (008 F1).
			assert.Equal(t, 2, revoked)
		})
	}
}

func sha(plain string) string {
	s := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(s[:])
}

// Bruker som oppfyller policy får 200; AK8.5 for tjeneste uten policy dekkes av første test.
func TestRefreshService_PolicySatisfiedOK(t *testing.T) {
	role, org := "user", "org1"
	f, a, _ := newRefreshFx(t, &role, 1, &org)
	plain, err := f.refSvc.Issue(context.Background(), f.user, a, "127.0.0.1", "t")
	require.NoError(t, err)
	w := f.post(plain, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	// Audit er asynkron: vent på rotasjonseventet, som logges før en eventuell avvisning.
	f.waitAudit(t, "refresh_token_rotated", 1)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, f.auditCount(t, "refresh_policy_denied"))
}

// default_org uten enforce_org er bare en claim-default, ikke et krav.
// Alle prod-tjenester har default_org satt, så en feil her stenger ute brukere.
func TestRefreshService_DefaultOrgWithoutEnforceOK(t *testing.T) {
	org := "vinkjeller"
	f, a, _ := newRefreshFx(t, nil, 0, &org)
	plain, err := f.refSvc.Issue(context.Background(), f.user, a, "127.0.0.1", "t")
	require.NoError(t, err)
	w := f.post(plain, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	f.waitAudit(t, "refresh_token_rotated", 1)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, f.auditCount(t, "refresh_policy_denied"))
}

// Deaktivert bruker: uendret 401, og barnet fra rotasjonen revokeres.
func TestRefreshService_DeactivatedUserUnauthorized(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	plain, err := f.refSvc.Issue(context.Background(), f.user, a, "127.0.0.1", "t")
	require.NoError(t, err)
	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, f.q.DeactivateUser(context.Background(), gen.DeactivateUserParams{DeactivatedAt: &now, ID: f.user.ID}))
	w := f.post(plain, "")
	require.Equal(t, http.StatusUnauthorized, w.Code)
	assert.NotContains(t, w.Body.String(), "access_token")
	f.waitAudit(t, "refresh_user_inactive", 1)
	fam, err := f.q.GetRefreshTokenByHash(context.Background(), sha(plain))
	require.NoError(t, err)
	var live int
	require.NoError(t, f.sqldb.QueryRow(
		"SELECT COALESCE(SUM(used=0 AND revoked=0),0) FROM refresh_tokens WHERE family_id = ?", fam.FamilyID).Scan(&live))
	assert.Equal(t, 0, live)
}

// AK8.6: parallelle refresh av samme RT, nøyaktig én lykkes.
// SetMaxOpenConns(1) serialiserer DB-kallene, så testen fanger regresjoner i
// handler-logikken, ikke ekte samtidighet i SQLite; den garantien kommer fra
// UPDATE … RETURNING i konsumeringen. -race kjøres ikke på RPi5 (47-bits VMA).
func TestRefreshService_ParallelSameTokenExactlyOne(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	plain, err := f.refSvc.Issue(context.Background(), f.user, a, "127.0.0.1", "t")
	require.NoError(t, err)
	var ok int32
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if f.post(plain, "").Code == http.StatusOK {
				atomic.AddInt32(&ok, 1)
			}
		}()
	}
	wg.Wait()
	assert.Equal(t, int32(1), ok)
}
