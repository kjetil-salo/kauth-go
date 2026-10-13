package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const (
	msOrgTid  = "11111111-2222-3333-4444-555555555555"
	msTestNon = "nonce-abc"
)

func msIss(tid string) string { return "https://login.microsoftonline.com/" + tid + "/v2.0" }

func msBool(b bool) *bool { return &b }

func msValid(tid string, edov *bool) msClaims {
	return msClaims{Email: "a@example.com", Tid: tid, Iss: msIss(tid), Nonce: msTestNon, XmsEdov: edov}
}

func TestValidateMSClaims(t *testing.T) {
	mut := func(f func(*msClaims)) msClaims {
		c := msValid(msOrgTid, msBool(true))
		f(&c)
		return c
	}
	tests := []struct {
		name       string
		cl         msClaims
		stateNonce string
		wantEmail  string
		wantReason string
	}{
		{"msa uten edov godtas", msValid(msPersonalTenantID, nil), msTestNon, "a@example.com", ""},
		{"org med edov true", msValid(msOrgTid, msBool(true)), msTestNon, "a@example.com", ""},
		{"org uten edov", msValid(msOrgTid, nil), msTestNon, "", "edov"},
		{"org med edov false", msValid(msOrgTid, msBool(false)), msTestNon, "", "edov"},
		{"tom email", mut(func(c *msClaims) { c.Email = "" }), msTestNon, "", "email_missing"},
		{"blank email", mut(func(c *msClaims) { c.Email = "  " }), msTestNon, "", "email_missing"},
		{"msa tom email", func() msClaims { c := msValid(msPersonalTenantID, nil); c.Email = ""; return c }(), msTestNon, "", "email_missing"},
		{"tid ikke guid", msValid("ikke-guid", msBool(true)), msTestNon, "", "issuer"},
		{"tom tid", mut(func(c *msClaims) { c.Tid = "" }), msTestNon, "", "issuer"},
		{"iss annen tenant", mut(func(c *msClaims) { c.Iss = msIss("99999999-2222-3333-4444-555555555555") }), msTestNon, "", "issuer"},
		{"iss common", mut(func(c *msClaims) { c.Iss = msIss("common") }), msTestNon, "", "issuer"},
		{"iss uten v2.0", mut(func(c *msClaims) { c.Iss = "https://login.microsoftonline.com/" + msOrgTid + "/" }), msTestNon, "", "issuer"},
		{"msa-tid men org-iss", func() msClaims { c := msValid(msPersonalTenantID, nil); c.Iss = msIss(msOrgTid); return c }(), msTestNon, "", "issuer"},
		{"nonce mangler", mut(func(c *msClaims) { c.Nonce = "" }), msTestNon, "", "nonce"},
		{"nonce ulik", mut(func(c *msClaims) { c.Nonce = "annen" }), msTestNon, "", "nonce"},
		{"state-nonce tom", msValid(msOrgTid, msBool(true)), "", "", "nonce"},
		{"tom nonce i både state og claim", mut(func(c *msClaims) { c.Nonce = "" }), "", "", "nonce"},
		{"tid med prefiks", msValid("x"+msOrgTid, msBool(true)), msTestNon, "", "issuer"},
		{"tid med suffiks", msValid(msOrgTid+"x", msBool(true)), msTestNon, "", "issuer"},
		{"nonce foran issuer", mut(func(c *msClaims) { c.Nonce = "annen"; c.Iss = "x" }), msTestNon, "", "nonce"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			email, reason := validateMSClaims(tc.cl, tc.stateNonce)
			assert.Equal(t, tc.wantReason, reason)
			assert.Equal(t, tc.wantEmail, email)
		})
	}
}

// Brukernavn-claim i rå JSON skal ikke gi e-post (K3), og xms_edov som
// streng eller tall skal aldri tolkes som sann: dekodingen feiler lukket.
func TestMSClaims_RawJSON(t *testing.T) {
	var cl msClaims
	raw := `{"preferred_username":"u@example.com","tid":"` + msOrgTid + `","iss":"` + msIss(msOrgTid) + `","nonce":"` + msTestNon + `","xms_edov":true}`
	require.NoError(t, json.Unmarshal([]byte(raw), &cl))
	_, reason := validateMSClaims(cl, msTestNon)
	assert.Equal(t, "email_missing", reason)

	for _, v := range []string{`"true"`, `1`, `"1"`} {
		var c msClaims
		assert.Error(t, json.Unmarshal([]byte(`{"xms_edov":`+v+`}`), &c), v)
	}
}

type msFixture struct {
	h *MicrosoftHandlers
	q *gen.Queries
}

func newMSFixture(t *testing.T, autoRegister int64, requireRole *string) (*msFixture, *gen.Service) {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })
	sqldb.SetMaxOpenConns(1)
	ts := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(context.Background(), gen.CreateServiceParams{
		ID: "klarsyn", DisplayName: "Klarsyn", Domain: "klarsyn.net",
		CallbackUrl: "https://klarsyn.net/auth/callback", Theme: "light", AccentColor: "#000",
		EmailFromName: "Klarsyn", AuthMicrosoft: 1, AutoRegister: autoRegister, RequireRole: requireRole,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: ts,
	}))
	_, err = q.CreateUser(context.Background(), gen.CreateUserParams{Email: "kjent@example.com", Roles: "user", Orgs: "", CreatedAt: ts})
	require.NoError(t, err)
	svc := gen.Service{ID: "klarsyn", Domain: "klarsyn.net", IsDefault: 1, CallbackUrl: "https://klarsyn.net/auth/callback",
		AuthMicrosoft: 1, AutoRegister: autoRegister, RequireRole: requireRole, Active: 1}
	cfg := config.Config{OIDCStateSecret: []byte("test-secret-32bytes-padded-here!")}
	aud := audit.NewService(q)
	h := NewMicrosoftHandlers(cfg, q, token.NewIssuerForTest(), token.NewRefreshService(sqldb, aud), service.NewRegistryForTest([]gen.Service{svc}), aud)
	return &msFixture{h: h, q: q}, &svc
}

func msFinish(f *msFixture, svc *gen.Service, cl msClaims) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	f.h.finishCallback(rr, httptest.NewRequest(http.MethodGet, "/ms-callback", nil), svc, cl, msTestNon)
	return rr
}

func msAuditEvents(t *testing.T, f *msFixture, typ string, want int) []gen.AuditEvent {
	t.Helper()
	var out []gen.AuditEvent
	require.Eventually(t, func() bool {
		all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
		require.NoError(t, err)
		out = out[:0]
		for _, e := range all {
			if e.EventType == typ {
				out = append(out, e)
			}
		}
		return len(out) == want
	}, 2*time.Second, 10*time.Millisecond)
	return out
}

func TestMSFinish_Rejected_NoUserNoTokensAudited(t *testing.T) {
	f, svc := newMSFixture(t, 1, nil)
	before, err := f.q.CountUsers(context.Background())
	require.NoError(t, err)

	cl := msValid(msOrgTid, nil) // org uten xms_edov
	cl.Email = "ny@example.com"
	rr := msFinish(f, svc, cl)

	assert.Equal(t, http.StatusSeeOther, rr.Code)
	assert.Equal(t, "/login?error=login_failed&service=klarsyn", rr.Header().Get("Location"))
	assert.Empty(t, rr.Result().Cookies(), "ingen refresh-cookie")
	after, err := f.q.CountUsers(context.Background())
	require.NoError(t, err)
	assert.Equal(t, before, after, "ingen bruker opprettet ved auto-register")

	ev := msAuditEvents(t, f, "microsoft_oidc_rejected", 1)
	require.NotNil(t, ev[0].Details)
	assert.Equal(t, "tid="+msOrgTid+" reason=edov", *ev[0].Details)
}

func TestMSFinish_Accepted(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	cl := msValid(msOrgTid, msBool(true))
	cl.Email = "kjent@example.com"
	rr := msFinish(f, svc, cl)
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.True(t, strings.HasPrefix(rr.Header().Get("Location"), "/dispatch?"))
}

func TestMSFinish_NoAccountAndPolicy_IndistinguishableAccessDenied(t *testing.T) {
	role := "konge"
	f, svc := newMSFixture(t, 0, &role)

	noAcc := msValid(msOrgTid, msBool(true))
	noAcc.Email = "ukjent@example.com"
	a := msFinish(f, svc, noAcc)

	policy := msValid(msOrgTid, msBool(true))
	policy.Email = "kjent@example.com" // finnes, men mangler rollen konge
	b := msFinish(f, svc, policy)

	assert.Equal(t, http.StatusSeeOther, a.Code)
	assert.Equal(t, "/login?error=access_denied&service=klarsyn", a.Header().Get("Location"))
	assert.Equal(t, a.Code, b.Code)
	assert.Equal(t, a.Header().Get("Location"), b.Header().Get("Location"))
	assert.Equal(t, a.Body.String(), b.Body.String())
}

func TestMSInitiate_SendsNonceFromState(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	f.h.cfg.MicrosoftClientID = "cid"
	rr := httptest.NewRecorder()
	f.h.InitiateLogin(rr, httptest.NewRequest(http.MethodGet, "https://klarsyn.net/ms-oidc-login", nil))
	require.Equal(t, http.StatusFound, rr.Code)

	loc, err := url.Parse(rr.Header().Get("Location"))
	require.NoError(t, err)
	nonce := loc.Query().Get("nonce")
	require.NotEmpty(t, nonce)

	var cookie *http.Cookie
	for _, c := range rr.Result().Cookies() {
		if c.Name == "ms_state" {
			cookie = c
		}
	}
	require.NotNil(t, cookie)
	assert.Equal(t, cookie.Value, loc.Query().Get("state"))
	claims, ok := parseState(f.h.cfg.OIDCStateSecret, cookie.Value)
	require.True(t, ok)
	assert.Equal(t, nonce, claims.Nonce)
}

func TestMSCallback_BadState_RedirectsLoginFailed(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	secret := f.h.cfg.OIDCStateSecret
	admin := signAdminState(secret, "klarsyn", "n")
	cases := []struct {
		name, query string
		cookie      string
	}{
		{"uten cookie", "state=xyz&code=c", ""},
		{"cookie ulik url", "state=xyz&code=c", "annet"},
		{"ugyldig signatur", "state=xyz&code=c", "xyz"},
		{"admin-state", "state=" + admin + "&code=c", admin},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ms-callback?"+tc.query, nil)
			if tc.cookie != "" {
				req.AddCookie(&http.Cookie{Name: "ms_state", Value: tc.cookie})
			}
			rr := httptest.NewRecorder()
			f.h.HandleCallback(rr, req)
			assert.Equal(t, http.StatusSeeOther, rr.Code)
			assert.Equal(t, "/login?error=login_failed", rr.Header().Get("Location"))
		})
	}
}

func msStateCookieReq(t *testing.T, f *msFixture, nonce string) *http.Request {
	t.Helper()
	st := SignState(f.h.cfg.OIDCStateSecret, "klarsyn", nonce)
	req := httptest.NewRequest(http.MethodGet, "/ms-callback?code=c&state="+url.QueryEscape(st), nil)
	req.AddCookie(&http.Cookie{Name: "ms_state", Value: st})
	return req
}

// Nonce i id_token må sammenlignes med nonce fra den signerte staten, ikke
// med seg selv.
func TestMSCallback_ComparesNonceFromSignedState(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	good := msValid(msOrgTid, msBool(true))
	good.Email = "kjent@example.com"
	good.Nonce = "state-nonce"

	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) { return good, nil }
	rr := httptest.NewRecorder()
	f.h.HandleCallback(rr, msStateCookieReq(t, f, "state-nonce"))
	assert.Equal(t, http.StatusFound, rr.Code)
	assert.True(t, strings.HasPrefix(rr.Header().Get("Location"), "/dispatch?"))

	rr = httptest.NewRecorder()
	f.h.HandleCallback(rr, msStateCookieReq(t, f, "annen-nonce"))
	assert.Equal(t, "/login?error=login_failed&service=klarsyn", rr.Header().Get("Location"))
	msAuditEvents(t, f, "microsoft_oidc_rejected", 1)
}

func TestMSCallback_ClaimsDecodeFailure_Audited(t *testing.T) {
	f, _ := newMSFixture(t, 0, nil)
	f.h.fetchClaims = func(context.Context, *oauth2.Config, string) (msClaims, error) {
		return msClaims{Tid: msOrgTid}, errClaimsDecode
	}
	rr := httptest.NewRecorder()
	f.h.HandleCallback(rr, msStateCookieReq(t, f, "n"))
	assert.Equal(t, "/login?error=login_failed&service=klarsyn", rr.Header().Get("Location"))
	ev := msAuditEvents(t, f, "microsoft_oidc_rejected", 1)
	require.NotNil(t, ev[0].Details)
	assert.Equal(t, "tid="+msOrgTid+" reason=claims_decode", *ev[0].Details)
}

func TestMSFinish_TrimsEmail(t *testing.T) {
	f, svc := newMSFixture(t, 0, nil)
	cl := msValid(msOrgTid, msBool(true))
	cl.Email = "  kjent@example.com\t"
	rr := msFinish(f, svc, cl)
	assert.Equal(t, http.StatusFound, rr.Code)
}
