package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
)

func (f *refreshFx) logout(cookie, query string) *httptest.ResponseRecorder {
	h := &auth.DispatchHandler{Registry: f.reg, Refresh: f.refSvc, Audit: audit.NewService(f.q)}
	req := httptest.NewRequest("GET", "/logout"+query, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: "refresh_token", Value: cookie})
	}
	w := httptest.NewRecorder()
	h.ServeLogout(w, req)
	return w
}

func (f *refreshFx) revokedCounts(t *testing.T) (total, revoked, userLogout int) {
	t.Helper()
	require.NoError(t, f.sqldb.QueryRow(
		`SELECT COUNT(*), COALESCE(SUM(revoked),0), COALESCE(SUM(revoked_reason='user_logout'),0) FROM refresh_tokens`,
	).Scan(&total, &revoked, &userLogout))
	return
}

func TestLogout_RevokesFamilyOfCookie(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt1, err := f.refSvc.Issue(context.Background(), f.user, a, "1.1.1.1", "ua")
	require.NoError(t, err)
	w := f.post(rt1, "")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &body))
	rt2 := body.RefreshToken
	require.NotEmpty(t, rt2)

	lw := f.logout(rt2, "")
	assert.Equal(t, http.StatusSeeOther, lw.Code)
	assert.Equal(t, "/login", lw.Header().Get("Location"))

	total, revoked, byLogout := f.revokedCounts(t)
	assert.Equal(t, 2, total)
	assert.Equal(t, 2, revoked)
	assert.GreaterOrEqual(t, byLogout, 1)
	f.waitAudit(t, "user_logout", 1)

	// AK4.3: ingen av tokenene gir nye tokens etterpå.
	for _, rt := range []string{rt1, rt2} {
		rw := f.post(rt, "")
		assert.NotEqual(t, http.StatusOK, rw.Code)
		assert.NotContains(t, rw.Body.String(), "access_token")
	}
}

func TestLogout_WithoutCookie_Unchanged(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	_, err := f.refSvc.Issue(context.Background(), f.user, a, "", "")
	require.NoError(t, err)
	w := f.logout("", "?redirect_uri=https://svca.test/cb")
	assert.Equal(t, "https://svca.test/cb", w.Header().Get("Location"))
	assert.NotNil(t, cookieByName(w, "refresh_token"))
	assert.Len(t, w.Result().Cookies(), 2)
	_, revoked, _ := f.revokedCounts(t)
	assert.Equal(t, 0, revoked)
	assert.Equal(t, 0, f.auditCount(t, "user_logout"))
}

func TestLogout_UnknownCookie_Unchanged(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	_, err := f.refSvc.Issue(context.Background(), f.user, a, "", "")
	require.NoError(t, err)
	w := f.logout("garbage", "?redirect_uri=https://evil.example/")
	assert.Equal(t, "/login", w.Header().Get("Location"))
	assert.NotNil(t, cookieByName(w, "refresh_token"))
	_, revoked, _ := f.revokedCounts(t)
	assert.Equal(t, 0, revoked)
	assert.Equal(t, 0, f.auditCount(t, "user_logout"))
}

func TestLogout_NilRefresh_NoPanic(t *testing.T) {
	f, _, _ := newRefreshFx(t, nil, 0, nil)
	h := &auth.DispatchHandler{Registry: f.reg}
	req := httptest.NewRequest("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: "x"})
	w := httptest.NewRecorder()
	assert.NotPanics(t, func() { h.ServeLogout(w, req) })
	assert.Equal(t, "/login", w.Header().Get("Location"))
}

func TestLogout_Twice_SingleAudit(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt, err := f.refSvc.Issue(context.Background(), f.user, a, "", "")
	require.NoError(t, err)
	f.logout(rt, "")
	f.waitAudit(t, "user_logout", 1)
	f.logout(rt, "")
	// Auditen er asynkron: gi en eventuell feilaktig andre skriving tid til å dukke opp.
	// Egen løkke i teststråden: require.Never kjører i en goroutine som kan overleve DB-lukkingen.
	for deadline := time.Now().Add(300 * time.Millisecond); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		require.Equal(t, 1, f.auditCount(t, "user_logout"))
	}
}

func TestLogout_CancelledContext_StillRevokes(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt, err := f.refSvc.Issue(context.Background(), f.user, a, "", "")
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	h := &auth.DispatchHandler{Registry: f.reg, Refresh: f.refSvc, Audit: audit.NewService(f.q)}
	req := httptest.NewRequest("GET", "/logout", nil).WithContext(ctx)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: rt})
	h.ServeLogout(httptest.NewRecorder(), req)
	_, revoked, byLogout := f.revokedCounts(t)
	assert.Equal(t, 1, revoked)
	assert.Equal(t, 1, byLogout)
}

// logoutWith sender GET /logout med Fetch Metadata-headere.
func (f *refreshFx) logoutWith(cookie string, hdr map[string]string) *httptest.ResponseRecorder {
	h := &auth.DispatchHandler{Registry: f.reg, Refresh: f.refSvc, Audit: audit.NewService(f.q)}
	req := httptest.NewRequest("GET", "/logout", nil)
	req.AddCookie(&http.Cookie{Name: "refresh_token", Value: cookie})
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeLogout(w, req)
	return w
}

func assertLogoutRejected(t *testing.T, f *refreshFx, w *httptest.ResponseRecorder) {
	t.Helper()
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/login", w.Header().Get("Location"))
	assert.Empty(t, w.Result().Cookies(), "ingen Set-Cookie")
	_, revoked, _ := f.revokedCounts(t)
	assert.Equal(t, 0, revoked)
	time.Sleep(50 * time.Millisecond)
	assert.Equal(t, 0, f.auditCount(t, "user_logout"))
}

func TestLogout_CrossSiteSubresource_NoRevokeNoSetCookie(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt, err := f.refSvc.Issue(context.Background(), f.user, a, "1.1.1.1", "ua")
	require.NoError(t, err)
	w := f.logoutWith(rt, map[string]string{
		"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Dest": "image"})
	assertLogoutRejected(t, f, w)
}

func TestLogout_CrossSiteIframe_NoRevoke(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt, err := f.refSvc.Issue(context.Background(), f.user, a, "1.1.1.1", "ua")
	require.NoError(t, err)
	w := f.logoutWith(rt, map[string]string{
		"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe"})
	assertLogoutRejected(t, f, w)
}

func TestLogout_CrossSiteTopLevelNavigate_Revokes(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt, err := f.refSvc.Issue(context.Background(), f.user, a, "1.1.1.1", "ua")
	require.NoError(t, err)
	w := f.logoutWith(rt, map[string]string{
		"Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document"})
	assert.Equal(t, http.StatusSeeOther, w.Code)
	_, revoked, _ := f.revokedCounts(t)
	assert.Equal(t, 1, revoked)
	f.waitAudit(t, "user_logout", 1)
}

func TestLogout_NoFetchMetadata_Revokes(t *testing.T) {
	f, a, _ := newRefreshFx(t, nil, 0, nil)
	rt, err := f.refSvc.Issue(context.Background(), f.user, a, "1.1.1.1", "ua")
	require.NoError(t, err)
	w := f.logoutWith(rt, nil)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	_, revoked, _ := f.revokedCounts(t)
	assert.Equal(t, 1, revoked)
	f.waitAudit(t, "user_logout", 1)
}
