package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
)

const allowedOrigin = "https://kjeller.lilleklo.work"

func refreshReq(plain string, origin *string) *http.Request {
	req := httptest.NewRequest("POST", "/token",
		strings.NewReader("grant_type=refresh_token&refresh_token="+plain))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if origin != nil {
		req.Header["Origin"] = []string{*origin}
	}
	return req
}

// refresh kjører requesten gjennom ekte CORS-kjede, slik at fravær av ACAO er reell.
func refresh(h *auth.PasswordHandlers, origins []string, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	auth.CORSMiddleware(origins)(http.HandlerFunc(h.Token)).ServeHTTP(w, req)
	return w
}

func sp(s string) *string { return &s }

// AK7.3 + AK7.4: avvist Origin gir 403 uten CORS-headere, og samme RT kan
// deretter brukes fra tillatt Origin (ingen rotasjon, ingen reuse-deteksjon).
func TestRefreshToken_InvalidOriginRejectedBeforeRotation(t *testing.T) {
	h, refSvc, user, svc := setupRefreshTest(t)
	h.WithCORSOrigins([]string{allowedOrigin, "https://spekto.live"})
	plain, err := refSvc.Issue(context.Background(), user, svc, "127.0.0.1", "test")
	require.NoError(t, err)

	list := []string{allowedOrigin, "https://spekto.live"}
	bad := []string{
		"https://evil.example", "null", "",
		"http://kjeller.lilleklo.work",
		allowedOrigin + ":8443",
		allowedOrigin + "/",
	}
	for _, o := range bad {
		w := refresh(h, list, refreshReq(plain, sp(o)))
		require.Equal(t, http.StatusForbidden, w.Code, "origin %q", o)
		assert.JSONEq(t, `{"error":"invalid_origin"}`, w.Body.String(), "origin %q", o)
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
	}

	// To Origin-headere (tillatt + evil) avvises, selv om CORS-laget så den første.
	two := refreshReq(plain, sp(allowedOrigin))
	two.Header.Add("Origin", "https://evil.example")
	w2 := refresh(h, list, two)
	require.Equal(t, http.StatusForbidden, w2.Code)
	assert.Empty(t, w2.Header().Get("Access-Control-Allow-Origin"))

	w := refresh(h, list, refreshReq(plain, sp(allowedOrigin)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, allowedOrigin, w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Body.String(), "refresh_token")
	assert.NotEmpty(t, w.Result().Cookies())
}

// AK7.5: uten Origin (server-til-server) er refresh uendret.
func TestRefreshToken_NoOriginUnchanged(t *testing.T) {
	h, refSvc, user, svc := setupRefreshTest(t)
	h.WithCORSOrigins([]string{allowedOrigin})
	plain, err := refSvc.Issue(context.Background(), user, svc, "127.0.0.1", "test")
	require.NoError(t, err)

	w := httptest.NewRecorder()
	h.RefreshToken(w, refreshReq(plain, nil))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Contains(t, w.Body.String(), "access_token")
	assert.NotEmpty(t, w.Result().Cookies())
}

// Tom allowlist: enhver Origin avvises, ingen Origin fungerer fortsatt.
func TestRefreshToken_EmptyAllowlistRejectsAnyOrigin(t *testing.T) {
	h, refSvc, user, svc := setupRefreshTest(t)
	plain, err := refSvc.Issue(context.Background(), user, svc, "127.0.0.1", "test")
	require.NoError(t, err)
	w := httptest.NewRecorder()
	h.RefreshToken(w, refreshReq(plain, sp(allowedOrigin)))
	require.Equal(t, http.StatusForbidden, w.Code)
}

// AK7.6: authorization_code-grant røres ikke av Origin-sjekken.
func TestToken_AuthorizationCodeIgnoresOriginCheck(t *testing.T) {
	h, _, _, _ := setupRefreshTest(t)
	h.WithCORSOrigins([]string{allowedOrigin})
	req := httptest.NewRequest("POST", "/token", strings.NewReader("grant_type=authorization_code"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://evil.example")
	w := httptest.NewRecorder()
	h.Token(w, req)
	require.Equal(t, http.StatusBadRequest, w.Code)
	assert.JSONEq(t, `{"error":"invalid_request"}`, w.Body.String())
}

func TestOriginAllowed(t *testing.T) {
	assert.True(t, auth.OriginAllowed([]string{allowedOrigin}, allowedOrigin))
	assert.False(t, auth.OriginAllowed([]string{allowedOrigin}, "https://evil.example"))
	assert.False(t, auth.OriginAllowed([]string{"null", ""}, "null"))
	assert.False(t, auth.OriginAllowed([]string{""}, ""))
}
