package fetchmeta

import (
	"bytes"
	"log/slog"
	"strings"

	"github.com/go-chi/chi/v5"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSameOrigin(t *testing.T) {
	cases := []struct {
		name     string
		site     string
		origin   string
		insecure bool
		want     bool
	}{
		{"same-origin", "same-origin", "", false, true},
		{"same-site", "same-site", "", false, false},
		{"cross-site", "cross-site", "", false, false},
		{"none", "none", "", false, false},
		{"same-site med riktig Origin", "same-site", "https://auth.test", false, false},
		{"Origin uten Sec-Fetch-Site", "", "https://auth.test", false, true},
		{"Origin http uten insecure", "", "http://auth.test", false, false},
		{"Origin http med insecure", "", "http://auth.test", true, true},
		{"Origin null", "", "null", false, false},
		{"Origin annen vert", "", "https://evil.test", false, false},
		{"ingen headere", "", "", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.insecure {
				t.Setenv("KAUTH_INSECURE_COOKIES", "true")
			} else {
				t.Setenv("KAUTH_INSECURE_COOKIES", "")
			}
			r := httptest.NewRequest(http.MethodPost, "https://auth.test/x", nil)
			r.Host = "auth.test"
			if c.site != "" {
				r.Header.Set("Sec-Fetch-Site", c.site)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			require.Equal(t, c.want, SameOrigin(r))
		})
	}
}

// K26: avvisningen logges uten stien, som kan bære et engangstoken.
func TestSameOrigin_RejectionLogDoesNotLeakPath(t *testing.T) {
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	r := chi.NewRouter()
	r.Post("/magic-login/{token}", func(w http.ResponseWriter, r *http.Request) { SameOrigin(r) })
	req := httptest.NewRequest(http.MethodPost, "https://auth.test/magic-login/hemmelig?x=hemmelig", nil)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	r.ServeHTTP(httptest.NewRecorder(), req)

	require.NotEmpty(t, buf.String())
	require.False(t, strings.Contains(buf.String(), "hemmelig"), buf.String())
}

func TestMiddleware_UnsafeMethodsRequireSameOrigin(t *testing.T) {
	t.Setenv("KAUTH_INSECURE_COOKIES", "")
	cases := []struct {
		name         string
		site, origin string
		want         bool
	}{
		{"same-origin", "same-origin", "", true},
		{"Origin lik egen uten Sec-Fetch-Site", "", "https://auth.test", true},
		{"cross-site", "cross-site", "", false},
		{"same-site", "same-site", "", false},
		{"none", "none", "", false},
		{"Origin null", "", "null", false},
		{"ingen headere", "", "", false},
	}
	for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, c := range cases {
			t.Run(m+" "+c.name, func(t *testing.T) {
				called := false
				h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
				r := httptest.NewRequest(m, "https://auth.test/admin/x", nil)
				r.Host = "auth.test"
				if c.site != "" {
					r.Header.Set("Sec-Fetch-Site", c.site)
				}
				if c.origin != "" {
					r.Header.Set("Origin", c.origin)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				require.Equal(t, c.want, called)
				if !c.want {
					require.Equal(t, http.StatusForbidden, w.Code)
				}
			})
		}
	}
}

func TestMiddleware_SafeMethodsPass(t *testing.T) {
	for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		t.Run(m, func(t *testing.T) {
			called := false
			h := Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
			r := httptest.NewRequest(m, "https://auth.test/admin/x", nil)
			r.Header.Set("Sec-Fetch-Site", "cross-site")
			h.ServeHTTP(httptest.NewRecorder(), r)
			require.True(t, called)
		})
	}
}

func TestLogoutAllowed(t *testing.T) {
	cases := []struct {
		name             string
		site, mode, dest string
		want             bool
	}{
		{"ingen Sec-Fetch", "", "", "", true},
		{"same-origin", "same-origin", "navigate", "document", true},
		{"same-origin fetch", "same-origin", "cors", "empty", true},
		{"same-site", "same-site", "no-cors", "image", true},
		{"none", "none", "navigate", "document", true},
		{"cross-site navigate document", "cross-site", "navigate", "document", true},
		{"cross-site navigate uten Dest", "cross-site", "navigate", "", true},
		{"cross-site navigate iframe", "cross-site", "navigate", "iframe", false},
		{"cross-site no-cors image", "cross-site", "no-cors", "image", false},
		{"cross-site cors empty", "cross-site", "cors", "empty", false},
		{"cross-site uten Mode", "cross-site", "", "document", false},
		{"ukjent verdi", "bogus", "navigate", "document", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://auth.test/logout", nil)
			for k, v := range map[string]string{"Sec-Fetch-Site": c.site, "Sec-Fetch-Mode": c.mode, "Sec-Fetch-Dest": c.dest} {
				if v != "" {
					r.Header.Set(k, v)
				}
			}
			require.Equal(t, c.want, LogoutAllowed(r))
		})
	}
}
