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
