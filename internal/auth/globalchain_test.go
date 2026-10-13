package auth_test

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"

	"github.com/zral/kauth-go/internal/auth"
)

// Kjeden selv må ikke stole på X-Forwarded-For og lignende: en RealIP-lignende
// middleware ville skrevet om RemoteAddr før ClientIP vurderer loopback.
func TestUseGlobal_ClientIPIgnoresForwardedHeaders(t *testing.T) {
	r := chi.NewRouter()
	auth.UseGlobal(r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	var got string
	r.Get("/ip", func(w http.ResponseWriter, req *http.Request) { got = auth.ClientIP(req) })

	cases := []struct{ name, remote, cf, want string }{
		{"tunnel med CF", "127.0.0.1:5000", "198.51.100.7", "198.51.100.7"},
		{"tunnel uten CF", "127.0.0.1:5000", "", "127.0.0.1"},
		{"direkte fra LAN", "192.168.1.5:5000", "198.51.100.7", "192.168.1.5"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/ip", nil)
			req.RemoteAddr = c.remote
			if c.cf != "" {
				req.Header.Set("CF-Connecting-IP", c.cf)
			}
			req.Header.Set("X-Forwarded-For", "6.6.6.6")
			req.Header.Set("X-Real-IP", "6.6.6.6")
			req.Header.Set("True-Client-IP", "6.6.6.6")
			r.ServeHTTP(httptest.NewRecorder(), req)
			assert.Equal(t, c.want, got)
		})
	}
}
