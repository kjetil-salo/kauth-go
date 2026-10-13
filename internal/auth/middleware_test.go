package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/zral/kauth-go/internal/auth"
)

func corsDo(origins []string, origin string) *httptest.ResponseRecorder {
	h := auth.CORSMiddleware(origins)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest("GET", "/x", nil)
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

func TestCORSMiddleware(t *testing.T) {
	list := []string{"https://a.example"}
	w := corsDo(list, "https://a.example")
	assert.Equal(t, "https://a.example", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))

	assert.Empty(t, corsDo(list, "https://evil.example").Header().Get("Access-Control-Allow-Origin"))
	assert.Empty(t, corsDo(list, "null").Header().Get("Access-Control-Allow-Origin"))
	// "*" i listen er ikke lenger wildcard og speiler aldri vilkårlig Origin.
	assert.Empty(t, corsDo([]string{"*"}, "https://evil.example").Header().Get("Access-Control-Allow-Origin"))
}
