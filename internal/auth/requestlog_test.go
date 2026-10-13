package auth

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

func TestMaskPath(t *testing.T) {
	cases := map[string]string{
		"/magic-login/0123abcd":  "/magic-login/***",
		"/magic-login/":          "/magic-login",
		"/magic-login/abc/def":   "/magic-login/***",
		"/magic-login":           "/magic-login",
		"//magic-login/X":        "/magic-login/***",
		"/Magic-Login/X":         "/Magic-Login/***",
		"/./magic-login/X":       "/magic-login/***",
		"/magic-login/X/":        "/magic-login/***",
		"/a/..//MAGIC-LOGIN/X":   "/MAGIC-LOGIN/***",
		"/x/magic-login/abcdef0": "/x/magic-login/***",
		"/magic-login%2FX":       "/magic-login%2FX",
		"/dispatch":              "/dispatch",
		"/callback":              "/callback",
		"":                       "/",
	}
	for in, want := range cases {
		if got := maskPath(in); got != want {
			t.Errorf("maskPath(%q) = %q, vil ha %q", in, got, want)
		}
	}
	// %2F dekodes av net/http til "/" i URL.Path før maskPath ser den.
	if got := maskPath("/magic-login/X"); got != "/magic-login/***" {
		t.Errorf("dekodet %%2F: %q", got)
	}
	if got := maskPath("/" + strings.Repeat("a", 500)); len(got) != 256 {
		t.Errorf("forventet avkorting til 256, fikk %d", len(got))
	}
}

func newTestLogger(buf *bytes.Buffer) *slog.Logger {
	return slog.New(slog.NewTextHandler(buf, nil))
}

func serveLogged(h http.Handler, method, target string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	req.RemoteAddr = "203.0.113.7:4321"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func loggedChain(buf *bytes.Buffer, final http.Handler) http.Handler {
	return ClientIPMiddleware(RequestLogger(newTestLogger(buf))(final))
}

func TestRequestLogger_LekkerIkkeQuery(t *testing.T) {
	var buf bytes.Buffer
	h := loggedChain(&buf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
	}))
	for _, target := range []string{
		"/dispatch?token=eyJxxx&rt=abc",
		"/admin/verify?token=zzz",
		"/callback?code=c&state=s",
		"/token?refresh_token=r",
		"/magic-login/deadbeefdeadbeef",
		"//magic-login/deadbeefdeadbeef",
		"/Magic-Login/deadbeefdeadbeef",
		"/./magic-login/deadbeefdeadbeef",
		"/magic-login%2Fdeadbeefdeadbeef",
		"/foo%3Fbar?token=eyJsecret",
	} {
		serveLogged(h, http.MethodGet, target)
	}
	out := buf.String()
	for _, forbidden := range []string{"eyJ", "token=", "rt=", "code=", "state=", "refresh_token", "RawQuery", "RequestURI", "deadbeef"} {
		if strings.Contains(out, forbidden) {
			t.Errorf("loggen inneholder %q:\n%s", forbidden, out)
		}
	}
	if !strings.Contains(out, "/magic-login/***") {
		t.Errorf("forventet maskert magic-login-sti:\n%s", out)
	}
}

func TestRequestLogger_Felter(t *testing.T) {
	var buf bytes.Buffer
	h := loggedChain(&buf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = w.Write([]byte("hei"))
	}))
	serveLogged(h, http.MethodPost, "/foo?a=b")
	out := buf.String()
	for _, want := range []string{"method=POST", "path=/foo", "status=418", "bytes=3", "duration=", "ip=203.0.113.7"} {
		if !strings.Contains(out, want) {
			t.Errorf("mangler %q i:\n%s", want, out)
		}
	}
	if n := strings.Count(out, "\n"); n != 1 {
		t.Errorf("forventet én linje, fikk %d", n)
	}
}

func TestRequestLogger_PanikGirFortsattLogglinje(t *testing.T) {
	var buf bytes.Buffer
	h := chimiddleware.Recoverer(loggedChain(&buf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	})))
	rec := serveLogged(h, http.MethodGet, "/x?token=eyJ")
	if rec.Code != 500 {
		t.Errorf("forventet 500 fra Recoverer, fikk %d", rec.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "status=500") || !strings.Contains(out, "path=/x") || !strings.Contains(out, "level=ERROR") {
		t.Errorf("forventet ERROR-linje med status 500:\n%s", out)
	}
	if strings.Contains(out, "token=") || strings.Contains(out, "eyJ") {
		t.Errorf("query lekket:\n%s", out)
	}
}

func TestRequestLogger_PanikPropagererUtenRecoverer(t *testing.T) {
	for _, v := range []any{"boom", http.ErrAbortHandler} {
		var buf bytes.Buffer
		h := loggedChain(&buf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { panic(v) }))
		func() {
			defer func() {
				if got := recover(); got != v {
					t.Errorf("forventet re-panic med %v, fikk %v", v, got)
				}
			}()
			serveLogged(h, http.MethodGet, "/x")
		}()
		if !strings.Contains(buf.String(), "status=500") {
			t.Errorf("mangler logglinje for %v:\n%s", v, buf.String())
		}
	}
}

func TestRequestLogger_PanikEtterWriteHeaderBeholderStatus(t *testing.T) {
	var buf bytes.Buffer
	h := chimiddleware.Recoverer(loggedChain(&buf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusSeeOther)
		panic("boom")
	})))
	serveLogged(h, http.MethodGet, "/x")
	if !strings.Contains(buf.String(), "status=303") {
		t.Errorf("forventet status=303:\n%s", buf.String())
	}
}

func TestRequestLogger_ImplisittOK(t *testing.T) {
	var buf bytes.Buffer
	h := loggedChain(&buf, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	serveLogged(h, http.MethodGet, "/x")
	if !strings.Contains(buf.String(), "status=200") || !strings.Contains(buf.String(), "bytes=0") {
		t.Errorf("forventet status=200 bytes=0:\n%s", buf.String())
	}
}

func TestRequestLogger_RuteMønsterLogges(t *testing.T) {
	var buf bytes.Buffer
	r := chi.NewRouter()
	r.Use(ClientIPMiddleware)
	r.Use(RequestLogger(newTestLogger(&buf)))
	r.Get("/magic-login/{token}", func(w http.ResponseWriter, r *http.Request) {})
	serveLogged(r, http.MethodGet, "/magic-login/deadbeefdeadbeef")
	serveLogged(r, http.MethodGet, "//magic-login/deadbeefdeadbeef")
	out := buf.String()
	if !strings.Contains(out, "path=/magic-login/{token}") {
		t.Errorf("forventet rutemønster:\n%s", out)
	}
	if strings.Contains(out, "deadbeef") {
		t.Errorf("token lekket:\n%s", out)
	}
	if !strings.Contains(out, "status=404") || !strings.Contains(out, "path=/magic-login/***") {
		t.Errorf("forventet maskert 404-sti:\n%s", out)
	}
}

// K26: POST-en som bruker opp tokenet logges som rutemønster, uten token.
func TestRequestLogger_MagicConfirmPostMasked(t *testing.T) {
	var buf bytes.Buffer
	r := chi.NewRouter()
	r.Use(ClientIPMiddleware)
	r.Use(RequestLogger(newTestLogger(&buf)))
	r.Post("/magic-login/{token}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusFound)
	})
	serveLogged(r, http.MethodPost, "/magic-login/deadbeefdeadbeef?service=x")
	serveLogged(r, http.MethodPost, "//magic-login/deadbeefdeadbeef")
	out := buf.String()
	if !strings.Contains(out, "method=POST") || !strings.Contains(out, "path=/magic-login/{token}") {
		t.Errorf("forventet POST med rutemønster:\n%s", out)
	}
	if strings.Contains(out, "deadbeef") {
		t.Errorf("token lekket:\n%s", out)
	}
}

type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func TestRequestLogger_Parallelt(t *testing.T) {
	sb := &syncBuf{}
	h := ClientIPMiddleware(RequestLogger(slog.New(slog.NewTextHandler(sb, nil)))(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) })))
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			serveLogged(h, http.MethodGet, fmt.Sprintf("/p?token=t%d", i))
		}(i)
	}
	wg.Wait()
	if n := strings.Count(sb.buf.String(), "\n"); n != 50 {
		t.Errorf("forventet 50 linjer, fikk %d", n)
	}
}
