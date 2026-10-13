package auth

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

var wantSecHeaders = map[string]string{
	"X-Content-Type-Options":    "nosniff",
	"Referrer-Policy":           "no-referrer",
	"X-Frame-Options":           "DENY",
	"Content-Security-Policy":   "frame-ancestors 'none'",
	"Strict-Transport-Security": "max-age=31536000",
}

// Samme rekkefølge som main.go: SecurityHeaders først, så Recoverer.
func secHeadersRouter(tdir string) http.Handler {
	r := chi.NewRouter()
	UseGlobal(r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	r.Get("/login", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html></html>"))
	})
	r.Get("/dispatch", func(w http.ResponseWriter, req *http.Request) {
		http.Redirect(w, req, "/login", http.StatusSeeOther)
	})
	r.Post("/token", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_request"}`))
	})
	dir := tdir
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.Dir(dir))))
	r.Get("/panic", func(http.ResponseWriter, *http.Request) { panic("boom") })
	r.With(func(http.Handler) http.Handler {
		return http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("mw") })
	}).Get("/panic-mw", func(http.ResponseWriter, *http.Request) {})
	r.Route("/.well-known", func(r chi.Router) {
		r.Use(CORSMiddleware([]string{"https://app.example"}))
		r.Get("/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"keys":[]}`))
		})
	})
	return r
}

func TestSecurityHeaders_AllResponseTypes(t *testing.T) {
	cases := []struct {
		name, method, path string
		origin             string
		status             int
	}{
		{"200 html", "GET", "/login", "", 200},
		{"303 redirect", "GET", "/dispatch", "", 303},
		{"json-feil", "POST", "/token", "", 400},
		{"404", "GET", "/finnes-ikke", "", 404},
		{"405", "DELETE", "/login", "", 405},
		{"static finnes", "GET", "/static/app.css", "", 200},
		{"static 404", "GET", "/static/mangler.css", "", 404},
		{"panikk i middleware gir 500", "GET", "/panic-mw", "", 500},
		{"panikk gir 500", "GET", "/panic", "", 500},
		{"preflight", "OPTIONS", "/.well-known/jwks.json", "https://app.example", 204},
		{"jwks med cors", "GET", "/.well-known/jwks.json", "https://app.example", 200},
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.css"), []byte("body{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := secHeadersRouter(dir)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("status = %d, vil ha %d", rec.Code, tc.status)
			}
			for k, want := range wantSecHeaders {
				if got := rec.Header().Get(k); got != want {
					t.Errorf("%s = %q, vil ha %q", k, got, want)
				}
			}
			if tc.origin != "" && rec.Header().Get("Access-Control-Allow-Origin") != tc.origin {
				t.Error("CORS-headere skal være uberørt")
			}
		})
	}
}

func TestSecurityHeaders_Negative(t *testing.T) {
	rec := httptest.NewRecorder()
	secHeadersRouter(t.TempDir()).ServeHTTP(rec, httptest.NewRequest("GET", "/login", nil))
	csp := rec.Header().Get("Content-Security-Policy")
	for _, bad := range []string{"script-src", "default-src"} {
		if strings.Contains(csp, bad) {
			t.Errorf("CSP skal ikke inneholde %s: %q", bad, csp)
		}
	}
	hsts := rec.Header().Get("Strict-Transport-Security")
	for _, bad := range []string{"includeSubDomains", "preload"} {
		if strings.Contains(hsts, bad) {
			t.Errorf("HSTS skal ikke inneholde %s: %q", bad, hsts)
		}
	}
}

// Valgt oppførsel: headerne settes før handleren, så en handler som selv
// kaller Set vinner. Ingen handler gjør det i dag.
func TestSecurityHeaders_HandlerCanOverride(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q, handler skal kunne overstyre", got)
	}
	if got := rec.Header().Get("Referrer-Policy"); got != "no-referrer" {
		t.Errorf("Referrer-Policy = %q", got)
	}
}

// Rekkefølgen er ikke observerbar via headere (de settes før noe kan panikke),
// så den låses strukturelt: SecurityHeaders må ligge før Recoverer i kjeden.
func TestUseGlobal_SecurityHeadersOutsideRecoverer(t *testing.T) {
	r := chi.NewRouter()
	UseGlobal(r, slog.New(slog.NewTextHandler(io.Discard, nil)))
	name := func(f any) string { return runtime.FuncForPC(reflect.ValueOf(f).Pointer()).Name() }
	idx := func(want string) int {
		for i, m := range r.Middlewares() {
			if name(m) == want {
				return i
			}
		}
		return -1
	}
	sec, rec := idx(name(SecurityHeaders)), idx(name(chimiddleware.Recoverer))
	if sec < 0 || rec < 0 || sec > rec {
		t.Errorf("SecurityHeaders (%d) må ligge før Recoverer (%d)", sec, rec)
	}
}

// Vakt: CSP og X-Frame-Options skal bare settes i secheaders.go, ellers kan en
// handler stille svekke vernet.
func TestSecurityHeaders_NotSetElsewhere(t *testing.T) {
	var offenders []string
	scanned, sawMain := 0, false
	for _, root := range []string{"../../internal", "../../cmd"} {
		err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") ||
				strings.HasSuffix(p, "_test.go") || filepath.Base(p) == "secheaders.go" {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			scanned++
			if filepath.ToSlash(p) == "../../cmd/kauth/main.go" {
				sawMain = true
			}
			// Små bokstaver fanger også w.Header()["content-security-policy"].
			src := strings.ToLower(string(b))
			for _, h := range []string{"content-security-policy", "x-frame-options"} {
				if strings.Contains(src, h) {
					offenders = append(offenders, p+": "+h)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatalf("skanning av %s: %v", root, err)
		}
	}
	// En vakt som ikke skanner noe, er grønn uten å vokte noe.
	if scanned == 0 || !sawMain {
		t.Fatalf("vakttesten skannet %d filer (main.go sett: %v), sjekk stiene", scanned, sawMain)
	}
	if len(offenders) > 0 {
		t.Errorf("sikkerhetsheadere satt utenfor secheaders.go: %v", offenders)
	}
}
