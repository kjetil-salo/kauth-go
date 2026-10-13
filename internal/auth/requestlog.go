package auth

import (
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

const (
	maxLoggedPath = 256
	maxLoggedIP   = 64
)

// maskPath normaliserer stien og skjuler alt etter et magic-login-segment.
// Tokenet er et engangs-credential og skal aldri havne i journald, også ikke
// når stien ikke matcher en rute (//magic-login/X, /Magic-Login/X,
// /./magic-login/X og %2F gir 404, men står likevel i loggen).
func maskPath(p string) string {
	segs := strings.Split(path.Clean("/"+p), "/")
	for i, seg := range segs {
		if strings.EqualFold(seg, "magic-login") && i < len(segs)-1 {
			segs = append(segs[:i+1], "***")
			break
		}
	}
	return truncate(strings.Join(segs, "/"), maxLoggedPath)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// RequestLogger logger én linje per request med et fast hvitelistet felt-
// sett. Query-strengen er bevisst utelatt: den bærer token, rt, code og state
// (/dispatch, /admin/verify, /callback), og en svartelistet tilnærming ville
// lekket ved første nye parameter. Når ruten matcher logges chi sitt mønster
// (/magic-login/{token}), ellers den normaliserte, maskerte stien. Må monteres
// etter ClientIPMiddleware, og innenfor Recoverer slik at en panikk fortsatt
// gir logglinje (defer). Panikkverdier skal ikke inneholde URL eller token,
// fordi Recoverer skriver dem til stderr.
func RequestLogger(l *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			defer func() {
				rec := recover()
				status := ww.Status()
				if status == 0 {
					status = http.StatusOK
					if rec != nil {
						// Ingenting skrevet: Recoverer svarer 500.
						status = http.StatusInternalServerError
					}
				}
				loggedPath := maskPath(r.URL.Path)
				if rctx := chi.RouteContext(r.Context()); rctx != nil {
					if pat := rctx.RoutePattern(); pat != "" && !strings.Contains(pat, "*") {
						loggedPath = pat
					}
				}
				attrs := []any{
					"method", r.Method, "path", loggedPath,
					"status", status, "bytes", ww.BytesWritten(),
					"duration", time.Since(start),
					"ip", truncate(ClientIP(r), maxLoggedIP),
				}
				if rec != nil {
					l.Error("request panic", attrs...)
					panic(rec)
				}
				l.Info("request", attrs...)
			}()
			next.ServeHTTP(ww, r)
		})
	}
}
