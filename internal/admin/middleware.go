package admin

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/zral/kauth-go/internal/token"
)

// AdminAuthMiddleware beskytter alle /admin/-ruter unntatt /admin/login og /admin/verify.
// HTML-requester (Accept: text/html eller ingen Accept) → 303 /admin/login.
// JSON-requester (Accept: application/json) → 401 JSON-feil.
func AdminAuthMiddleware(issuer *token.Issuer) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("admin_token")
			if err != nil {
				respondUnauthorized(w, r, "ingen admin_token-cookie")
				return
			}

			// Formål og aud sjekkes i Verify: et access-token, eller et admin-token
			// fra før aud ble innført, skal ikke gi admin-tilgang.
			claims, err := issuer.Verify(cookie.Value, token.ExpectAdmin)
			if err != nil {
				slog.Debug("admin-token avvist", "error", err)
				respondUnauthorized(w, r, "unauthorized")
				return
			}

			if !hasRole(strings.Join(claims.Groups, ","), "konge") {
				respondUnauthorized(w, r, "mangler konge-rolle")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// respondUnauthorized sender enten 303 → /admin/login (HTML) eller 401 JSON.
func respondUnauthorized(w http.ResponseWriter, r *http.Request, reason string) {
	accept := r.Header.Get("Accept")
	if strings.Contains(accept, "application/json") {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":  "unauthorized",
			"reason": reason,
		})
		return
	}
	// HTML-request: redirect til innloggingssiden.
	http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
}
