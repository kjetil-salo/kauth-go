package admin

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// adminUserLookup er det middlewaren trenger av databasen: admin-JWT-en lever
// opptil admin-TTL, så deaktivering og rolleendring må gjelde med en gang.
type adminUserLookup interface {
	GetActiveUserByEmail(ctx context.Context, email string) (gen.User, error)
}

type actorCtxKey struct{}

// ActorFromContext returnerer admin-e-posten fra DB-raden som middlewaren la i
// konteksten, eller "" utenfor en autentisert admin-request.
func ActorFromContext(ctx context.Context) string {
	actor, _ := ctx.Value(actorCtxKey{}).(string)
	return actor
}

// AdminAuthMiddleware beskytter alle /admin/-ruter unntatt /admin/login og /admin/verify.
// HTML-requester (Accept: text/html eller ingen Accept) → 303 /admin/login.
// JSON-requester (Accept: application/json) → 401 JSON-feil.
func AdminAuthMiddleware(issuer *token.Issuer, users adminUserLookup) func(http.Handler) http.Handler {
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

			// Fail-closed: tokenet alene er ikke nok. Deaktivert eller slettet bruker,
			// fjernet konge-rolle og DB-feil gir alle avvisning.
			user, err := users.GetActiveUserByEmail(r.Context(), claims.Email)
			if err != nil {
				if !errors.Is(err, sql.ErrNoRows) {
					slog.Error("admin: brukeroppslag feilet", "error", err)
				}
				respondUnauthorized(w, r, "unauthorized")
				return
			}
			if !hasRole(user.Roles, "konge") {
				respondUnauthorized(w, r, "unauthorized")
				return
			}

			ctx := context.WithValue(r.Context(), actorCtxKey{}, user.Email)
			next.ServeHTTP(w, r.WithContext(ctx))
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
