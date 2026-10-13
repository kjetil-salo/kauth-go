package auth

import (
	"log/slog"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
)

// UseGlobal monterer den globale middleware-kjeden. Egen funksjon slik at
// main.go og testene bruker nøyaktig samme kjede og rekkefølge.
func UseGlobal(r *chi.Mux, logger *slog.Logger) {
	// Først, utenfor Recoverer, slik at også 500-svar får sikkerhetsheadere.
	r.Use(SecurityHeaders)
	r.Use(chimiddleware.Recoverer)
	r.Use(ClientIPMiddleware)
	// Etter ClientIPMiddleware (logger bruker ClientIP) og innenfor Recoverer
	// (panikk gir fortsatt logglinje).
	r.Use(RequestLogger(logger))
}
