package auth

import (
	"context"
	"net/http"
	"strings"

	chimiddleware "github.com/go-chi/chi/v5/middleware"

	"github.com/zral/kauth-go/internal/audit"
)

type contextKey string

const clientIPKey contextKey = "clientIP"

// ClientIPMiddleware henter klient-IP og legger den i context.
// Leser CF-Connecting-IP → X-Forwarded-For → RemoteAddr via audit.ExtractIP.
func ClientIPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := audit.ExtractIP(r.Header.Get("CF-Connecting-IP"), r.Header.Get("X-Forwarded-For"), r.RemoteAddr)
		ctx := context.WithValue(r.Context(), clientIPKey, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ClientIP leser klient-IP fra context (satt av ClientIPMiddleware).
// Returnerer tom streng dersom middleware ikke kjøres — akseptabelt frem til Task 10.
func ClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(clientIPKey).(string); ok {
		return ip
	}
	return ""
}

// CORSMiddleware setter Access-Control-Allow-* headere når origin matcher allowlisten.
// Tom origins-liste betyr ingen CORS-headere — ingen wildcard-fallback.
// Wildcard støttes ikke (config.Load avviser "*"); en origin må stå eksakt i listen.
func CORSMiddleware(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			if OriginAllowed(origins, origin) {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Vary", "Origin")
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Logger og Recoverer er re-eksporter av chi/middleware for enklere import i main.
var Logger = chimiddleware.Logger
var Recoverer = chimiddleware.Recoverer

// OriginAllowed sjekker en Origin-header mot allowlisten med eksakt match.
// "null" og tom streng godtas aldri, selv om noen skulle ha lagt dem i listen.
func OriginAllowed(origins []string, origin string) bool {
	if origin == "" || origin == "null" {
		return false
	}
	for _, o := range origins {
		if strings.TrimSpace(o) == origin {
			return true
		}
	}
	return false
}
