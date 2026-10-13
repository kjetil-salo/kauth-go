package auth

import "net/http"

// SecurityHeaders setter vernheadere før handleren kjører, slik at redirects,
// JSON, feilsvar og statiske filer alle får dem. Monteres utenfor Recoverer så
// også 500-svar dekkes.
//
// CSP er bevisst bare frame-ancestors: login-sidene bruker inline CSS/JS og
// Google Fonts, så script-src/default-src ville brutt dem. HSTS har ikke
// includeSubDomains/preload fordi andre underdomener ikke er vår å binde.
// En handler som selv kaller Header().Set på en av disse overstyrer verdien.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", "frame-ancestors 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		next.ServeHTTP(w, r)
	})
}
