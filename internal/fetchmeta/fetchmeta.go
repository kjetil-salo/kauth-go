// Package fetchmeta vurderer hvor en nettleserforespørsel kommer fra, ut fra
// Fetch Metadata-headerne (Sec-Fetch-Site) og Origin.
package fetchmeta

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
)

// SameOrigin sier om en tilstandsendrende forespørsel (POST) er utløst fra
// kauths egen origin. Den er fail-closed (PB2): når verken Sec-Fetch-Site eller
// en Origin vi kjenner igjen er til stede, avvises forespørselen. Alle moderne
// nettlesere sender minst én av dem på en POST, og en bekreftelse som bare
// gjøres på ekte brukerhandling er verdt at en sjelden klient må åpne lenken på nytt.
func SameOrigin(r *http.Request) bool {
	site := r.Header.Get("Sec-Fetch-Site")
	origin := r.Header.Get("Origin")

	ok := false
	switch {
	case site != "":
		// Når nettleseren oppgir Sec-Fetch-Site, er den autoritativ. same-site,
		// cross-site og none godtas ikke, selv om Origin skulle se riktig ut.
		ok = site == "same-origin"
	case origin != "":
		ok = origin == "https://"+r.Host || (insecure() && origin == "http://"+r.Host)
	}
	if !ok {
		// Bare rutemønsteret logges: stien kan bære et engangstoken (K26).
		route := ""
		if rc := chi.RouteContext(r.Context()); rc != nil {
			route = rc.RoutePattern()
		}
		slog.Warn("fetchmeta: avviste forespørsel utenfra egen origin",
			"route", route, "sec_fetch_site", site, "origin", origin)
	}
	return ok
}

// Middleware krever samme origin på alle ikke-sikre metoder. GET, HEAD og
// OPTIONS slippes gjennom uendret (K12). Avvisning gir fast tekst uten at next
// kalles, og uten audit: en forfalsket forespørsel skal ikke kunne fylle loggen.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		if !SameOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// LogoutAllowed avgjør om GET /logout kan revokere og slette cookies. Cross-site
// underressurser (img, fetch) og iframe skal ikke kunne logge brukeren ut
// stille, men synlig toppnivå-navigasjon er en bevisst handling (PB3).
// Manglende Sec-Fetch-Site (eldre klient, curl) behandles som navigasjon.
func LogoutAllowed(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "same-site", "none":
		return true
	case "cross-site":
		dest := r.Header.Get("Sec-Fetch-Dest")
		return r.Header.Get("Sec-Fetch-Mode") == "navigate" && (dest == "" || dest == "document")
	}
	// Ukjent verdi: fail-closed.
	return false
}

// insecure er lokal utvikling og eval: http godtas bare der, med samme bryter
// som cookie-koden bruker. Bak Cloudflare Tunnel er r.TLS alltid nil, så
// skjemaet kan ikke leses fra forespørselen.
func insecure() bool { return os.Getenv("KAUTH_INSECURE_COOKIES") == "true" }
