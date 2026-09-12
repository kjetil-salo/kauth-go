package auth

import (
	"fmt"
	"html/template"
	"net/http"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/service"
)

// LoginPageData er template-data for login.html og magic-login.html.
type LoginPageData struct {
	Service     *gen.Service
	LogoHTML    template.HTML // konvertert fra Service.LogoHtml — rå HTML, ikke escaped
	RedirectURI string
	Error       string
	// BodyBgCSS er ferdig-beregnet CSS background-verdi for body-elementet.
	// Brukes i <style>-blokken der Go html/template blokkerer dynamisk url()-konstruksjon.
	// Trust boundary: verdien er sammensatt fra DB-felter (BgCss, BgImage) med fast /static/-prefix.
	BodyBgCSS template.CSS
	// BeforeBgCSS er ferdig-beregnet CSS background-verdi for body::before (mørkt tema).
	BeforeBgCSS template.CSS
	// Locale er valgt språk (nb/en/de) — brukes som lang-attributt og for å
	// bære språket videre i lenker ut av siden.
	Locale string
	// T er de oversatte tekstene for Locale.
	T i18n.Strings
	// Languages er alternativene i språkvelgeren.
	Languages []i18n.Link
	// Tagline er tjenestens budskap på valgt språk, med services.tagline som
	// fallback for tjenester som ennå ikke er oversatt.
	Tagline string
}

// buildBgCSS beregner CSS background-verdier for BodyBgCSS og BeforeBgCSS.
// bgImage er DB-verdi som "/fjord-dawn.jpg" (uten /static/-prefix — prefix legges til her).
// bgCss er DB-verdi som "#09090B" (brukes bare ved mørkt tema).
func buildBgCSS(theme string, bgImage *string, bgCss *string) (bodyCss, beforeCss template.CSS) {
	if theme == "dark" {
		if bgCss != nil && *bgCss != "" {
			bodyCss = template.CSS(*bgCss)
		} else {
			bodyCss = "#09090B"
		}
		if bgImage != nil && *bgImage != "" {
			beforeCss = template.CSS(fmt.Sprintf("url('/static%s') center/cover no-repeat", *bgImage))
		}
	} else {
		if bgImage != nil && *bgImage != "" {
			bodyCss = template.CSS(fmt.Sprintf("url('/static%s') center/cover no-repeat fixed", *bgImage))
		} else if bgCss != nil && *bgCss != "" {
			// Bakoverkompatibel utvidelse: lyst tema uten bg_image kan nå bruke
			// en flat farge (bg_css) i stedet for default-bildet under.
			bodyCss = template.CSS(*bgCss)
		} else {
			bodyCss = template.CSS(fmt.Sprintf("url('/static%s') center/cover no-repeat fixed", "/fjord-dawn.jpg"))
		}
	}
	return
}

// LoginHandler rendrer login-siden.
type LoginHandler struct {
	Registry  *service.Registry
	Templates *template.Template
}

// ServeLogin håndterer GET /login.
// Resolver tjeneste fra ?service=ID-parameter eller host-header.
func (h *LoginHandler) ServeLogin(w http.ResponseWriter, r *http.Request) {
	serviceID := r.URL.Query().Get("service")
	redirectURI := r.URL.Query().Get("redirect_uri")

	svc := h.Registry.ResolveOrDefault(r.Host, serviceID, redirectURI)
	if svc == nil {
		http.Error(w, "ukjent tjeneste", http.StatusBadRequest)
		return
	}

	var logoHTML template.HTML
	if svc.LogoHtml != nil {
		// Stored HTML rendered raw. Trust boundary: only admins with the konge role
		// can set svc.LogoHtml (see admin/services.go). Compromised admin = stored XSS
		// on every login page for that service. Sanitisation is intentionally not
		// applied here; admin-side validation is the proper control.
		logoHTML = template.HTML(*svc.LogoHtml) // #nosec G203
	}

	locale := i18n.FromRequest(r)

	tagline := i18n.Tagline(svc.ID, locale)
	if tagline == "" && svc.Tagline != nil {
		// Tjenesten er ikke oversatt ennå — vis DB-verdien framfor ingenting.
		tagline = *svc.Tagline
	}

	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	data := LoginPageData{
		Service:     svc,
		LogoHTML:    logoHTML,
		RedirectURI: redirectURI,
		Error:       r.URL.Query().Get("error"),
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, r.URL),
		Tagline:     tagline,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Responsen varierer med Accept-Language (via i18n.FromRequest) — caches må ta høyde for dette.
	w.Header().Set("Vary", "Accept-Language")
	if err := h.Templates.ExecuteTemplate(w, "login.html", data); err != nil {
		http.Error(w, "mal-feil", http.StatusInternalServerError)
	}
}

// ServeLegacyLogin håndterer GET /login.html og /login-pov.html → 301 /login.
func ServeLegacyLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if q := r.URL.RawQuery; q != "" {
		target += "?" + q
	}
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}
