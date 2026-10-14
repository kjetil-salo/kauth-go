// Package i18n holder oversettelsene for de bruker-vendte login-sidene og
// magic-link-e-posten. Bevisst uten avhengigheter utover stdlib:
// Accept-Language-parsing er ~40 linjer, og det er billigere enn å dra
// golang.org/x/text inn i en binær som skal være liten og CGO-fri.
package i18n

import (
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// Fallback brukes når nettleseren ikke ber om et språk vi har.
const Fallback = "en"

// Strings er alle oversatte tekster for én locale.
//
// Flat struct framfor map[string]string er et bevisst valg: en skrivefeil i
// en template ({{.T.Feilnavn}}) gir render-feil, mens et map-oppslag ville
// gitt en stille tom streng i prod.
type Strings struct {
	// Felles for begge sidene
	SignIn              string
	EmailPlaceholder    string
	PasswordPlaceholder string
	Or                  string

	// login.html
	ContinueWithGoogle    string
	ContinueWithMicrosoft string
	SignInWithEmailLink   string

	// magic-login.html
	MagicPageTitle  string
	MagicSubmit     string
	MagicSending    string
	MagicCheckInbox string
	// MagicSentToBefore og MagicSentToAfter omslutter e-postadressen som
	// JS setter inn i <span id="confirm-email">. Delt i to fordi tysk
	// plasserer verbet etter objektet: "… an <e-post> gesendt."
	MagicSentToBefore string
	MagicSentToAfter  string
	MagicValidMinutes string
	BackToSignIn      string

	// magic-confirm.html: bekreftelsessiden på GET /magic-login/{token}.
	// MagicConfirmBlocked vises ved 403 når POST-en ikke kom fra vår egen side.
	MagicConfirmTitle   string
	MagicConfirmButton  string
	MagicConfirmHint    string
	MagicConfirmBlocked string

	// Feilkoder fra ?error=
	ErrAccessDenied    string
	ErrInvalidRedirect string
	ErrExpiredLink     string
	ErrTooManyRequests string
	ErrNoAccount       string
	// ErrLoginFailed vises for login_failed og for alle ukjente ?error=-verdier.
	ErrLoginFailed string
	// ErrInternal vises ved serverfeil. Bevisst generisk — den spesifikke
	// årsaken hører i loggen, ikke på skjermen til noen som ikke kan bruke den.
	ErrInternal string

	// Magic-link-e-post. MailBody har nøyaktig én {link}-placeholder.
	MailSubject string
	MailBody    string
}

// Get returnerer katalogen for locale, eller Fallback-katalogen ved ukjent
// locale. Kallere trenger derfor ikke sjekke om locale er støttet.
func Get(locale string) Strings {
	if s, ok := catalog[locale]; ok {
		return s
	}
	return catalog[Fallback]
}

// supported er locale-kodene vi har oversettelser for, i den rekkefølgen
// språkvelgeren skal vise dem.
var supported = []string{"nb", "en", "de"}

// normalize gjør en BCP47-tag om til en av våre locale-koder, eller "" hvis
// vi ikke har språket. Norsk sendes som nb, nn eller no avhengig av nettleser
// og operativsystem, så alle tre mappes til nb.
func normalize(tag string) string {
	tag = strings.ToLower(strings.TrimSpace(tag))
	if i := strings.IndexAny(tag, "-_"); i >= 0 {
		tag = tag[:i]
	}
	switch tag {
	case "nb", "nn", "no":
		return "nb"
	case "en":
		return "en"
	case "de":
		return "de"
	}
	return ""
}

// Resolve velger locale. En eksplisitt lang-param vinner over nettleserens
// preferanse, men en ustøttet lang-param avbryter ikke kjeden — den faller
// videre til Accept-Language framfor å tvinge fallback.
func Resolve(langParam, acceptLanguage string) string {
	if loc := normalize(langParam); loc != "" {
		return loc
	}
	if loc := fromAcceptLanguage(acceptLanguage); loc != "" {
		return loc
	}
	return Fallback
}

// FromRequest er wrapperen handlerne bruker.
func FromRequest(r *http.Request) string {
	return Resolve(r.URL.Query().Get("lang"), r.Header.Get("Accept-Language"))
}

// fromAcceptLanguage plukker det høyest vektede språket vi støtter, eller ""
// hvis ingen av alternativene finnes i katalogen.
func fromAcceptLanguage(header string) string {
	type candidate struct {
		locale string
		weight float64
	}
	var candidates []candidate

	for _, part := range strings.Split(header, ",") {
		fields := strings.Split(part, ";")
		locale := normalize(fields[0])
		if locale == "" {
			continue
		}
		weight := 1.0
		for _, f := range fields[1:] {
			f = strings.TrimSpace(f)
			if !strings.HasPrefix(f, "q=") {
				continue
			}
			parsed, err := strconv.ParseFloat(f[2:], 64)
			if err != nil {
				// Ugyldig q diskvalifiserer alternativet framfor å gi det
				// full vekt — en klient som sender søppel skal ikke kunne
				// overstyre et velformet alternativ lenger ned i listen.
				weight = 0
				break
			}
			weight = parsed
		}
		if weight > 0 {
			candidates = append(candidates, candidate{locale, weight})
		}
	}

	if len(candidates) == 0 {
		return ""
	}
	// Stabil sortering, så lik q beholder rekkefølgen klienten sendte.
	sort.SliceStable(candidates, func(i, j int) bool {
		return candidates[i].weight > candidates[j].weight
	})
	return candidates[0].locale
}

// Link er ett alternativ i språkvelgeren på login-sidene.
type Link struct {
	Code   string // "nb" — brukes som lang- og hreflang-attributt
	Label  string // "NO" — teksten som vises
	Name   string // "Norsk" — title/aria-label for skjermlesere
	Href   string // path + query med lang satt
	Active bool
}

// display holder visningsnavnene. Hvert språk skriver sitt eget navn på sitt
// eget språk — en tysk bruker leter etter "Deutsch", ikke "German".
var display = map[string]struct{ Label, Name string }{
	"nb": {"NO", "Norsk"},
	"en": {"EN", "English"},
	"de": {"DE", "Deutsch"},
}

// Links bygger språkvelgeren for gjeldende URL. Href-ene er path-relative så
// host aldri havner i markup, og eksisterende query-params (service,
// redirect_uri) overlever språkbyttet.
func Links(active string, u *url.URL) []Link {
	out := make([]Link, 0, len(supported))
	for _, code := range supported {
		q := u.Query()
		q.Set("lang", code)
		out = append(out, Link{
			Code:   code,
			Label:  display[code].Label,
			Name:   display[code].Name,
			Href:   u.Path + "?" + q.Encode(),
			Active: code == active,
		})
	}
	return out
}
