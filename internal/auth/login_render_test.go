package auth

import (
	"html/template"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/i18n"
)

// testLoginService har alle fire innloggingsmetoder på, slik at rendringen
// treffer hver gren i templaten og ingen oversatt streng blir stående
// uprøvd bak en {{if}}.
func testLoginService(theme string) *gen.Service {
	tagline := "Test-tjeneste"
	return &gen.Service{
		ID:             "test",
		DisplayName:    "Testify",
		Tagline:        &tagline,
		Domain:         "test.local",
		CallbackUrl:    "https://test.local/callback",
		Theme:          theme,
		AccentColor:    "#2563EB",
		EmailFromName:  "Test",
		AuthGoogle:     1,
		AuthMicrosoft:  1,
		AuthMagicLink:  1,
		AuthPassword:   1,
		JwtCookieName:  "auth_token",
		AccessTokenTtl: "PT15M",
		Active:         1,
	}
}

// testPageData bygger template-data slik ServeLogin gjør det.
func testPageData(t *testing.T, theme, locale, rawURL string) LoginPageData {
	t.Helper()
	u, err := url.Parse(rawURL)
	require.NoError(t, err)

	svc := testLoginService(theme)
	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	return LoginPageData{
		Service:     svc,
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, u),

		PasswordLoginEnabled: true,
	}
}

func renderLogin(t *testing.T, passwordEnabled bool, authPassword int64) string {
	t.Helper()
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)
	data := testPageData(t, "dark", "nb", "/login?service=test")
	data.PasswordLoginEnabled = passwordEnabled
	data.Service.AuthPassword = authPassword
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	return out.String()
}

func TestLoginTemplate_PasswordForm(t *testing.T) {
	assert.NotContains(t, renderLogin(t, false, 1), `type="password"`, "bryter av skjuler skjemaet selv med auth_password=1")
	assert.Contains(t, renderLogin(t, true, 1), `type="password"`)
	assert.NotContains(t, renderLogin(t, true, 0), `type="password"`)
}

// TestLoginTemplate_RendersInAllLocales fanger feltnavn-typo i templaten —
// den ene feilklassen struct-katalogen ikke fanger ved kompilering.
func TestLoginTemplate_RendersInAllLocales(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	want := map[string]string{
		"en": "Continue with Google",
		"nb": "Fortsett med Google",
		"de": "Mit Google fortfahren",
	}

	for _, theme := range []string{"light", "dark"} {
		for _, locale := range []string{"en", "nb", "de"} {
			t.Run(theme+"/"+locale, func(t *testing.T) {
				data := testPageData(t, theme, locale, "/login?service=test")

				var out strings.Builder
				require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))

				html := out.String()
				assert.Contains(t, html, want[locale])
				assert.Contains(t, html, `<html lang="`+locale+`">`)
				// Magic-link-knappen må bære språket videre. Sjekk hele
				// href-en, ikke bare "lang=<locale>" — den strengen finnes
				// i språkvelgeren uansett locale og ville gjort testen blind.
				assert.Contains(t, html, "/magic-login?service=test&amp;lang="+locale)
			})
		}
	}
}

func TestLoginTemplate_ShowsLanguageSwitcher(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))

	html := out.String()
	// Aktivt språk skal rendres som <span class="active">, ikke som lenke —
	// ">DE<" alene matcher begge grenene og tester ingenting.
	assert.Contains(t, html, `<span class="active" lang="de"`)
	assert.Contains(t, html, "Norsk")
	assert.Contains(t, html, "English")
	assert.Contains(t, html, "lang=nb")
	assert.Contains(t, html, "lang=en")
}

func TestLoginTemplate_TranslatesErrorCodes(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	data.Error = "access_denied"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	assert.Contains(t, out.String(), "Zugriff verweigert.")
}

// TestLoginTemplate_TranslatesInvalidRedirect dekker login.html sin
// invalid_redirect-gren, som ellers aldri kjøres av noen test — en skrivefeil
// i .T.ErrInvalidRedirect ville sluppet gjennom kompilator og hele suiten.
func TestLoginTemplate_TranslatesInvalidRedirect(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	data.Error = "invalid_redirect"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	assert.Contains(t, out.String(), "Ungültige Rücksprungadresse")
}

func TestMagicLoginTemplate_RendersInAllLocales(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	wantSubmit := map[string]string{
		"en": "Send sign-in link",
		"nb": "Send innloggingslenke",
		"de": "Anmeldelink senden",
	}
	wantInbox := map[string]string{
		"en": "Check your inbox",
		"nb": "Sjekk innboksen din",
		"de": "Prüfen Sie Ihren E-Mail-Eingang",
	}

	for _, theme := range []string{"light", "dark"} {
		for _, locale := range []string{"en", "nb", "de"} {
			t.Run(theme+"/"+locale, func(t *testing.T) {
				data := testPageData(t, theme, locale, "/magic-login?service=test")

				var out strings.Builder
				require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))

				html := out.String()
				assert.Contains(t, html, wantSubmit[locale])
				assert.Contains(t, html, wantInbox[locale])
				assert.Contains(t, html, `<html lang="`+locale+`">`)
				// "/magic-login?lang=" er identisk i alle locales (det er
				// JS-kildekode, ikke oversatt tekst) — den beviser bare at
				// fetch() bygger URL-en, ikke at riktig språk kom med. Det
				// gjør derimot LANG-verdien: html/template quoter og
				// escaper {{.Locale}} selv, så en håndlagt anførselstegn i
				// templaten ville gitt "'de'" i stedet for "de" her.
				assert.Contains(t, html, "/magic-login?lang=")
				assert.Contains(t, html, `var LANG = "`+locale+`";`)
				if locale == "de" {
					// Språkvelgeren i magic-login.html hadde ingen dekning —
					// templaten kunne vært slettet uten at noen test slo ut.
					assert.Contains(t, html, `<span class="active" lang="de"`)
				}
			})
		}
	}
}

// Tysk ordstilling krever at setningen deles rundt e-postadressen:
// "… an <e-post> gesendet." Verbet havner etter objektet.
func TestMagicLoginTemplate_GermanWordOrder(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/magic-login?service=test")
	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))

	html := out.String()
	before := strings.Index(html, "Wir haben einen Anmeldelink an")
	span := strings.Index(html, `id="confirm-email"`)
	after := strings.Index(html, "gesendet.")
	require.NotEqual(t, -1, before)
	require.NotEqual(t, -1, span)
	require.NotEqual(t, -1, after)
	assert.Less(t, before, span, "prefiks skal komme før e-postadressen")
	assert.Less(t, span, after, "verbet skal komme etter e-postadressen")
}

func TestMagicLoginTemplate_TranslatesErrorCodes(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "en", "/magic-login?service=test")
	data.Error = "rate"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))
	assert.Contains(t, out.String(), "Too many requests.")
}

// TestMagicLoginTemplate_TranslatesInvalidRedirect dekker magic-login.html
// sin invalid_redirect-gren. ShowForm sender ?error= rett gjennom til
// templaten (magic.go), så grenen er nåbar fra en vilkårlig URL — en
// skrivefeil i .T.ErrInvalidRedirect ville sluppet gjennom kompilator og
// hele suiten uten denne testen.
func TestMagicLoginTemplate_TranslatesInvalidRedirect(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/magic-login?service=test")
	data.Error = "invalid_redirect"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))
	assert.Contains(t, out.String(), "Ungültige Rücksprungadresse")
}

// TestMagicLoginTemplate_TranslatesExpiredError dekker magic-login.html sin
// expired-gren, som TranslatesErrorCodes over ikke rører (den tester "rate").
func TestMagicLoginTemplate_TranslatesExpiredError(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/magic-login?service=test")
	data.Error = "expired"

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))
	assert.Contains(t, out.String(), "Der Link ist abgelaufen oder wurde bereits verwendet.")
}

// TestLoginTemplate_TranslatesTagline dekker den ene bruker-vendte strengen som
// ikke ligger i Strings-structen: tjenestens tagline, som slås opp per
// tjeneste-ID. Templaten bruker {{.Tagline}}, ikke {{.Service.Tagline}} — bytter
// noen tilbake til DB-feltet, viser siden norsk tekst på tysk igjen.
func TestLoginTemplate_TranslatesTagline(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	want := map[string]string{
		"nb": "Logg inn for å administrere dine arrangementer",
		"en": "Sign in to manage your events",
		"de": "Melden Sie sich an, um Ihre Events zu verwalten",
	}

	for locale, expected := range want {
		t.Run(locale, func(t *testing.T) {
			data := testPageData(t, "light", locale, "/login?service=spekto")
			data.Tagline = i18n.Tagline("spekto", locale)

			var out strings.Builder
			require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
			assert.Contains(t, out.String(), expected)
		})
	}
}

// En tjeneste uten katalog-oppføring faller tilbake til DB-taglinen framfor å
// vise ingenting.
func TestLoginTemplate_TaglineFallsBackToDatabase(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	data := testPageData(t, "light", "de", "/login?service=test")
	data.Tagline = "Test-tjeneste" // som ServeLogin setter fra svc.Tagline

	var out strings.Builder
	require.NoError(t, tmpl.ExecuteTemplate(&out, "login.html", data))
	assert.Contains(t, out.String(), "Test-tjeneste")
}

// TestMagicLoginTemplate_TranslatesNoAccount dekker no_account-grenen, som
// Redeem redirecter til når tjenesten ikke har auto-registrering. Uten
// denne kjøres grenen aldri av suiten, og en skrivefeil i .T.ErrNoAccount ville
// gitt en stille trunkert side (magic.go forkaster render-feilen).
func TestMagicLoginTemplate_TranslatesNoAccount(t *testing.T) {
	tmpl, err := template.ParseGlob("../../templates/*.html")
	require.NoError(t, err)

	want := map[string]string{
		"nb": "Ingen konto funnet for denne e-postadressen.",
		"en": "No account found for this email address.",
		"de": "Für diese E-Mail-Adresse wurde kein Konto gefunden.",
	}

	for locale, expected := range want {
		t.Run(locale, func(t *testing.T) {
			data := testPageData(t, "light", locale, "/magic-login?service=test")
			data.Error = "no_account"

			var out strings.Builder
			require.NoError(t, tmpl.ExecuteTemplate(&out, "magic-login.html", data))
			assert.Contains(t, out.String(), expected)
		})
	}
}
