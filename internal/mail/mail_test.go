package mail

import (
	"bufio"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/i18n"
)

// buildMagicBody er den rene tekst-byggingen SendMagicLink gjør. Testet
// direkte fordi SendMagicLink ellers krever en SMTP-server.
func TestBuildMagicBody_ReplacesLink(t *testing.T) {
	link := "https://auth.spekto.live/magic-login/abc123?service=spekto"

	for _, locale := range []string{"en", "nb", "de"} {
		body := buildMagicBody(i18n.Get(locale), link)
		assert.Contains(t, body, link, "locale %s: lenken mangler i brødteksten", locale)
		assert.NotContains(t, body, "{link}", "locale %s: placeholder ikke erstattet", locale)
	}
}

func TestBuildMagicBody_LocalisedText(t *testing.T) {
	link := "https://example.test/x"
	assert.Contains(t, buildMagicBody(i18n.Get("de"), link), "Hallo!")
	assert.Contains(t, buildMagicBody(i18n.Get("nb"), link), "Hei!")
	assert.Contains(t, buildMagicBody(i18n.Get("en"), link), "Hello!")
}

func TestBuildMessage_UsesLocalisedSubject(t *testing.T) {
	msg := buildMessage("from@example.test", "Test", "to@example.test",
		i18n.Get("de").MailSubject, "brødtekst", "<p>brødtekst</p>")
	require.True(t, strings.Contains(msg, "Subject: Ihr Anmeldelink"),
		"emnet skal være tysk, fikk:\n%s", msg)
}

// BACKLOG F21: en tjeneste med satt email_from_address men uten konfigurert
// KAUTH_BREVO_API_KEY skal feile tydelig i stedet for å stille falle tilbake
// til den globale SMTP-avsenderen (ville gjenskapt akkurat merkevare-mismatchen
// F21 løser). Ingen SMTP-mock her — feilen skal komme FØR noe forsøk på å sende.
func TestSendMagicLink_FromAddressWithoutBrevoKey_Errors(t *testing.T) {
	svc := New(config.Config{SMTPMock: false, BrevoAPIKey: ""})
	err := svc.SendMagicLink("bruker@example.test", "Spekto", "https://x.test/y", "nb", "noreply@spekto.live")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KAUTH_BREVO_API_KEY")
}

// Tom fromAddress skal ikke kreve Brevo-nøkkel i det hele tatt — dette er
// standardveien for tjenester uten egen avsenderadresse (uendret oppførsel).
func TestSendMagicLink_MockMode_IgnoresMissingBrevoKeyWhenNoFromAddress(t *testing.T) {
	svc := New(config.Config{SMTPMock: true, BrevoAPIKey: ""})
	err := svc.SendMagicLink("bruker@example.test", "Klarsyn", "https://x.test/y", "nb", "")
	require.NoError(t, err)
}

// kortTidsgrenser gjør timeout-testene raske og gjenoppretter pakkevariablene.
func kortTidsgrenser(t *testing.T, dial, session time.Duration) {
	t.Helper()
	d, s := dialTimeout, sessionTimeout
	dialTimeout, sessionTimeout = dial, session
	t.Cleanup(func() { dialTimeout, sessionTimeout = d, s })
}

// sendMedVakt kjører sendingen i en goroutine slik at en mutant som fjerner
// tidsgrensen gir rask rød test i stedet for hang.
func sendMedVakt(t *testing.T, vent time.Duration, f func() error) (error, time.Duration) {
	t.Helper()
	start := time.Now()
	ch := make(chan error, 1)
	go func() { ch <- f() }()
	select {
	case err := <-ch:
		return err, time.Since(start)
	case <-time.After(vent):
		t.Fatal("sendingen hang forbi tidsgrensen")
		return nil, 0
	}
}

func assertTimeout(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	var ne net.Error
	require.True(t, errors.As(err, &ne), "forventet net.Error, fikk %v", err)
	assert.True(t, ne.Timeout(), "forventet timeout, fikk %v", err)
}

type fakeOpts struct {
	auth     bool   // annonser AUTH PLAIN og svar 235
	silentAt string // "", "BANNER", "MAIL" eller "DATA": her slutter serveren å svare
}

type fakeSrv struct {
	addr string
	cmds chan string // kommandoer mottatt, i rekkefølge
	data chan string // meldingsinnhold etter DATA
}

// startFake starter en minimal SMTP-server for én tilkobling. Den stille
// varianten holder forbindelsen åpen til testen er ferdig, så klientens
// tidsgrense er det eneste som kan avslutte sendingen.
func startFake(t *testing.T, o fakeOpts) *fakeSrv {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	f := &fakeSrv{addr: ln.Addr().String(), cmds: make(chan string, 32), data: make(chan string, 1)}
	done := make(chan struct{})
	t.Cleanup(func() { close(done); ln.Close() })

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		serve := func() {
			if o.silentAt == "BANNER" {
				<-done
				return
			}
			r := bufio.NewReader(c)
			fmt.Fprint(c, "220 fake ESMTP\r\n")
			var data strings.Builder
			inData := false
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				if inData {
					if line == ".\r\n" {
						inData = false
						f.data <- data.String()
						if o.silentAt == "DATA" {
							<-done
							return
						}
						fmt.Fprint(c, "250 ok\r\n")
						continue
					}
					data.WriteString(line)
					continue
				}
				cmd := strings.ToUpper(strings.TrimSpace(line))
				f.cmds <- cmd
				switch {
				case strings.HasPrefix(cmd, "EHLO"):
					if o.auth {
						fmt.Fprint(c, "250-fake\r\n250 AUTH PLAIN\r\n")
					} else {
						fmt.Fprint(c, "250 fake\r\n")
					}
				case strings.HasPrefix(cmd, "AUTH PLAIN"):
					fmt.Fprint(c, "235 ok\r\n")
				case strings.HasPrefix(cmd, "MAIL"):
					if o.silentAt == "MAIL" {
						<-done
						return
					}
					fmt.Fprint(c, "250 ok\r\n")
				case strings.HasPrefix(cmd, "RCPT"):
					fmt.Fprint(c, "250 ok\r\n")
				case cmd == "DATA":
					inData = true
					fmt.Fprint(c, "354 go\r\n")
				case cmd == "QUIT":
					fmt.Fprint(c, "221 bye\r\n")
					return
				default:
					fmt.Fprint(c, "500 ?\r\n")
				}
			}
		}
		serve()
		c.Close()
	}()
	return f
}

func (f *fakeSrv) sett() []string {
	var out []string
	for {
		select {
		case c := <-f.cmds:
			out = append(out, c)
		default:
			return out
		}
	}
}

func TestSMTP_DialTimeout(t *testing.T) {
	kortTidsgrenser(t, 300*time.Millisecond, 2*time.Second)
	err, d := sendMedVakt(t, 3*time.Second, func() error {
		return sendSMTP("10.255.255.1:25", "localhost", nil, "a@x.test", "b@x.test", "m", false)
	})
	require.Error(t, err)
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Skipf("miljøet gir ikke timeout (%v); testen beviser ingenting her", err)
	}
	assert.Contains(t, err.Error(), "smtp dial")
	assert.Less(t, d, 1300*time.Millisecond)
}

func TestSMTP_SessionDeadline(t *testing.T) {
	for _, at := range []string{"BANNER", "MAIL", "DATA"} {
		for _, requireTLS := range []bool{false, true} {
			if requireTLS && at != "BANNER" {
				continue // uten STARTTLS i EHLO stopper requireTLS før MAIL
			}
			t.Run(fmt.Sprintf("%s/tls=%v", at, requireTLS), func(t *testing.T) {
				f := startFake(t, fakeOpts{silentAt: at})
				kortTidsgrenser(t, time.Second, 300*time.Millisecond)
				err, d := sendMedVakt(t, 300*time.Millisecond+2*time.Second, func() error {
					return sendSMTP(f.addr, "localhost", nil, "a@x.test", "b@x.test", "m", requireTLS)
				})
				assertTimeout(t, err)
				assert.Less(t, d, 1300*time.Millisecond)
			})
		}
	}
}

func TestSMTP_RequireTLS(t *testing.T) {
	kortTidsgrenser(t, time.Second, 2*time.Second)

	f := startFake(t, fakeOpts{})
	err, _ := sendMedVakt(t, 4*time.Second, func() error {
		return sendSMTP(f.addr, "localhost", nil, "a@x.test", "b@x.test", "m", true)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "starttls")
	for _, c := range f.sett() {
		assert.False(t, strings.HasPrefix(c, "MAIL"), "MAIL skal aldri sendes uten TLS")
	}

	f2 := startFake(t, fakeOpts{})
	err, _ = sendMedVakt(t, 4*time.Second, func() error {
		return sendSMTP(f2.addr, "localhost", nil, "a@x.test", "b@x.test", "m", false)
	})
	require.NoError(t, err)
}

func TestSMTP_Auth(t *testing.T) {
	kortTidsgrenser(t, time.Second, 2*time.Second)
	auth := smtp.PlainAuth("", "u", "p", "localhost")

	f := startFake(t, fakeOpts{auth: true})
	err, _ := sendMedVakt(t, 4*time.Second, func() error {
		return sendSMTP(f.addr, "localhost", auth, "a@x.test", "b@x.test", "m", false)
	})
	require.NoError(t, err)
	var sett []string
	sett = f.sett()
	var harAuth bool
	for _, c := range sett {
		harAuth = harAuth || strings.HasPrefix(c, "AUTH PLAIN")
	}
	assert.True(t, harAuth, "AUTH PLAIN skulle vært sendt: %v", sett)

	f2 := startFake(t, fakeOpts{})
	err, _ = sendMedVakt(t, 4*time.Second, func() error {
		return sendSMTP(f2.addr, "localhost", auth, "a@x.test", "b@x.test", "m", false)
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "støtter ikke AUTH")
}

func TestSMTP_HappyPathPlain(t *testing.T) {
	f := startFake(t, fakeOpts{})
	kortTidsgrenser(t, time.Second, 2*time.Second)
	msg := buildMessage("a@x.test", "A", "b@x.test", "Emne", "Hei", "<p>Hei</p>")
	err, _ := sendMedVakt(t, 4*time.Second, func() error {
		return sendSMTP(f.addr, "localhost", nil, "a@x.test", "b@x.test", msg, false)
	})
	require.NoError(t, err)
	select {
	case d := <-f.data:
		assert.Contains(t, d, "Subject: Emne")
	case <-time.After(time.Second):
		t.Fatal("serveren fikk aldri meldingen")
	}
}

func TestBuildLinkInviteBody_AllLocales(t *testing.T) {
	link := "https://auth.example.test/link/abc"
	for _, locale := range []string{"en", "nb", "de"} {
		body := buildLinkInviteBody(i18n.Get(locale), link, "Acme")
		assert.Contains(t, body, link, locale)
		assert.Contains(t, body, "Acme", locale)
		assert.NotContains(t, body, "{link}", locale)
		assert.NotContains(t, body, "{provider}", locale)
	}
}

func TestSendLinkInvite_FromAddressWithoutBrevoKey_Errors(t *testing.T) {
	svc := New(config.Config{SMTPMock: false})
	err := svc.SendLinkInvite("bruker@example.test", "Spekto", "https://x.test/link/t", "Acme", "nb", "noreply@spekto.live")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KAUTH_BREVO_API_KEY")
	assert.NotContains(t, err.Error(), "/link/t")
}

func TestSendLinkInvite_MockModeSucceeds(t *testing.T) {
	require.NoError(t, New(config.Config{SMTPMock: true}).SendLinkInvite("a@b.test", "N", "https://x.test/link/t", "Acme", "nb", ""))
}

func TestSendLinkConfirmation_FromAddressWithoutBrevoKey_Errors(t *testing.T) {
	err := New(config.Config{SMTPMock: false}).SendLinkConfirmation("bruker@example.test", "Spekto", "Acme", "nb", "noreply@spekto.live")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KAUTH_BREVO_API_KEY")
}

func TestSendLinkConfirmation_MockModeSucceeds(t *testing.T) {
	require.NoError(t, New(config.Config{SMTPMock: true}).SendLinkConfirmation("a@b.test", "N", "Acme", "nb", ""))
}

// Begge delene må være med, og HTML sist: i multipart/alternative er den
// siste delen den klienten foretrekker å vise.
func TestBuildMessage_MultipartAlternativeWithHTMLLast(t *testing.T) {
	msg := buildMessage("from@example.test", "Test", "to@example.test",
		"emne", "ren tekst", `<p><a href="https://x.test/y">Logg inn</a></p>`)

	assert.Contains(t, msg, "Content-Type: multipart/alternative; boundary=")
	assert.Contains(t, msg, "Content-Type: text/plain; charset=UTF-8")
	assert.Contains(t, msg, "Content-Type: text/html; charset=UTF-8")
	assert.Contains(t, msg, "Content-Transfer-Encoding: quoted-printable")
	assert.Less(t, strings.Index(msg, "text/plain"), strings.Index(msg, "text/html"),
		"HTML-delen skal komme sist")

	dec, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(
		msg[strings.Index(msg, "ren tekst"):])))
	require.NoError(t, err)
	assert.Contains(t, string(dec), "ren tekst")
}

// Selve feilen dette retter: lenken må være en ekte <a href>, ikke bare
// tekst som e-postklienten kanskje gjør trykkbar.
func TestBuildHTMLBody_MagicLinkHasClickableAnchorAndVisibleURL(t *testing.T) {
	link := "https://auth.example.test/magic-login/abc123?service=x&lang=nb"

	for _, locale := range []string{"en", "nb", "de"} {
		tr := i18n.Get(locale)
		got := buildHTMLBody(buildMagicBody(tr, link), link, tr.SignIn, tr.MailLinkFallback)

		// & må escapes i href, ellers er lenken ugyldig HTML.
		assert.Contains(t, got, `<a href="https://auth.example.test/magic-login/abc123?service=x&amp;lang=nb"`,
			"locale %s: knappen mangler href til lenken", locale)
		assert.Contains(t, got, html.EscapeString(tr.SignIn), "locale %s: knappetekst mangler", locale)
		assert.Contains(t, got, html.EscapeString(tr.MailLinkFallback),
			"locale %s: kopier-lenken-teksten mangler", locale)
		assert.NotContains(t, got, "{link}", "locale %s: placeholder ikke erstattet", locale)
		// Tre forekomster: knappens href, og href + synlig tekst på
		// kopier-lenken under den.
		assert.Equal(t, 3, strings.Count(got, "magic-login/abc123"),
			"locale %s: lenken skal både være knapp og synlig tekst", locale)
	}
}

// Koblingsinvitasjonen (016) skal ha samme knapp, merket med
// leverandørnavnet fra LinkConfirmButton.
func TestBuildHTMLBody_LinkInviteUsesProviderButton(t *testing.T) {
	tr := i18n.Get("nb")
	link := "https://auth.example.test/link/abc"
	body := buildLinkInviteBody(tr, link, "Google")
	got := buildHTMLBody(body, link, strings.ReplaceAll(tr.LinkConfirmButton, "{provider}", "Google"), tr.MailLinkFallback)

	assert.Contains(t, got, `<a href="https://auth.example.test/link/abc"`)
	assert.Contains(t, got, "Fortsett til Google")
	assert.NotContains(t, got, "{provider}")
}

// Kvitteringsmailen har ingen lenke — da skal det heller ikke bli noen
// knapp eller tom kopier-lenke-seksjon.
func TestBuildHTMLBody_NoLinkGivesNoButton(t *testing.T) {
	tr := i18n.Get("nb")
	body := strings.ReplaceAll(tr.LinkMailBody, "{provider}", "Google")
	got := buildHTMLBody(body, "", "", "")

	assert.NotContains(t, got, "<a href")
	assert.Contains(t, got, "<p>Hei!</p>")
	assert.Contains(t, got, "Google")
}

// Brødteksten skal ikke kunne injisere markup i HTML-utgaven.
func TestBuildHTMLBody_EscapesBodyText(t *testing.T) {
	got := buildHTMLBody("Hei <script>alert(1)</script>\n\nhttps://x.test/y\n",
		"https://x.test/y", "Logg inn", "Kopier:")
	assert.NotContains(t, got, "<script>")
	assert.Contains(t, got, "&lt;script&gt;")
}
