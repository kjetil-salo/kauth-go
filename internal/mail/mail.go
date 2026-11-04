package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"html"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/i18n"
)

type Service struct{ cfg config.Config }

func New(cfg config.Config) *Service { return &Service{cfg: cfg} }

// SendMagicLink sender innloggingslenken på valgt språk. Ukjent locale
// faller til engelsk via i18n.Get, så kalleren trenger ikke validere.
//
// fromAddress er tjenestens `email_from_address` (BACKLOG F21) — tom streng
// betyr ingen override, og sendingen går uendret via rå SMTP med den globale
// KAUTH_SMTP_FROM (samme oppførsel som før denne feltet fantes). En satt
// verdi sendes via Brevo, siden det feltet kun skal populeres for tjenester
// på et domene som faktisk er Brevo-verifisert (se doc/BACKLOG.md F21) —
// rå SMTP/Resend er ikke verifisert for de domenene.
func (s *Service) SendMagicLink(to, fromName, linkURL, locale, fromAddress string) error {
	t := i18n.Get(locale)
	if s.cfg.SMTPMock {
		fmt.Printf("[MAIL MOCK] To: %s | Fra: %s (%s) | Språk: %s | Link: %s\n", to, fromName, fromAddress, locale, linkURL)
		return nil
	}
	body := buildMagicBody(t, linkURL)
	htmlBody := buildHTMLBody(body, linkURL, t.SignIn, t.MailLinkFallback)

	if fromAddress != "" {
		if s.cfg.BrevoAPIKey == "" {
			return fmt.Errorf("email_from_address=%q satt men KAUTH_BREVO_API_KEY mangler", fromAddress)
		}
		return sendBrevo(s.cfg.BrevoAPIKey, fromAddress, fromName, to, t.MailSubject, body, htmlBody)
	}

	msg := buildMessage(s.cfg.SMTPFrom, fromName, to, t.MailSubject, body, htmlBody)
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	return sendSMTP(addr, s.cfg.SMTPHost, auth, s.cfg.SMTPFrom, to, msg, s.cfg.SMTPStartTLS)
}

// SendLinkInvite sender koblingsinvitasjonen (016). Samme transportvalg og
// mock-linje som SendMagicLink; mock-linjen har lenken så eval kan lese den.
// providerName er leverandørens visningsnavn og kommer fra en admin-satt rad.
func (s *Service) SendLinkInvite(to, fromName, linkURL, providerName, locale, fromAddress string) error {
	t := i18n.Get(locale)
	if s.cfg.SMTPMock {
		fmt.Printf("[MAIL MOCK] To: %s | Fra: %s (%s) | Språk: %s | Type: link-invite | Link: %s\n", to, fromName, fromAddress, locale, linkURL)
		return nil
	}
	// Linjeskift i navnet ville blitt til ekstra e-posthoder i Subject.
	providerName = strings.NewReplacer("\r", " ", "\n", " ").Replace(providerName)
	subject := strings.ReplaceAll(t.LinkInviteSubject, "{provider}", providerName)
	body := buildLinkInviteBody(t, linkURL, providerName)
	htmlBody := buildHTMLBody(body, linkURL,
		strings.ReplaceAll(t.LinkConfirmButton, "{provider}", providerName), t.MailLinkFallback)

	if fromAddress != "" {
		if s.cfg.BrevoAPIKey == "" {
			return fmt.Errorf("email_from_address=%q satt men KAUTH_BREVO_API_KEY mangler", fromAddress)
		}
		return sendBrevo(s.cfg.BrevoAPIKey, fromAddress, fromName, to, subject, body, htmlBody)
	}
	msg := buildMessage(s.cfg.SMTPFrom, fromName, to, subject, body, htmlBody)
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	return sendSMTP(addr, s.cfg.SMTPHost, auth, s.cfg.SMTPFrom, to, msg, s.cfg.SMTPStartTLS)
}

// SendLinkConfirmation sender kvitteringen etter en vellykket kobling (016),
// slik at en videresendt invitasjon blir synlig for brukeren. Samme
// transportvalg som SendLinkInvite. Mock-linjen har ingen lenke.
func (s *Service) SendLinkConfirmation(to, fromName, providerName, locale, fromAddress string) error {
	t := i18n.Get(locale)
	if s.cfg.SMTPMock {
		fmt.Printf("[MAIL MOCK] To: %s | Fra: %s (%s) | Språk: %s | Type: link-confirmation | Leverandør: %s\n", to, fromName, fromAddress, locale, providerName)
		return nil
	}
	providerName = strings.NewReplacer("\r", " ", "\n", " ").Replace(providerName)
	body := strings.ReplaceAll(t.LinkMailBody, "{provider}", providerName)
	htmlBody := buildHTMLBody(body, "", "", "")

	if fromAddress != "" {
		if s.cfg.BrevoAPIKey == "" {
			return fmt.Errorf("email_from_address=%q satt men KAUTH_BREVO_API_KEY mangler", fromAddress)
		}
		return sendBrevo(s.cfg.BrevoAPIKey, fromAddress, fromName, to, t.LinkMailSubject, body, htmlBody)
	}
	msg := buildMessage(s.cfg.SMTPFrom, fromName, to, t.LinkMailSubject, body, htmlBody)
	addr := fmt.Sprintf("%s:%d", s.cfg.SMTPHost, s.cfg.SMTPPort)
	auth := smtp.PlainAuth("", s.cfg.SMTPUser, s.cfg.SMTPPassword, s.cfg.SMTPHost)
	return sendSMTP(addr, s.cfg.SMTPHost, auth, s.cfg.SMTPFrom, to, msg, s.cfg.SMTPStartTLS)
}

// buildLinkInviteBody setter inn leverandørnavn og lenke i den oversatte teksten.
func buildLinkInviteBody(t i18n.Strings, linkURL, providerName string) string {
	body := strings.ReplaceAll(t.LinkInviteBody, "{provider}", providerName)
	return strings.ReplaceAll(body, "{link}", linkURL)
}

// buildHTMLBody er HTML-utgaven av en ferdig ren-tekst-brødtekst.
//
// Grunnen til at den finnes: e-postene var ren tekst der lenken bare var en
// lang URL-streng. Klienter som ikke auto-linkifier ren tekst (flere
// Android-klienter gjør det ikke når linjen brytes) viste da en lenke
// brukeren ikke fikk trykket på — den så ut som en lenke, men var død tekst.
// Symptomet i support er "lenken fungerer ikke", mens serverloggen ikke har
// en eneste request på tokenet.
//
// Er linkURL satt, byttes forekomsten av den i teksten ut med en knapp
// merket buttonLabel, og lenken gjentas som synlig tekst under knappen slik
// at den også kan kopieres manuelt. Er linkURL tom (kvitteringsmailen),
// blir det bare avsnitt.
func buildHTMLBody(text, linkURL, buttonLabel, fallbackText string) string {
	var sb strings.Builder
	sb.WriteString(`<div style="font-family:system-ui,sans-serif;font-size:15px;line-height:1.5;color:#0f172a">`)

	if linkURL == "" {
		sb.WriteString(htmlParagraphs(text))
		sb.WriteString(`</div>`)
		return sb.String()
	}

	before, after, _ := strings.Cut(text, linkURL)
	href := html.EscapeString(linkURL)
	sb.WriteString(htmlParagraphs(before))
	sb.WriteString(`<p><a href="` + href + `" style="display:inline-block;padding:12px 22px;` +
		`background:#2563eb;color:#ffffff;text-decoration:none;border-radius:6px;font-weight:600">` +
		html.EscapeString(buttonLabel) + `</a></p>`)
	sb.WriteString(`<p style="font-size:13px;color:#475569">` + html.EscapeString(fallbackText) +
		`<br><a href="` + href + `" style="color:#2563eb;word-break:break-all">` + href + `</a></p>`)
	sb.WriteString(htmlParagraphs(after))
	sb.WriteString(`</div>`)
	return sb.String()
}

// htmlParagraphs gjør avsnittene i en ren-tekst-brødtekst til <p>-elementer.
// Enkeltlinjeskift inne i et avsnitt blir <br>. All tekst escapes.
func htmlParagraphs(text string) string {
	var sb strings.Builder
	for _, para := range strings.Split(strings.Trim(text, "\n"), "\n\n") {
		para = strings.Trim(para, "\n")
		if para == "" {
			continue
		}
		sb.WriteString("<p>" + strings.ReplaceAll(html.EscapeString(para), "\n", "<br>") + "</p>")
	}
	return sb.String()
}

// sendBrevo sender via Brevos transaksjons-e-post-API (samme endepunkt og
// mønster som POV-appens src/lib/server/mail/transport.ts). htmlContent er
// påkrevd av API-et uten templateId, og får samme HTML-utgave som SMTP-veien
// sender. textContent er den rene teksten, slik at klienter som foretrekker
// ren tekst viser identisk innhold.
func sendBrevo(apiKey, fromAddress, fromName, to, subject, plainBody, htmlBody string) error {
	payload := map[string]any{
		"sender":      map[string]string{"name": fromName, "email": fromAddress},
		"to":          []map[string]string{{"email": to}},
		"subject":     subject,
		"htmlContent": htmlBody,
		"textContent": plainBody,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("brevo: json marshal: %w", err)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodPost, "https://api.brevo.com/v3/smtp/email", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("brevo: bygg request: %w", err)
	}
	req.Header.Set("api-key", apiKey)
	req.Header.Set("Content-Type", "application/json")

	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("brevo: request feilet: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode >= 300 {
		return fmt.Errorf("brevo: uventet status %d", res.StatusCode)
	}
	return nil
}

// buildMagicBody setter lenken inn i den oversatte brødteksten.
// Navngitt placeholder framfor %s fordi go vet flagger fmt.Sprintf med
// ikke-konstant format-streng.
func buildMagicBody(t i18n.Strings, linkURL string) string {
	return strings.ReplaceAll(t.MailBody, "{link}", linkURL)
}

// Tidsgrenser for rå SMTP. Pakkevariabler slik at testene kan korte dem ned.
// Uten dem henger et stille eller tregt relé en innloggingsforespørsel (og
// goroutinen bak) på ubestemt tid.
var (
	dialTimeout    = 10 * time.Second
	sessionTimeout = 30 * time.Second
)

// dialSMTP kobler til med tidsgrense og setter en absolutt frist for hele
// SMTP-samtalen før banneret leses, siden smtp.Dial ikke har noen av delene.
func dialSMTP(addr, host string) (*smtp.Client, error) {
	conn, err := (&net.Dialer{Timeout: dialTimeout}).Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp dial: %w", err)
	}
	if err := conn.SetDeadline(time.Now().Add(sessionTimeout)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("smtp deadline: %w", err)
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("smtp banner: %w", err)
	}
	return c, nil
}

// sendSMTP er felles sendrutine for begge grenene. requireTLS=true (KAUTH_SMTP_STARTTLS)
// feiler hvis serveren ikke tilbyr STARTTLS; ellers oppgraderes opportunistisk
// slik standardbibliotekets SendMail gjorde. PlainAuth nekter selv ukryptert auth mot ikke-localhost.
func sendSMTP(addr, host string, auth smtp.Auth, from, to, msg string, requireTLS bool) error {
	c, err := dialSMTP(addr, host)
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.Hello("localhost"); err != nil {
		return fmt.Errorf("smtp hello: %w", err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host}); err != nil {
			return fmt.Errorf("starttls: %w", err)
		}
	} else if requireTLS {
		return fmt.Errorf("starttls: serveren tilbyr ikke STARTTLS")
	}
	if auth != nil {
		if ok, _ := c.Extension("AUTH"); !ok {
			return fmt.Errorf("smtp: serveren støtter ikke AUTH")
		}
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth: %w", err)
		}
	}
	if err := c.Mail(from); err != nil {
		return fmt.Errorf("smtp mail: %w", err)
	}
	if err := c.Rcpt(to); err != nil {
		return fmt.Errorf("smtp rcpt: %w", err)
	}
	wc, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	if _, err := fmt.Fprint(wc, msg); err != nil {
		wc.Close()
		return fmt.Errorf("smtp data: %w", err)
	}
	if err := wc.Close(); err != nil {
		return fmt.Errorf("smtp data: %w", err)
	}
	return c.Quit()
}

// buildMessage bygger en multipart/alternative-melding med både ren tekst og
// HTML. Klienten velger selv: de som viser ren tekst får nøyaktig samme
// brødtekst som før, de som viser HTML får en trykkbar knapp.
//
// Begge delene sendes quoted-printable. Uten en Content-Transfer-Encoding ble
// UTF-8 tidligere lagt rått på linjen, og en lang lenke ble én lang linje —
// to ting som er avhengige av at hvert ledd i e-postkjeden er snilt.
func buildMessage(from, fromName, to, subject, textBody, htmlBody string) string {
	var parts bytes.Buffer
	mw := multipart.NewWriter(&parts)

	// Feilene under kan bare komme fra skriving til bytes.Buffer, som ikke
	// feiler — derfor ingen error-retur å bære videre til kalleren.
	writePart := func(contentType, body string) {
		h := make(textproto.MIMEHeader)
		h.Set("Content-Type", contentType+"; charset=UTF-8")
		h.Set("Content-Transfer-Encoding", "quoted-printable")
		w, err := mw.CreatePart(h)
		if err != nil {
			return
		}
		qp := quotedprintable.NewWriter(w)
		_, _ = qp.Write([]byte(body))
		_ = qp.Close()
	}
	// Rekkefølgen er en del av formatet: i multipart/alternative er den
	// siste delen den klienten foretrekker, så HTML må komme sist.
	writePart("text/plain", textBody)
	writePart("text/html", htmlBody)
	_ = mw.Close()

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromName, from))
	sb.WriteString(fmt.Sprintf("To: %s\r\n", to))
	sb.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject)))
	sb.WriteString("MIME-Version: 1.0\r\n")
	sb.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=%q\r\n\r\n", mw.Boundary()))
	sb.WriteString(parts.String())
	return sb.String()
}
