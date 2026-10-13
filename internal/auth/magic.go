package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// --- Magic handlers ---

// magicMailer lar tester telle sendinger uten å fange stdout.
type magicMailer interface {
	SendMagicLink(to, fromName, linkURL, locale, fromAddress string) error
}

type MagicHandlers struct {
	cfg     config.Config
	queries *gen.Queries
	mailer  magicMailer
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
	sendWG  sync.WaitGroup // lar tester vente på asynkrone sendinger
	tmpl    *template.Template
}

func NewMagicHandlers(cfg config.Config, q *gen.Queries, m *mail.Service, iss *token.Issuer,
	ref *token.RefreshService, reg *service.Registry, aud *audit.Service, tmpl *template.Template) *MagicHandlers {
	return &MagicHandlers{cfg: cfg, queries: q, mailer: m, issuer: iss, refresh: ref,
		reg: reg, aud: aud, tmpl: tmpl}
}

// WaitForSends venter til asynkrone e-postsendinger er ferdige (tester og
// kontrollert nedstenging).
func (h *MagicHandlers) WaitForSends() { h.sendWG.Wait() }

// ShowForm — GET /magic-login
func (h *MagicHandlers) ShowForm(w http.ResponseWriter, r *http.Request) {
	svc := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")
	logoHTML := logoHTMLFor(svc)
	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	locale := i18n.FromRequest(r)
	data := LoginPageData{
		Service:     svc,
		LogoHTML:    logoHTML,
		Error:       r.URL.Query().Get("error"),
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, r.URL),
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Responsen varierer med Accept-Language (via i18n.FromRequest) — caches må ta høyde for dette.
	w.Header().Set("Vary", "Accept-Language")
	_ = h.tmpl.ExecuteTemplate(w, "magic-login.html", data)
}

// logoHTMLFor gjør tjenestens lagrede logo om til rå HTML for malene.
func logoHTMLFor(svc *gen.Service) template.HTML {
	if svc.LogoHtml == nil {
		return ""
	}
	// Stored HTML rendered raw. Trust boundary: only admins with the konge role
	// can set svc.LogoHtml (see admin/services.go). Compromised admin = stored XSS
	// on every login page for that service. Sanitisation is intentionally not
	// applied here; admin-side validation is the proper control.
	return template.HTML(*svc.LogoHtml) // #nosec G203
}

// resolveMagicLinkBaseURL avgjør hvilken host magic-link-e-posten skal peke til.
//
// BACKLOG F1 / ADN 87: tidligere ble h.cfg.BaseURL (global, statisk config-verdi,
// alltid https://auth.klarsyn.net) brukt uansett hvilken tjeneste login-flyten
// gjaldt — en Spekto-bruker fikk dermed en lenke til Klarsyn sin egen side.
// svc er allerede korrekt resolvet fra r.Host av kalleren (service.Registry,
// nivå 2 i Resolve()) — bruk dens AuthHost når den finnes. Tjenester uten
// eksplisitt auth_host i DB (klarsyn er is_default og har historisk aldri
// trengt et eget auth_host siden BaseURL allerede pekte dit) faller tilbake
// til cfg.BaseURL, som bevarer eksisterende oppførsel for dem uendret.
func resolveMagicLinkBaseURL(cfg config.Config, svc *gen.Service) string {
	if svc != nil && svc.AuthHost != nil && *svc.AuthHost != "" {
		return "https://" + *svc.AuthHost
	}
	return cfg.BaseURL
}

// randRead er byttbar slik at testen kan simulere feil. Fra Go 1.24 krasjer
// crypto/rand heller enn å returnere feil, så grenen er et forsvar mot
// framtidige endringer, ikke en sti som nås i drift.
var randRead = rand.Read

// RequestLink — POST /magic-login
// Returnerer alltid 200 (anti-enumeration). Minimum 200ms responstid.
func (h *MagicHandlers) RequestLink(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	defer func() {
		if d := time.Since(start); d < 200*time.Millisecond {
			time.Sleep(200*time.Millisecond - d)
		}
	}()
	_ = r.ParseForm()
	// Locale leses fra POST-URL-en; magic-login.html legger ?lang= på fetch-kallet.
	locale := i18n.FromRequest(r)
	// Kvoten telles per normalisert adresse, ellers omgås den med store bokstaver
	// eller mellomrom.
	email := NormalizeEmail(r.FormValue("email"))
	// Leser "service" (ny template) med fallback til "service_id" (gammel form)
	serviceID := r.FormValue("service")
	if serviceID == "" {
		serviceID = r.FormValue("service_id")
	}
	svc := h.reg.ResolveOrDefault(r.Host, serviceID, "")

	b := make([]byte, 32)
	if _, err := randRead(b); err != nil {
		// Et token uten entropi må aldri lagres eller sendes. Feilen avslører ikke
		// om eposten finnes, så anti-enumeration-kravet brytes ikke.
		slog.Error("magic-link: kunne ikke generere token", "error", err)
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	plainToken := hex.EncodeToString(b)

	// Alle grener under svarer likt: avslått metode, kvote, lagringsfeil og
	// suksess skal ikke kunne skilles utenfra (anti-enumeration).
	if h.storeToken(r.Context(), svc, email, plainToken) {
		fromName := svc.EmailFromName
		var fromAddress string
		if svc.EmailFromAddress != nil {
			fromAddress = *svc.EmailFromAddress
		}
		// lang følger med i lenken slik at et eksplisitt språkvalg overlever turen
		// via e-postklienten. Verdiene kodes fordi tjeneste-ID kommer fra
		// skjemaet/DB og ellers kan sprenge query-strengen (&, #).
		q := url.Values{}
		q.Set("service", svc.ID)
		q.Set("lang", locale)
		link := resolveMagicLinkBaseURL(h.cfg, svc) + "/magic-login/" + plainToken + "?" + q.Encode()
		// Sendes asynkront: SMTP-latens bare i suksessgrenen ville ellers skilt
		// «adressen fikk lenke» fra de andre grenene (timing-enumeration). Raden er
		// allerede lagret. Mail-laget tar ikke context, så avbrudd på klientsiden
		// påvirker ikke sendingen; feil logges uten adresse eller lenke.
		h.sendWG.Add(1)
		go func() {
			defer h.sendWG.Done()
			if err := h.mailer.SendMagicLink(email, fromName, link, locale, fromAddress); err != nil {
				slog.Error("magic-link: kunne ikke sende e-post", "error", err)
			}
		}()
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("sjekk e-post"))
}

// storeToken lagrer hashen av tokenet og returnerer true bare når raden faktisk
// ble satt inn. Mislykket lagring, kvote eller avslått metode gir ingen e-post:
// en lenke uten rad ville vært en død lenke som i tillegg avslører at forespørselen
// ikke ble begrenset.
func (h *MagicHandlers) storeToken(ctx context.Context, svc *gen.Service, email, plainToken string) bool {
	if svc == nil || svc.AuthMagicLink != 1 || !token.ValidEmail(email) {
		return false
	}
	// Tjenesten er allerede resolvet; rå skjemaverdi lagres aldri, ellers kunne
	// en ukjent service-ID gi en rad bundet til en tjeneste som ikke finnes.
	serviceID := svc.ID
	if err := token.CheckMagicPurpose(token.MagicPurposeService, &serviceID); err != nil {
		slog.Error("magic-link: ugyldig formål", "error", err)
		return false
	}
	now := time.Now().UTC()
	// BACKLOG F1 K4: redirect_uri er ikke i bruk (magic-login.html sender den
	// aldri); innlogging dekkes av redirect_uri-cookien satt klientside.
	n, err := h.queries.InsertMagicTokenLimited(ctx, gen.InsertMagicTokenLimitedParams{
		TokenHash:   token.HashOpaque(plainToken),
		Email:       email,
		ServiceID:   &serviceID,
		Purpose:     token.MagicPurposeService,
		CreatedAt:   now.Format(time.RFC3339),
		ExpiresAt:   now.Add(15 * time.Minute).Format(time.RFC3339),
		WindowStart: now.Add(-15 * time.Minute).Format(time.RFC3339),
	})
	if err != nil {
		slog.Error("magic-link: kunne ikke lagre token", "service", serviceID, "error", err)
		return false
	}
	return n == 1
}

// redirectWithError sender brukeren tilbake til magic-login-skjemaet med en
// feilkode og valgt språk. Bruker query-escaping på alle tre verdiene selv om
// code er en literal og locale er begrenset til nb/en/de av i18n.Resolve —
// service-ID kommer fra request.
func (h *MagicHandlers) redirectWithError(w http.ResponseWriter, r *http.Request, serviceID, code, locale string) {
	q := url.Values{}
	q.Set("service", serviceID)
	q.Set("error", code)
	q.Set("lang", locale)
	http.Redirect(w, r, "/magic-login?"+q.Encode(), http.StatusFound)
}

// MagicConfirmData er maldata for magic-confirm.html. Siden har med vilje ingen
// e-postadresse: lenken kan åpnes av andre enn mottakeren (videresending,
// delt skjerm), og adressen trengs ikke for å fullføre.
type MagicConfirmData struct {
	Service     *gen.Service
	LogoHTML    template.HTML
	BodyBgCSS   template.CSS
	BeforeBgCSS template.CSS
	Locale      string
	T           i18n.Strings
	Languages   []i18n.Link
	// Action er stien skjemaet POST-er til (samme sti som GET).
	Action string
	// Blocked vises ved 403: POST-en kom ikke fra vår egen side.
	Blocked bool
}

func (h *MagicHandlers) renderConfirm(w http.ResponseWriter, r *http.Request, svc *gen.Service, status int, blocked bool) {
	bodyCss, beforeCss := buildBgCSS(svc.Theme, svc.BgImage, svc.BgCss)
	locale := i18n.FromRequest(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Siden bærer et engangstoken i stien og må ikke caches.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "Accept-Language")
	w.WriteHeader(status)
	if err := h.tmpl.ExecuteTemplate(w, "magic-confirm.html", MagicConfirmData{
		Service:     svc,
		LogoHTML:    logoHTMLFor(svc),
		BodyBgCSS:   bodyCss,
		BeforeBgCSS: beforeCss,
		Locale:      locale,
		T:           i18n.Get(locale),
		Languages:   i18n.Links(locale, r.URL),
		// Tjeneste og språk følger med så feil etter POST havner på riktig tema
		// og språk. svc er den lagrede tjenesten, og locale er hvitelistet.
		Action:  r.URL.Path + "?" + url.Values{"service": {svc.ID}, "lang": {locale}}.Encode(),
		Blocked: blocked,
	}); err != nil {
		slog.Error("magic-link: kunne ikke rendre bekreftelsessiden", "error", err)
	}
}

// storedService slår opp tjenesten tokenet er bundet til. nil betyr at raden
// ikke har en brukbar tjeneste: ukjent, inaktiv eller uten magic link. ?service=
// i lenken er bare et tema-hint og brukes aldri her (K6).
func (h *MagicHandlers) storedService(row gen.MagicToken) *gen.Service {
	if row.ServiceID == nil {
		return nil
	}
	svc := h.reg.Resolve("", *row.ServiceID, "")
	if svc == nil || svc.AuthMagicLink != 1 {
		return nil
	}
	return svc
}

// ShowConfirm — GET /magic-login/{token}
// Viser bare en bekreftelsesside. E-postklienter og lenkeskannere henter
// lenker med GET, så innloggingen skjer først på POST. Ingen rad endres og
// ingenting telles i limiteren (P1).
func (h *MagicHandlers) ShowConfirm(w http.ResponseWriter, r *http.Request) {
	locale := i18n.FromRequest(r)
	hint := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")

	row, err := h.queries.GetValidMagicTokenByHash(r.Context(), gen.GetValidMagicTokenByHashParams{
		TokenHash: token.HashOpaque(chi.URLParam(r, "token")),
		Purpose:   token.MagicPurposeService,
		Now:       time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		h.redirectWithError(w, r, hint.ID, "expired", locale)
		return
	}
	svc := h.storedService(row)
	if svc == nil {
		h.redirectWithError(w, r, hint.ID, "expired", locale)
		return
	}
	h.renderConfirm(w, r, svc, http.StatusOK, false)
}

// Redeem — POST /magic-login/{token}
func (h *MagicHandlers) Redeem(w http.ResponseWriter, r *http.Request) {
	ip := ClientIP(r)
	ua := r.Header.Get("User-Agent")
	locale := i18n.FromRequest(r)
	t := i18n.Get(locale)
	hint := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")

	hash := token.HashOpaque(chi.URLParam(r, "token"))
	now := time.Now().UTC().Format(time.RFC3339)

	if !fetchmeta.SameOrigin(r) {
		// Blokkert siden bruker tokenets egen tjeneste som tema når den finnes,
		// men raden røres ikke.
		themeSvc := hint
		if row, err := h.queries.GetValidMagicTokenByHash(r.Context(), gen.GetValidMagicTokenByHashParams{
			TokenHash: hash, Purpose: token.MagicPurposeService, Now: now,
		}); err == nil {
			if stored := h.storedService(row); stored != nil {
				themeSvc = stored
			}
		}
		h.renderConfirm(w, r, themeSvc, http.StatusForbidden, true)
		return
	}

	magic, err := h.queries.ConsumeMagicToken(r.Context(), gen.ConsumeMagicTokenParams{
		TokenHash: hash,
		Purpose:   token.MagicPurposeService,
		Now:       now,
	})
	if err != nil {
		// Brukertilstand, ikke serverfeil: send tilbake til skjemaet med oversatt
		// melding så brukeren kan be om en ny lenke.
		h.redirectWithError(w, r, hint.ID, "expired", locale)
		return
	}
	// Formålsbinding (ADN 9): et token uten tjeneste er utstedt til admin-panelet
	// (/admin/verify) og skal ikke kunne gi en tjenesteinnlogging.
	if magic.ServiceID == nil {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "magic_link", Email: magic.Email, IP: ip, UA: ua, Success: false, Details: "admin-token brukt mot tjenesteinnlogging, hint=" + hint.ID})
		h.redirectWithError(w, r, hint.ID, "expired", locale)
		return
	}
	// Alt videre bruker bare tjenesten tokenet er bundet til, aldri host eller
	// ?service= fra denne forespørselen (K6).
	svc := h.storedService(magic)
	if svc == nil {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "magic_link", Email: magic.Email, ServiceID: *magic.ServiceID, IP: ip, UA: ua, Success: false, Details: "tjeneste inaktiv eller magic link av"})
		h.redirectWithError(w, r, *magic.ServiceID, "expired", locale)
		return
	}

	user, err := h.queries.GetActiveUserByEmail(r.Context(), magic.Email)
	if err != nil {
		if svc.AutoRegister != 1 {
			h.redirectWithError(w, r, svc.ID, "no_account", locale)
			return
		}
		defaultOrg := ""
		if svc.DefaultOrg != nil {
			defaultOrg = *svc.DefaultOrg
		}
		defaultRole := "user"
		if svc.DefaultRole != nil && *svc.DefaultRole != "" {
			defaultRole = *svc.DefaultRole
		}
		user, err = h.queries.CreateUser(r.Context(), gen.CreateUserParams{
			Email:     magic.Email,
			Roles:     defaultRole,
			Orgs:      defaultOrg,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		})
		if err != nil {
			slog.Error("magic-link: kunne ikke opprette bruker", "email", magic.Email, "service", svc.ID, "error", err)
			http.Error(w, t.ErrInternal, http.StatusInternalServerError)
			return
		}
	}

	// require_role/enforce_org håndheves nå her — tidligere ble magic link
	// (i motsetning til Google/Microsoft) aldri sjekket mot disse, slik at en
	// bruker uten en tjenestes påkrevde rolle likevel kunne logge inn dit via
	// magic link (github.com/zral/kauth-go/issues/3).
	if err := checkPolicy(user, svc); err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "magic_link", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false, Details: err.Error()})
		h.redirectWithError(w, r, svc.ID, "access_denied", locale)
		return
	}

	accessToken, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		slog.Error("magic-link: kunne ikke utstede access-token", "email", user.Email, "service", svc.ID, "error", err)
		http.Error(w, t.ErrInternal, http.StatusInternalServerError)
		return
	}
	refreshToken, err := h.refresh.Issue(r.Context(), user, *svc, ip, ua)
	if err != nil {
		slog.Error("magic-link: kunne ikke utstede refresh-token", "email", user.Email, "service", svc.ID, "error", err)
		http.Error(w, t.ErrInternal, http.StatusInternalServerError)
		return
	}
	setRefreshCookie(w, refreshToken)

	lastLogin := time.Now().UTC().Format(time.RFC3339)
	if err := h.queries.UpdateUserLastLogin(r.Context(), gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, Email: user.Email}); err != nil {
		slog.Error("magic-link: kunne ikke oppdatere last_login", "email", user.Email, "error", err)
	}
	h.aud.Log(r.Context(), audit.Event{Type: "magic_link_login", AuthMethod: "magic_link", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?token="+url.QueryEscape(accessToken)+"&rt="+url.QueryEscape(refreshToken)+"&service="+url.QueryEscape(svc.ID), http.StatusFound)
}
