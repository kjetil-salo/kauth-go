package auth

import (
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
	"github.com/zral/kauth-go/internal/i18n"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// --- Rate limiter ---

type rateLimiterEntry struct {
	count     int
	windowEnd time.Time
}

type RateLimiter struct {
	mu      sync.Mutex
	entries map[string]*rateLimiterEntry
	limit   int
	window  time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{entries: make(map[string]*rateLimiterEntry), limit: limit, window: window}
}

func (rl *RateLimiter) Allow(email string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.entries[email]
	if !ok || now.After(e.windowEnd) {
		rl.entries[email] = &rateLimiterEntry{count: 1, windowEnd: now.Add(rl.window)}
		return true
	}
	if e.count >= rl.limit {
		return false
	}
	e.count++
	return true
}

// --- Magic handlers ---

type MagicHandlers struct {
	cfg     config.Config
	queries *gen.Queries
	mailer  *mail.Service
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
	rl      *RateLimiter
	tmpl    *template.Template
}

func NewMagicHandlers(cfg config.Config, q *gen.Queries, m *mail.Service, iss *token.Issuer,
	ref *token.RefreshService, reg *service.Registry, aud *audit.Service, tmpl *template.Template) *MagicHandlers {
	return &MagicHandlers{cfg: cfg, queries: q, mailer: m, issuer: iss, refresh: ref,
		reg: reg, aud: aud, rl: NewRateLimiter(3, 15*time.Minute), tmpl: tmpl}
}

// ShowForm — GET /magic-login
func (h *MagicHandlers) ShowForm(w http.ResponseWriter, r *http.Request) {
	svc := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")
	var logoHTML template.HTML
	if svc.LogoHtml != nil {
		// Stored HTML rendered raw. Trust boundary: only admins with the konge role
		// can set svc.LogoHtml (see admin/services.go). Compromised admin = stored XSS
		// on every login page for that service. Sanitisation is intentionally not
		// applied here; admin-side validation is the proper control.
		logoHTML = template.HTML(*svc.LogoHtml) // #nosec G203
	}
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
	email := r.FormValue("email")
	// Leser "service" (ny template) med fallback til "service_id" (gammel form)
	serviceID := r.FormValue("service")
	if serviceID == "" {
		serviceID = r.FormValue("service_id")
	}
	svc := h.reg.ResolveOrDefault(r.Host, serviceID, "")

	if !h.rl.Allow(email) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("sjekk e-post"))
		return
	}

	b := make([]byte, 32)
	_, _ = rand.Read(b)
	plainToken := hex.EncodeToString(b)
	now := time.Now().UTC()

	// BACKLOG F1 K4: redirect_uri ble tidligere lest fra query-param her, men
	// magic-login.html sin fetch() sender aldri det feltet (kun email+service) —
	// verdien var derfor alltid nil i praksis, og RedirectUri leses ikke andre
	// steder i kodebasen (verifisert). Fjernet i stedet for å late som den brukes;
	// selve redirect-etter-innlogging dekkes av redirect_uri-cookien satt
	// klientside i login.html (samme mekanisme som Google/Microsoft-flyten).
	if err := h.queries.InsertMagicToken(r.Context(), gen.InsertMagicTokenParams{
		Token:       plainToken,
		Email:       email,
		ServiceID:   &serviceID,
		RedirectUri: nil,
		ExpiresAt:   now.Add(15 * time.Minute).Format(time.RFC3339),
		CreatedAt:   now.Format(time.RFC3339),
	}); err != nil {
		slog.Error("magic-link: kunne ikke lagre token", "email", email, "error", err)
		// Anti-enumeration: same response regardless
	}

	fromName := svc.EmailFromName
	var fromAddress string
	if svc.EmailFromAddress != nil {
		fromAddress = *svc.EmailFromAddress
	}
	baseURL := resolveMagicLinkBaseURL(h.cfg, svc)
	// lang følger med i lenken slik at et eksplisitt språkvalg overlever turen
	// via e-postklienten — nettleseren som åpner lenken kan ha en annen
	// Accept-Language enn den brukeren valgte på login-siden.
	link := baseURL + "/magic-login/" + plainToken + "?service=" + serviceID + "&lang=" + locale
	if err := h.mailer.SendMagicLink(email, fromName, link, locale, fromAddress); err != nil {
		slog.Error("magic-link: kunne ikke sende e-post", "email", email, "error", err)
		// Anti-enumeration: same response regardless
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("sjekk e-post"))
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

// VerifyToken — GET /magic-login/{token}
func (h *MagicHandlers) VerifyToken(w http.ResponseWriter, r *http.Request) {
	svcID := r.URL.Query().Get("service")
	svc := h.reg.ResolveOrDefault(r.Host, svcID, "")
	ip := ClientIP(r)
	ua := r.Header.Get("User-Agent")
	locale := i18n.FromRequest(r)
	t := i18n.Get(locale)

	magic, err := h.queries.ConsumeMagicToken(r.Context(), gen.ConsumeMagicTokenParams{
		Token:     chi.URLParam(r, "token"),
		ExpiresAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		// Brukertilstand, ikke serverfeil: send tilbake til skjemaet med oversatt
		// melding så brukeren kan be om en ny lenke.
		h.redirectWithError(w, r, svc.ID, "expired", locale)
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
