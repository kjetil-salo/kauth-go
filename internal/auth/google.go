package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	googleOAuth2 "golang.org/x/oauth2/google"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// AdminSessionStarter lar OIDC-callbacken starte en admin-sesjon uten at auth
// kjenner admin-cookie, TTL eller admin-audit. Implementasjonen ligger i
// internal/admin (som ikke kan importeres herfra uten syklus) og injiseres fra
// main.go. Kalleren har allerede verifisert at brukeren er aktiv og har
// rollen konge.
type AdminSessionStarter interface {
	StartAdminSession(w http.ResponseWriter, r *http.Request, user gen.User, serviceID string) error
}

type GoogleHandlers struct {
	cfg           config.Config
	queries       *gen.Queries
	issuer        *token.Issuer
	refresh       *token.RefreshService
	reg           *service.Registry
	aud           *audit.Service
	adminSessions AdminSessionStarter
}

func NewGoogleHandlers(cfg config.Config, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service, adminSessions AdminSessionStarter) *GoogleHandlers {
	return &GoogleHandlers{cfg: cfg, queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud, adminSessions: adminSessions}
}

// InitiateLogin — GET /oidc-login eller /social-login
// Hvis redirect_uri-param er satt, lagres den som cookie slik at /dispatch
// kan rute brukeren tilbake til riktig intern path etter callback.
func (h *GoogleHandlers) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	// Lagre redirect_uri-cookie FØR Google-redirect (Java-mønster)
	if ru := r.URL.Query().Get("redirect_uri"); ru != "" {
		secure := os.Getenv("KAUTH_INSECURE_COOKIES") != "true"
		http.SetCookie(w, &http.Cookie{
			Name:     "redirect_uri",
			Value:    url.QueryEscape(ru),
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteLaxMode,
			MaxAge:   600,
		})
	}

	svc := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")
	h.redirectToGoogle(w, r, svc, false)
}

// InitiateAdminLogin — GET /admin/google-init
// Starter samme Google-flyt og samme /callback som vanlig innlogging, men med
// admin-formål i den HMAC-signerte staten. Formålet hentes aldri fra query,
// cookie eller redirect_uri, og redirect_uri-cookien settes ikke: admin-flyten
// skal ikke innom /dispatch.
func (h *GoogleHandlers) InitiateAdminLogin(w http.ResponseWriter, r *http.Request) {
	svc := h.reg.ResolveOrDefault(r.Host, "", "")
	h.redirectToGoogle(w, r, svc, true)
}

func (h *GoogleHandlers) redirectToGoogle(w http.ResponseWriter, r *http.Request, svc *gen.Service, adminPurpose bool) {
	if svc.AuthGoogle != 1 {
		http.Error(w, "Google-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	clientID, _ := googleCreds(h.cfg, svc)
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	var state string
	if adminPurpose {
		state = signAdminState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	} else {
		state = SignState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	}
	oauthCfg := &oauth2.Config{
		ClientID:    clientID,
		Endpoint:    googleOAuth2.Endpoint,
		RedirectURL: "https://" + r.Host + "/callback",
		Scopes:      []string{oidc.ScopeOpenID, "email", "profile"},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "oidc_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	authURL := oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account"))
	http.Redirect(w, r, authURL, http.StatusFound)
}

// HandleCallback — GET /callback
func (h *GoogleHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, err := r.Cookie("oidc_state")
	if err != nil || sc.Value != r.URL.Query().Get("state") {
		http.Error(w, "ugyldig state", http.StatusBadRequest)
		return
	}
	// Admin-formålet leses bare fra den signerte staten, aldri fra query eller
	// andre cookies.
	claims, ok := parseState(h.cfg.OIDCStateSecret, sc.Value)
	if !ok {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	svcID, adminPurpose := claims.ServiceID, claims.Admin
	svc := h.reg.ResolveOrDefault(r.Host, svcID, "")
	clientID, clientSecret := googleCreds(h.cfg, svc)
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     googleOAuth2.Endpoint,
		RedirectURL:  "https://" + r.Host + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	// Feil etter at staten er kjent som admin auditeres som mislykket
	// admin-innlogging, ikke bare som en HTTP-feil.
	fail := func(status int, msg, details string) {
		if adminPurpose {
			h.auditAdminFailure(r, svc, "", details)
		}
		http.Error(w, msg, status)
	}
	oauth2Token, err := oauthCfg.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		fail(http.StatusUnauthorized, "token-utveksling feilet", "kodeutveksling feilet")
		return
	}
	// Bug-fix: handle provider discovery error (brief silently ignored it)
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		fail(http.StatusInternalServerError, "OIDC discovery feilet", "OIDC discovery feilet")
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		fail(http.StatusUnauthorized, "id_token ugyldig", "id_token ugyldig")
		return
	}
	var cl googleClaims
	if err := idToken.Claims(&cl); err != nil {
		fail(http.StatusUnauthorized, "kunne ikke lese claims", "kunne ikke lese claims")
		return
	}
	h.finishCallback(w, r, svc, adminPurpose, cl)
}

// googleClaims er det vi trenger fra Googles id_token.
type googleClaims struct {
	Email         string `json:"email"`
	Name          string `json:"name"`
	EmailVerified bool   `json:"email_verified"`
}

// finishCallback er alt som skjer etter at id_token er verifisert og claims er
// lest. Skilt ut fra HandleCallback slik at begge grenene kan testes uten
// Google.
func (h *GoogleHandlers) finishCallback(w http.ResponseWriter, r *http.Request, svc *gen.Service, adminPurpose bool, cl googleClaims) {
	ctx := r.Context()
	if adminPurpose {
		clearCookie(w, "oidc_state")
		h.completeAdminLogin(w, r, svc, cl)
		return
	}
	user, err := h.findOrCreate(ctx, cl.Email, cl.Name, svc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkPolicy(user, svc); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")
	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "kunne ikke utstede token", http.StatusInternalServerError)
		return
	}
	rt, err := h.refresh.Issue(ctx, user, *svc, ip, ua)
	if err != nil {
		http.Error(w, "kunne ikke utstede refresh-token", http.StatusInternalServerError)
		return
	}
	setRefreshCookie(w, rt)
	clearCookie(w, "oidc_state")
	lastLogin := time.Now().UTC().Format(time.RFC3339)
	if err := h.queries.UpdateUserLastLogin(ctx, gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, Email: user.Email}); err != nil {
		slog.Error("google: kunne ikke oppdatere last_login", "email", user.Email, "error", err)
	}
	h.aud.Log(ctx, audit.Event{Type: "google_oidc_login", AuthMethod: "google", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?token="+url.QueryEscape(at)+"&rt="+url.QueryEscape(rt)+"&service="+url.QueryEscape(svc.ID), http.StatusFound)
}

// auditAdminFailure skriver admin_google_login med success=0.
func (h *GoogleHandlers) auditAdminFailure(r *http.Request, svc *gen.Service, email, details string) {
	h.aud.Log(r.Context(), audit.Event{Type: "admin_google_login", AuthMethod: "google", Email: email, ServiceID: svc.ID, IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: details})
}

// completeAdminLogin avslutter en OIDC-flyt med admin-formål. Den slår bare opp
// en eksisterende aktiv bruker: ingen auto-registrering og ingen tjenestepolicy
// (admin er ikke bundet til en tjeneste). Rollen konge kreves med eksakt match,
// og Google må ha bekreftet e-postadressen. Ingen JWT havner i URL-en;
// sesjonen settes som cookie av AdminSessionStarter.
func (h *GoogleHandlers) completeAdminLogin(w http.ResponseWriter, r *http.Request, svc *gen.Service, cl googleClaims) {
	ctx := r.Context()
	reject := func(email, details string) {
		h.auditAdminFailure(r, svc, email, details)
		http.Redirect(w, r, "/admin/login?err=ingen_tilgang", http.StatusSeeOther)
	}
	// Normalisert slik at oppslaget ikke avhenger av hvordan Google skriver adressen.
	email := strings.ToLower(strings.TrimSpace(cl.Email))
	if email == "" {
		reject("", "mangler e-post i id_token")
		return
	}
	if !cl.EmailVerified {
		reject(email, "e-post ikke verifisert av Google")
		return
	}
	user, err := h.queries.GetActiveUserByEmail(ctx, email)
	if err != nil || !csvHasExact(user.Roles, "konge") {
		reject(email, "ukjent, deaktivert eller mangler konge-rolle")
		return
	}
	if h.adminSessions == nil {
		slog.Error("google: admin-flyt uten AdminSessionStarter")
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	if err := h.adminSessions.StartAdminSession(w, r, user, svc.ID); err != nil {
		slog.Error("google: kunne ikke starte admin-sesjon", "email", user.Email, "error", err)
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (h *GoogleHandlers) findOrCreate(ctx context.Context, email, name string, svc *gen.Service) (gen.User, error) {
	u, err := h.queries.GetActiveUserByEmail(ctx, email)
	if err == nil {
		return u, nil
	}
	if svc.AutoRegister != 1 {
		return gen.User{}, fmt.Errorf("ingen konto")
	}
	role := "user"
	if svc.DefaultRole != nil && *svc.DefaultRole != "" {
		role = *svc.DefaultRole
	}
	org := ""
	if svc.DefaultOrg != nil {
		org = *svc.DefaultOrg
	}
	return h.queries.CreateUser(ctx, gen.CreateUserParams{
		Email:     email,
		Name:      &name,
		Roles:     role,
		Orgs:      org,
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
}

// csvHasExact sjekker om en kommaseparert streng inneholder value som et
// eget felt — ikke som substring. "sysadmin" eller "admin-readonly" skal
// IKKE matche kravet "admin"; kun et felt der hele trimmede verdien er
// nøyaktig "admin" teller.
func csvHasExact(csv, value string) bool {
	for _, part := range strings.Split(csv, ",") {
		if strings.TrimSpace(part) == value {
			return true
		}
	}
	return false
}

func checkPolicy(user gen.User, svc *gen.Service) error {
	if svc.RequireRole != nil && *svc.RequireRole != "" && !csvHasExact(user.Roles, *svc.RequireRole) {
		return fmt.Errorf("mangler rolle")
	}
	if svc.EnforceOrg == 1 && svc.DefaultOrg != nil && !csvHasExact(user.Orgs, *svc.DefaultOrg) {
		return fmt.Errorf("ikke autorisert")
	}
	return nil
}

func googleCreds(cfg config.Config, svc *gen.Service) (id, secret string) {
	id = cfg.GoogleClientID
	if svc.GoogleClientID != nil && *svc.GoogleClientID != "" {
		id = *svc.GoogleClientID
	}
	secret = cfg.GoogleClientSecret
	if svc.GoogleClientSecret != nil && *svc.GoogleClientSecret != "" {
		secret = *svc.GoogleClientSecret
	}
	return
}
