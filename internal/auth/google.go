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

type GoogleHandlers struct {
	cfg     config.Config
	queries *gen.Queries
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
}

func NewGoogleHandlers(cfg config.Config, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *GoogleHandlers {
	return &GoogleHandlers{cfg: cfg, queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud}
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
	state := SignState(h.cfg.OIDCStateSecret, svc.ID, nonce)
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
	svcID, ok := VerifyState(h.cfg.OIDCStateSecret, sc.Value)
	if !ok {
		http.Error(w, "ugyldig HMAC", http.StatusBadRequest)
		return
	}
	svc := h.reg.ResolveOrDefault(r.Host, svcID, "")
	clientID, clientSecret := googleCreds(h.cfg, svc)
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint:     googleOAuth2.Endpoint,
		RedirectURL:  "https://" + r.Host + "/callback",
		Scopes:       []string{oidc.ScopeOpenID, "email", "profile"},
	}
	oauth2Token, err := oauthCfg.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "token-utveksling feilet", http.StatusUnauthorized)
		return
	}
	// Bug-fix: handle provider discovery error (brief silently ignored it)
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		http.Error(w, "OIDC discovery feilet", http.StatusInternalServerError)
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	idToken, err := provider.Verifier(&oidc.Config{ClientID: clientID}).Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token ugyldig", http.StatusUnauthorized)
		return
	}
	// Bug-fix: correct JSON struct tags (brief had a single tag "email,name" for both fields)
	var cl struct {
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := idToken.Claims(&cl); err != nil {
		http.Error(w, "kunne ikke lese claims", http.StatusUnauthorized)
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
