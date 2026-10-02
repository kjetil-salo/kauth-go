package auth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// msAuthBase er base-URL for Microsoft /common v2.0-endepunktet.
// Nøkkel-URL blir msAuthBase+"/keys" = https://login.microsoftonline.com/common/oauth2/v2.0/keys.
// Microsoft publiserer faktisk nøkler på /discovery/v2.0/keys, men /v2.0/keys redirecter dit
// og fungerer i praksis. Dersom go-oidc klager på URL ved integrasjonstest kan dette endres.
const msAuthBase = "https://login.microsoftonline.com/common/oauth2/v2.0"

type MicrosoftHandlers struct {
	cfg     config.Config
	queries *gen.Queries
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
}

func NewMicrosoftHandlers(cfg config.Config, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *MicrosoftHandlers {
	return &MicrosoftHandlers{cfg: cfg, queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud}
}

// InitiateLogin — GET /ms-oidc-login
func (h *MicrosoftHandlers) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	// Eksplisitt service-param (nå alltid satt av login.html sin ms-btn-lenke)
	// må vinne over host-header-match — samme resonnement som google.go.
	host := r.Host
	serviceID := r.URL.Query().Get("service")
	if serviceID != "" {
		host = ""
	}
	svc := h.reg.ResolveOrDefault(host, serviceID, "")
	if svc.AuthMicrosoft != 1 {
		http.Error(w, "Microsoft-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	clientID, _ := msCreds(h.cfg, svc)
	// Fix 4: handle generateNonce error rather than silently ignoring it
	nonce, err := generateNonce()
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	state := SignState(h.cfg.OIDCStateSecret, svc.ID, nonce)
	oauthCfg := &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: "https://" + r.Host + "/ms-callback",
		Scopes:      []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  msAuthBase + "/authorize",
			TokenURL: msAuthBase + "/token",
		},
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ms_state",
		Value:    state,
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
	http.Redirect(w, r, oauthCfg.AuthCodeURL(state, oauth2.SetAuthURLParam("prompt", "select_account")), http.StatusFound)
}

// HandleCallback — GET /ms-callback
func (h *MicrosoftHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, err := r.Cookie("ms_state")
	if err != nil || sc.Value != r.URL.Query().Get("state") {
		http.Error(w, "ugyldig state", http.StatusBadRequest)
		return
	}
	svcID, ok := VerifyState(h.cfg.OIDCStateSecret, sc.Value)
	if !ok {
		http.Error(w, "ugyldig HMAC", http.StatusBadRequest)
		return
	}
	// svcID kommer fra signert state satt i InitiateLogin — host-header skal
	// ikke kunne overstyre den her.
	svc := h.reg.ResolveOrDefault("", svcID, "")
	clientID, clientSecret := msCreds(h.cfg, svc)
	oauthCfg := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  "https://" + r.Host + "/ms-callback",
		Scopes:       []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  msAuthBase + "/authorize",
			TokenURL: msAuthBase + "/token",
		},
	}
	oauth2Token, err := oauthCfg.Exchange(ctx, r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "token-utveksling feilet", http.StatusUnauthorized)
		return
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	// SkipIssuerCheck er nødvendig: Microsoft /common-endepunkt utsteder per-tenant issuer-claims
	verifier := oidc.NewVerifier(
		msAuthBase,
		oidc.NewRemoteKeySet(ctx, "https://login.microsoftonline.com/common/discovery/v2.0/keys"),
		&oidc.Config{ClientID: clientID, SkipIssuerCheck: true},
	)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token ugyldig: "+err.Error(), http.StatusUnauthorized)
		return
	}
	// Fix 5: multi-line struct for readability (same fields and tags as brief)
	var cl struct {
		Email             string `json:"email"`
		PreferredUsername string `json:"preferred_username"`
		Name              string `json:"name"`
	}
	// Fix 1: handle Claims error rather than silently ignoring it
	if err := idToken.Claims(&cl); err != nil {
		http.Error(w, "kunne ikke lese claims", http.StatusUnauthorized)
		return
	}
	// Enterprise accounts often have empty email; fall back to UPN-ish preferred_username
	email := cl.Email
	if email == "" {
		email = cl.PreferredUsername
	}
	user, err := h.findOrCreate(ctx, email, cl.Name, svc)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	if err := checkPolicy(user, svc); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")
	// Fix 2: handle IssueAccess error rather than silently ignoring it
	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "kunne ikke utstede token", http.StatusInternalServerError)
		return
	}
	// Fix 3: handle Issue error rather than silently ignoring it (use = not :=; err already in scope)
	rt, err := h.refresh.Issue(ctx, user, *svc, ip, ua)
	if err != nil {
		http.Error(w, "kunne ikke utstede refresh-token", http.StatusInternalServerError)
		return
	}
	setRefreshCookie(w, rt)
	clearCookie(w, "ms_state")
	lastLogin := time.Now().UTC().Format(time.RFC3339)
	if err := h.queries.UpdateUserLastLogin(ctx, gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, Email: user.Email}); err != nil {
		slog.Error("microsoft: kunne ikke oppdatere last_login", "email", user.Email, "error", err)
	}
	h.aud.Log(ctx, audit.Event{Type: "microsoft_oidc_login", AuthMethod: "microsoft", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?token="+url.QueryEscape(at)+"&rt="+url.QueryEscape(rt)+"&service="+url.QueryEscape(svc.ID), http.StatusFound)
}

func (h *MicrosoftHandlers) findOrCreate(ctx context.Context, email, name string, svc *gen.Service) (gen.User, error) {
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

func msCreds(cfg config.Config, svc *gen.Service) (id, secret string) {
	id = cfg.MicrosoftClientID
	if svc.MicrosoftClientID != nil && *svc.MicrosoftClientID != "" {
		id = *svc.MicrosoftClientID
	}
	secret = cfg.MicrosoftClientSecret
	if svc.MicrosoftClientSecret != nil && *svc.MicrosoftClientSecret != "" {
		secret = *svc.MicrosoftClientSecret
	}
	return
}
