package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
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
	// fetchClaims er en testsøm; nil betyr ekte kodeutveksling og verifisering.
	fetchClaims func(ctx context.Context, cfg *oauth2.Config, code string) (msClaims, error)
}

func NewMicrosoftHandlers(cfg config.Config, q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *MicrosoftHandlers {
	return &MicrosoftHandlers{cfg: cfg, queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud}
}

// InitiateLogin — GET /ms-oidc-login
func (h *MicrosoftHandlers) InitiateLogin(w http.ResponseWriter, r *http.Request) {
	svc := h.reg.ResolveOrDefault(r.Host, r.URL.Query().Get("service"), "")
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
	http.Redirect(w, r, oauthCfg.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.SetAuthURLParam("prompt", "select_account")), http.StatusFound)
}

// HandleCallback — GET /ms-callback
func (h *MicrosoftHandlers) HandleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	sc, err := r.Cookie("ms_state")
	if err != nil || sc.Value != r.URL.Query().Get("state") {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	claims, ok := parseState(h.cfg.OIDCStateSecret, sc.Value)
	if !ok || claims.Admin {
		redirectLoginError(w, r, "", errCodeLoginFailed)
		return
	}
	svc := h.reg.ResolveOrDefault(r.Host, claims.ServiceID, "")
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
	fetch := h.fetchClaims
	if fetch == nil {
		fetch = fetchMSClaims
	}
	cl, err := fetch(ctx, oauthCfg, r.URL.Query().Get("code"))
	if err != nil {
		if errors.Is(err, errClaimsDecode) {
			h.auditRejected(r, svc, cl.Tid, msReasonClaimsDecode)
		} else {
			slog.Warn("microsoft: id_token-henting feilet", "error", err)
		}
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	h.finishCallback(w, r, svc, cl, claims.Nonce)
}

var errClaimsDecode = errors.New("claims kunne ikke dekodes")

// fetchMSClaims bytter koden, verifiserer id_token-signaturen og dekoder claims.
// Ved dekodingsfeil returneres det som lot seg lese av tid sammen med errClaimsDecode.
func fetchMSClaims(ctx context.Context, cfg *oauth2.Config, code string) (msClaims, error) {
	oauth2Token, err := cfg.Exchange(ctx, code)
	if err != nil {
		return msClaims{}, fmt.Errorf("kodeutveksling: %w", err)
	}
	rawIDToken, _ := oauth2Token.Extra("id_token").(string)
	// SkipIssuerCheck er nødvendig: /common utsteder per-tenant iss. Signatur,
	// audience og utløp verifiseres fortsatt; issuer sjekkes i validateMSClaims.
	verifier := oidc.NewVerifier(
		msAuthBase,
		oidc.NewRemoteKeySet(ctx, "https://login.microsoftonline.com/common/discovery/v2.0/keys"),
		&oidc.Config{ClientID: cfg.ClientID, SkipIssuerCheck: true},
	)
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return msClaims{}, fmt.Errorf("id_token: %w", err)
	}
	var cl msClaims
	if err := idToken.Claims(&cl); err != nil {
		// Feilen fra JSON-dekoderen navngir felt og type, ikke verdier, og
		// trengs for å se hvilken claim Microsoft sender i et annet format.
		slog.Warn("microsoft: claims kunne ikke dekodes", "err", err)
		var partial struct {
			Tid string `json:"tid"`
		}
		_ = idToken.Claims(&partial)
		return msClaims{Tid: partial.Tid}, errClaimsDecode
	}
	cl.XmsEdov = parseEdov(cl.XmsEdovRaw)
	return cl, nil
}

func (h *MicrosoftHandlers) auditRejected(r *http.Request, svc *gen.Service, tid, reason string) {
	details := "reason=" + reason
	if tid != "" {
		details = "tid=" + sanitizeLogValue(tid) + " " + details
	}
	h.aud.Log(r.Context(), audit.Event{Type: "microsoft_oidc_rejected", AuthMethod: "microsoft", ServiceID: svc.ID,
		IP: ClientIP(r), UA: r.Header.Get("User-Agent"), Success: false, Details: details})
}

// finishCallback tar over etter at id_token er signaturverifisert, slik at
// claims-avslag og policy kan testes uten nettverk.
func (h *MicrosoftHandlers) finishCallback(w http.ResponseWriter, r *http.Request, svc *gen.Service, cl msClaims, stateNonce string) {
	ctx := r.Context()
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")
	email, reason := validateMSClaims(cl, stateNonce)
	email = strings.TrimSpace(email)
	if reason != "" {
		h.auditRejected(r, svc, cl.Tid, reason)
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	user, err := h.findOrCreate(ctx, email, cl.Name, svc)
	if err != nil {
		if errors.Is(err, errNoAccount) {
			redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
			return
		}
		slog.Error("microsoft: kunne ikke opprette bruker", "error", err)
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	if err := checkPolicy(user, svc); err != nil {
		redirectLoginError(w, r, svc.ID, errCodeAccessDenied)
		return
	}
	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		slog.Error("microsoft: kunne ikke utstede token", "error", err)
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
		return
	}
	rt, err := h.refresh.Issue(ctx, user, *svc, ip, ua)
	if err != nil {
		slog.Error("microsoft: kunne ikke utstede refresh-token", "error", err)
		redirectLoginError(w, r, svc.ID, errCodeLoginFailed)
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
		return gen.User{}, errNoAccount
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
