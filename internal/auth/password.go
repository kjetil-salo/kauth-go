package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// PasswordHandlers håndterer passord-innlogging og OAuth2 refresh-grant.
type PasswordHandlers struct {
	queries *gen.Queries
	issuer  *token.Issuer
	refresh *token.RefreshService
	reg     *service.Registry
	aud     *audit.Service
}

func NewPasswordHandlers(q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service) *PasswordHandlers {
	return &PasswordHandlers{queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud}
}

// DoLogin — POST /do-login
func (h *PasswordHandlers) DoLogin(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.TrimSpace(r.FormValue("email"))
	password := r.FormValue("password")
	svcID := r.FormValue("service_id")
	svc := h.reg.ResolveOrDefault(r.Host, svcID, "")

	if svc.AuthPassword != 1 {
		http.Error(w, "passord-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	user, err := h.queries.GetActiveUserByEmail(r.Context(), email)
	if err != nil || user.PasswordHash == nil || *user.PasswordHash == "" {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "password", Email: email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		http.Error(w, "ugyldig e-post eller passord", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(*user.PasswordHash), []byte(password)); err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "password", Email: email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		http.Error(w, "ugyldig e-post eller passord", http.StatusUnauthorized)
		return
	}

	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	rt, err := h.refresh.Issue(r.Context(), user, *svc, ip, ua)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	setRefreshCookie(w, rt)

	lastLogin := time.Now().UTC().Format(time.RFC3339)
	if err := h.queries.UpdateUserLastLogin(r.Context(), gen.UpdateUserLastLoginParams{LastLogin: &lastLogin, Email: user.Email}); err != nil {
		slog.Error("password: kunne ikke oppdatere last_login", "email", user.Email, "error", err)
	}
	h.aud.Log(r.Context(), audit.Event{Type: "login_success", AuthMethod: "password", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	http.Redirect(w, r, "/dispatch?token="+url.QueryEscape(at)+"&rt="+url.QueryEscape(rt)+"&service="+url.QueryEscape(svc.ID), http.StatusFound)
}

// Token — POST /token. Dispatcher på grant_type (RFC 6749 §4).
// Ingen grant_type (eldre klienter) behandles som refresh_token for
// bakoverkompatibilitet.
func (h *PasswordHandlers) Token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	if r.FormValue("grant_type") == "authorization_code" {
		h.authorizationCodeGrant(w, r)
		return
	}
	h.RefreshToken(w, r)
}

// authorizationCodeGrant løser inn en autorisasjonskode fra /login
// (RFC 6749 §4.1.3 + PKCE, RFC 7636 §4.6).
func (h *PasswordHandlers) authorizationCodeGrant(w http.ResponseWriter, r *http.Request) {
	code := r.FormValue("code")
	redirectURI := r.FormValue("redirect_uri")
	clientID := r.FormValue("client_id")
	verifier := r.FormValue("code_verifier")
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	if code == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	row, err := h.queries.ConsumeAuthorizationCode(r.Context(), gen.ConsumeAuthorizationCodeParams{
		Code:      code,
		ExpiresAt: now,
	})
	if err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_invalid", ServiceID: clientID, IP: ip, UA: ua, Success: false})
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	// client_id og redirect_uri må matche eksakt det koden ble utstedt for
	// (RFC 6749 §4.1.3) — hindrer at en kode utstedt til én klient/redirect_uri
	// løses inn et annet sted.
	if row.ServiceID != clientID || row.RedirectUri != redirectURI {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	svc := h.reg.Resolve("", row.ServiceID, "")
	if svc == nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_client")
		return
	}

	if svc.RequiresPkce == 1 {
		challenge, method := "", ""
		if row.CodeChallenge != nil {
			challenge = *row.CodeChallenge
		}
		if row.CodeChallengeMethod != nil {
			method = *row.CodeChallengeMethod
		}
		if !VerifyPKCE(verifier, challenge, method) {
			h.aud.Log(r.Context(), audit.Event{Type: "pkce_verification_failed", Email: row.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
			writeTokenError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	}

	user, err := h.queries.GetActiveUserByEmail(r.Context(), row.Email)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	nonce := ""
	if row.Nonce != nil {
		nonce = *row.Nonce
	}
	idToken, err := h.issuer.IssueIDToken(user, *svc, nonce)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	rt, err := h.refresh.Issue(r.Context(), user, *svc, ip, ua)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}

	h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_exchanged", AuthMethod: "authorization_code", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})

	ttl, err := token.ParseISO8601Duration(svc.AccessTokenTtl)
	if err != nil || ttl <= 0 {
		ttl = 15 * time.Minute
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  at,
		"id_token":      idToken,
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    int64(ttl.Seconds()),
	})
}

// RefreshToken — POST /token
// Leser refresh token fra cookie FØR form-body (cookie prioriteres).
func (h *PasswordHandlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	plain := ""
	if c, err := r.Cookie("refresh_token"); err == nil {
		plain = c.Value
	}
	if plain == "" {
		plain = r.FormValue("refresh_token")
	}
	if plain == "" {
		writeTokenError(w, http.StatusBadRequest, "invalid_request")
		return
	}

	result, err := h.refresh.Rotate(r.Context(), plain, ip, ua)
	if err != nil {
		clearCookie(w, "refresh_token")
		if errors.Is(err, token.ErrTokenReuse) {
			writeTokenError(w, http.StatusUnauthorized, "refresh_token_reused")
			return
		}
		writeTokenError(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}

	user, err := h.queries.GetActiveUserByEmail(r.Context(), result.Email)
	if err != nil {
		writeTokenError(w, http.StatusUnauthorized, "invalid_or_expired_token")
		return
	}

	svc := h.reg.ResolveOrDefault("", r.FormValue("service_id"), "")

	at, err := h.issuer.IssueAccess(user, *svc)
	if err != nil {
		http.Error(w, "intern feil", http.StatusInternalServerError)
		return
	}
	setAuthCookies(w, svc, at, result.NewToken)

	ttl, err := token.ParseISO8601Duration(svc.AccessTokenTtl)
	if err != nil || ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":  at,
		"refresh_token": result.NewToken,
		"token_type":    "Bearer",
		"expires_in":    int64(ttl.Seconds()),
	})
}

func writeTokenError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
