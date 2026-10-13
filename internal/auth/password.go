package auth

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"

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
	// passwordLoginEnabled er den globale bryteren (KAUTH_PASSWORD_LOGIN_ENABLED).
	// Den gjelder /do-login uansett tjenestens auth_password.
	passwordLoginEnabled bool
	// corsOrigins er KAUTH_CORS_ORIGINS; brukes til Origin-sjekk på refresh-grant.
	corsOrigins []string
}

// WithCORSOrigins setter origin-allowlisten som refresh-grant sjekker mot.
func (h *PasswordHandlers) WithCORSOrigins(origins []string) *PasswordHandlers {
	h.corsOrigins = origins
	if len(origins) == 0 {
		slog.Warn("refresh-allowlist er tom: all refresh med Origin-header avvises (KAUTH_CORS_ORIGINS)")
	} else {
		slog.Info("refresh-allowlist lastet", "origins", len(origins))
	}
	return h
}

func NewPasswordHandlers(q *gen.Queries, iss *token.Issuer, ref *token.RefreshService, reg *service.Registry, aud *audit.Service, passwordLoginEnabled bool) *PasswordHandlers {
	return &PasswordHandlers{queries: q, issuer: iss, refresh: ref, reg: reg, aud: aud, passwordLoginEnabled: passwordLoginEnabled}
}

// DoLogin — POST /do-login
func (h *PasswordHandlers) DoLogin(w http.ResponseWriter, r *http.Request) {
	// Før alt annet: ingen skjemaparsing, brukeroppslag eller bcrypt når
	// bryteren er av.
	if !h.passwordLoginEnabled {
		http.Error(w, "passord-innlogging ikke aktivert", http.StatusForbidden)
		return
	}
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

	// require_role/enforce_org håndheves nå her — tidligere ble
	// passord-login (i motsetning til Google/Microsoft) aldri sjekket mot
	// disse (github.com/zral/kauth-go/issues/3).
	if err := checkPolicy(user, svc); err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "login_failed", AuthMethod: "password", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false, Details: err.Error()})
		http.Error(w, err.Error(), http.StatusForbidden)
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
	// RFC 7636 §4.1: 43-128 tegn. En kortere/lengre verdi er aldri gyldig —
	// avvis før vi i det hele tatt bruker den, samme prinsipp som å ikke
	// hashe et opplagt for kort passord.
	if len(verifier) < 43 || len(verifier) > 128 {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
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

	// PKCE er obligatorisk for enhver kode utstedt via denne flyten — ingen
	// per-tjeneste unntak (se migrasjon 007: code_challenge er NOT NULL).
	if !VerifyPKCE(verifier, row.CodeChallenge, row.CodeChallengeMethod) {
		h.aud.Log(r.Context(), audit.Event{Type: "pkce_verification_failed", Email: row.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	user, err := h.queries.GetActiveUserByEmail(r.Context(), row.Email)
	if err != nil {
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	// Kritisk: svc.RequireRole/EnforceOrg må håndheves HER, ikke antas
	// dekket av at brukeren en gang logget inn et sted. /dispatch sin
	// service-ID-sjekk (q.Get("service") == oidcReq.ClientID) er IKKE nok —
	// den er en URL-parameter angriperen selv styrer når /dispatch kalles
	// direkte, ikke en verdi bundet til tokenet (vanlige access-tokens har
	// ingen aud). En bruker med et gyldig token for tjeneste B kan derfor gå
	// rett til /dispatch?token=<B-token>&service=A og få en A-kode uten å
	// noensinne ha gått via A sin login-handler, der checkPolicy normalt
	// ville stoppet dem. Denne sjekken er derfor det ENESTE stedet i hele
	// authorization_code-flyten som faktisk håndhever A sine tilgangsregler
	// — se PR-diskusjonen (github.com/zral/kauth-go/pull/1) for det fulle
	// angrepsscenarioet.
	if err := checkPolicy(user, svc); err != nil {
		h.aud.Log(r.Context(), audit.Event{Type: "authorization_code_policy_denied", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: false})
		writeTokenError(w, http.StatusBadRequest, "invalid_grant")
		return
	}

	nonce := ""
	if row.Nonce != nil {
		nonce = *row.Nonce
	}
	scope := ""
	if row.Scope != nil {
		scope = *row.Scope
	}

	at, err := h.issuer.IssueAccessForAudience(user, *svc, clientID)
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
	resp := map[string]any{
		"access_token":  at,
		"refresh_token": rt,
		"token_type":    "Bearer",
		"expires_in":    int64(ttl.Seconds()),
	}
	// id_token er en OIDC-ting (OIDC Core §3.1.3.3): utstedes kun når
	// openid-scopet faktisk ble bedt om. En ren OAuth2-klient som aldri ba
	// om openid skal ikke få et identitetstoken den ikke forventer.
	if scopeContains(scope, "openid") {
		idToken, err := h.issuer.IssueIDToken(user, *svc, nonce)
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		resp["id_token"] = idToken
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

// scopeContains sjekker om et mellomromseparert scope-felt inneholder en
// eksakt scope-verdi (ikke substreng-match — "openidconnect" skal ikke
// telle som "openid").
func scopeContains(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// RefreshToken — POST /token
// Leser refresh token fra cookie FØR form-body (cookie prioriteres).
func (h *PasswordHandlers) RefreshToken(w http.ResponseWriter, r *http.Request) {
	ip, ua := ClientIP(r), r.Header.Get("User-Agent")

	// Origin-sjekk FØR Rotate: et avvist kall skal ikke brenne tokenet. Uten
	// Origin-header (server-til-server) går kallet gjennom som før. En tom
	// Origin-header er en header som finnes, og avvises.
	if vals, present := r.Header["Origin"]; present {
		origin := ""
		if len(vals) > 0 {
			origin = vals[0]
		}
		if len(vals) > 1 || !OriginAllowed(h.corsOrigins, origin) {
			// Ingen CORS-headere på avvisningen, selv om en middleware skulle ha satt dem.
			for _, k := range []string{"Access-Control-Allow-Origin", "Access-Control-Allow-Credentials", "Access-Control-Allow-Methods", "Access-Control-Allow-Headers"} {
				w.Header().Del(k)
			}
			_ = r.ParseForm()
			logged := sanitizeOrigin(strings.Join(vals, ","))
			slog.Warn("refresh avvist: origin", "origin", logged, "ip", ip)
			// Audit bare når et refresh-token faktisk er presentert, slik at
			// anonyme kall ikke gir DB-skriving.
			if c, err := r.Cookie("refresh_token"); (err == nil && c.Value != "") || r.PostFormValue("refresh_token") != "" {
				h.aud.Log(r.Context(), audit.Event{Type: "refresh_invalid_origin", Details: "origin=" + logged, IP: ip, UA: ua, Success: false})
			}
			writeTokenError(w, http.StatusForbidden, "invalid_origin")
			return
		}
	}
	_ = r.ParseForm()

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

// sanitizeOrigin fjerner kontrolltegn og kutter til 200 tegn; Origin er
// klientstyrt og havner i logg og audit.
func sanitizeOrigin(o string) string {
	o = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, o)
	if len(o) > 200 {
		o = o[:200]
	}
	return strings.ToValidUTF8(o, "")
}
