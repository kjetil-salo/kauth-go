package auth

import (
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// DispatchHandler håndterer post-login routing og utlogging.
type DispatchHandler struct {
	Registry     *service.Registry
	Issuer       *token.Issuer
	Queries      *gen.Queries
	DefaultSvcID string // ID til default-tjeneste for cookie-navn
}

// nullableStr returnerer nil for tom streng, ellers en peker til strengen —
// for felter som er NULL-bare i databasen (sqlc emit_pointers_for_null_types).
func nullableStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// readRedirectCookie leser og URL-dekoder redirect_uri-cookien.
func readRedirectCookie(r *http.Request) string {
	c, err := r.Cookie("redirect_uri")
	if err != nil {
		return ""
	}
	v, _ := url.QueryUnescape(c.Value)
	return strings.Trim(v, `"`)
}

// appendTokenAndRT bygger endelig redirect-URL med token som query-param og rt som fragment.
func appendTokenAndRT(target, token, rt string) string {
	sep := "?"
	if strings.Contains(target, "?") {
		sep = "&"
	}
	u := target + sep + "token=" + url.QueryEscape(token)
	if rt != "" {
		u += "#rt=" + url.QueryEscape(rt)
	}
	return u
}

// ServeDispatch håndterer GET /dispatch.
// Leser token og rt fra URL query-params (ikke cookies — cross-host cookies virker ikke).
// Fem-nivå routing, mest presise kilde først:
//  1. redirect_uri-cookie → IsAllowedCallback → redirect med ?token=#rt (slett cookie)
//  2. ?service= — verifisert service-ID fra login-flyten → redirect CallbackUrl
//  3. host-header → match mot service.AuthHost → redirect CallbackUrl
//  4. token-claim org → match mot service.DefaultOrg → redirect CallbackUrl
//  5. Fallback til default-tjenestens CallbackUrl
func (h *DispatchHandler) ServeDispatch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	jwtToken := q.Get("token")
	rt := q.Get("rt")

	// Mangler token → tilbake til login
	if jwtToken == "" {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	// Verifiser token
	claims, err := h.Issuer.Verify(jwtToken)
	if err != nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	clearRedirectCookie := &http.Cookie{
		Name:     "redirect_uri",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	}

	// Nivå 0: standard OIDC authorization_code-flyt. oidc_authz-cookien ble
	// satt av LoginHandler.ServeLogin når forespørselen inneholdt
	// response_type=code&client_id=... — redirect_uri og (ev.) PKCE-krav er
	// allerede validert der. Her genereres selve koden og brukeren sendes
	// til klientens redirect_uri med ?code=&state=, IKKE med et token i
	// klartekst — koden løses inn på /token (grant_type=authorization_code).
	if oidcReq, ok := ReadOIDCAuthorizeCookie(r); ok {
		ClearOIDCAuthorizeCookie(w)
		code, err := GenerateAuthorizationCode()
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		expiresAt := time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z")
		err = h.Queries.InsertAuthorizationCode(r.Context(), gen.InsertAuthorizationCodeParams{
			Code:                code,
			ServiceID:           oidcReq.ClientID,
			Email:               claims.Email,
			RedirectUri:         oidcReq.RedirectURI,
			Scope:               nullableStr(oidcReq.Scope),
			Nonce:               nullableStr(oidcReq.Nonce),
			CodeChallenge:       nullableStr(oidcReq.CodeChallenge),
			CodeChallengeMethod: nullableStr(oidcReq.CodeChallengeMethod),
			CreatedAt:           time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			ExpiresAt:           expiresAt,
		})
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		target := oidcReq.RedirectURI + "?code=" + url.QueryEscape(code)
		if oidcReq.State != "" {
			target += "&state=" + url.QueryEscape(oidcReq.State)
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}

	// Nivå 1: eksplisitt redirect_uri fra cookie
	if redirectURI := readRedirectCookie(r); redirectURI != "" {
		// Intern path (starter med / men ikke //) → ingen allowlist-sjekk nødvendig.
		// Dobbel-skråstrek (//) ville vært protokoll-relativ URL og potensielt open redirect.
		if strings.HasPrefix(redirectURI, "/") && !strings.HasPrefix(redirectURI, "//") {
			http.SetCookie(w, clearRedirectCookie)
			sep := "?"
			if strings.Contains(redirectURI, "?") {
				sep = "&"
			}
			http.Redirect(w, r, redirectURI+sep+"token="+url.QueryEscape(jwtToken), http.StatusSeeOther)
			return
		}
		// Ekstern URL → eksisterende allowlist-sjekk
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if h.Registry.IsAllowedCallback(svc, redirectURI) {
				http.SetCookie(w, clearRedirectCookie)
				http.Redirect(w, r, appendTokenAndRT(redirectURI, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 2: verifisert service-ID fra login-flyten.
	// Login-handlerne kjenner tjenesten presist (HMAC-signert state for OIDC,
	// resolvet tjeneste for magic/passord) og sender den hit. Uten den må vi
	// gjette ut fra org-claims, og en bruker uten tjenestens default_org
	// havner da på feil tjeneste.
	if svcID := q.Get("service"); svcID != "" {
		if svc := h.Registry.Resolve("", svcID, ""); svc != nil {
			http.SetCookie(w, clearRedirectCookie)
			http.Redirect(w, r, appendTokenAndRT(svc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
			return
		}
	}

	// Nivå 3: host-match — bruker kom inn via en service-spesifikk auth-host
	// (auth.spekto.live → spekto, auth.lilleklo.work → vinkjeller).
	// Dette må vinne over org-match for at f.eks. en konge med "lars" i orgs
	// som logger inn på auth.spekto.live skal lande på spekto-app, ikke klarsyn.
	if r.Host != "" {
		hostLc := strings.ToLower(r.Host)
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if svc.AuthHost != nil && strings.ToLower(*svc.AuthHost) == hostLc {
				http.SetCookie(w, clearRedirectCookie)
				http.Redirect(w, r, appendTokenAndRT(svc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 4: org-match via JWT-claims
	allSvcs := h.Registry.All()
	for _, svc := range allSvcs {
		if svc.DefaultOrg == nil {
			continue
		}
		for _, org := range claims.Org {
			if org == *svc.DefaultOrg {
				http.SetCookie(w, clearRedirectCookie)
				http.Redirect(w, r, appendTokenAndRT(svc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 5: fallback til default-tjenestens callback
	defaultSvc := h.Registry.ResolveOrDefault("", h.DefaultSvcID, "")
	if defaultSvc != nil {
		http.SetCookie(w, clearRedirectCookie)
		http.Redirect(w, r, appendTokenAndRT(defaultSvc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ServeLogout håndterer GET /logout.
// Sletter auth_token og refresh_token, redirecter til redirect_uri eller /login.
func (h *DispatchHandler) ServeLogout(w http.ResponseWriter, r *http.Request) {
	defaultSvc := h.Registry.ResolveOrDefault("", h.DefaultSvcID, "")

	// Slett auth_token-cookie
	cookieName := "auth_token"
	if defaultSvc != nil {
		cookieName = defaultSvc.JwtCookieName
	}
	http.SetCookie(w, &http.Cookie{
		Name:     cookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	})

	// Slett refresh_token-cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   0,
		HttpOnly: true,
		Secure:   os.Getenv("KAUTH_INSECURE_COOKIES") != "true",
		SameSite: http.SameSiteLaxMode,
	})

	// Redirect til oppgitt URI hvis den er registrert, ellers /login
	if redirectURI := r.URL.Query().Get("redirect_uri"); redirectURI != "" {
		allSvcs := h.Registry.All()
		for _, svc := range allSvcs {
			if h.Registry.IsAllowedCallback(svc, redirectURI) {
				http.Redirect(w, r, redirectURI, http.StatusSeeOther)
				return
			}
		}
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
