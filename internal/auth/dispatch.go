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

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/fetchmeta"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

// DispatchHandler håndterer post-login routing og utlogging.
type DispatchHandler struct {
	Registry     *service.Registry
	Issuer       *token.Issuer
	Queries      *gen.Queries
	Audit        *audit.Service        // nil tillatt: da logges mismatch bare via slog
	DefaultSvcID string                // ID til default-tjeneste for cookie-navn
	Refresh      *token.RefreshService // nil tillatt: da revokeres ikke familien ved logout
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
	claims, err := h.Issuer.Verify(jwtToken, token.ExpectAccess)
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
	cleared := false
	clearRedirect := func() {
		if !cleared {
			cleared = true
			http.SetCookie(w, clearRedirectCookie)
		}
	}

	// En redirect_uri-cookie slettes uansett hvilket nivå som ruter, også
	// OIDC-nivå 0 som aldri leser den: ellers overlever en plantet cookie en
	// OIDC-runde og slår til ved neste vanlige innlogging.
	if _, err := r.Cookie("redirect_uri"); err == nil {
		clearRedirect()
	}

	// Nivå 0: standard OIDC authorization_code-flyt. oidc_authz-cookien ble
	// satt av LoginHandler.ServeLogin når forespørselen inneholdt
	// response_type=code&client_id=... — men cookien er USIGNERT (samme
	// tillitsmodell som redirect_uri-cookien), så alt den sier gjennomkjøres
	// på nytt her, der den faktisk brukes:
	//
	//  1. service-ID-en personen faktisk logget inn på (?service=, satt av
	//     alle fire login-handlerne) må være IDENTISK med oidcReq.ClientID.
	//     Uten denne sjekken kan en avbrutt OIDC-runde (cookien lever i 10
	//     min) kapre en helt urelatert påfølgende innlogging: person starter
	//     OIDC mot klient A, avbryter, logger inn på intern tjeneste B —
	//     uten sjekken ville /dispatch ha utstedt en A-kode for B sin
	//     innlogging, og B sine egne require_role/enforce_org-regler (som
	//     evalueres i login-handleren for B, ikke her) blir aldri vurdert
	//     for A. Se ServeLogin, som i tillegg rydder cookien proaktivt i
	//     ikke-OIDC-grenen — dette er andre laget i samme forsvar.
	//  2. redirect_uri verifiseres mot tjenestens allowlist på nytt, av
	//     samme grunn — /login sin validering er ikke noe /dispatch kan
	//     stole på en usignert cookie for å ha faktisk skjedd.
	if oidcReq, ok := ReadOIDCAuthorizeCookie(r); ok {
		ClearOIDCAuthorizeCookie(w)
		svc := h.Registry.Resolve("", oidcReq.ClientID, "")
		if svc == nil || q.Get("service") != oidcReq.ClientID || !h.Registry.IsAllowedCallback(svc, oidcReq.RedirectURI) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		// Cookien er usignert, så resource revalideres her — der den faktisk
		// brukes — på samme måte som client_id og redirect_uri over. Uten
		// dette kunne en håndlaget cookie plassert en vilkårlig streng i aud.
		if !ValidResourceIndicator(oidcReq.Resource) {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		code, err := GenerateAuthorizationCode()
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		expiresAt := time.Now().UTC().Add(60 * time.Second).Format("2006-01-02T15:04:05Z")
		err = h.Queries.InsertAuthorizationCode(r.Context(), gen.InsertAuthorizationCodeParams{
			Code:                token.HashOpaque(code),
			ServiceID:           oidcReq.ClientID,
			Email:               claims.Email,
			RedirectUri:         oidcReq.RedirectURI,
			Scope:               nullableStr(oidcReq.Scope),
			Nonce:               nullableStr(oidcReq.Nonce),
			CodeChallenge:       oidcReq.CodeChallenge,
			CodeChallengeMethod: oidcReq.CodeChallengeMethod,
			CreatedAt:           time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			ExpiresAt:           expiresAt,
			Resource:            nullableStr(oidcReq.Resource),
		})
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		target, err := buildRedirectWithCode(oidcReq.RedirectURI, code, oidcReq.State)
		if err != nil {
			http.Error(w, "intern feil", http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, target, http.StatusSeeOther)
		return
	}

	// Nivå 1: eksplisitt redirect_uri fra cookie. Cookien er usignert og kan
	// plantes av hvem som helst via ?redirect_uri=, så bare en verdi som er
	// eksakt lik en registrert callback_url godtas. Ingen intern-sti-gren:
	// nettlesere tolker `/\evil.example` som `//evil.example`, så enhver
	// prefiksvurdering av stier er en open redirect. Alt annet ignoreres og
	// rutingen faller videre til nivå 2-5.
	if redirectURI := readRedirectCookie(r); redirectURI != "" {
		var target *gen.Service
		loginSvc := q.Get("service")
		sharedWithLogin := false
		for _, svc := range h.Registry.All() {
			if !h.Registry.IsAllowedCallback(svc, redirectURI) {
				continue
			}
			if target == nil {
				target = svc
			}
			// Flere tjenester kan dele callback (klarsyn/analyse): da er det
			// ingen mismatch så lenge innloggingstjenesten er blant dem.
			if svc.ID == loginSvc {
				sharedWithLogin = true
			}
		}
		if target != nil {
			if !sharedWithLogin {
				h.logServiceMismatch(r, claims.Email, loginSvc, target.ID)
			}
			http.Redirect(w, r, appendTokenAndRT(redirectURI, jwtToken, rt), http.StatusSeeOther)
			return
		}
	}

	// Nivå 2: verifisert service-ID fra login-flyten.
	// Login-handlerne kjenner tjenesten presist (HMAC-signert state for OIDC,
	// resolvet tjeneste for magic/passord) og sender den hit. Uten den må vi
	// gjette ut fra org-claims, og en bruker uten tjenestens default_org
	// havner da på feil tjeneste.
	if svcID := q.Get("service"); svcID != "" {
		if svc := h.Registry.Resolve("", svcID, ""); svc != nil {
			clearRedirect()
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
				clearRedirect()
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
				clearRedirect()
				http.Redirect(w, r, appendTokenAndRT(svc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
				return
			}
		}
	}

	// Nivå 5: fallback til default-tjenestens callback
	defaultSvc := h.Registry.ResolveOrDefault("", h.DefaultSvcID, "")
	if defaultSvc != nil {
		clearRedirect()
		http.Redirect(w, r, appendTokenAndRT(defaultSvc.CallbackUrl, jwtToken, rt), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// logServiceMismatch registrerer at nivå 1 sender brukeren til en callback som
// tilhører en annen tjeneste enn den brukeren logget inn mot. Bare logging: Lars har
// bestemt at redirecten ikke skal håndheves før wspekto-flyten er rettet (L4).
// Verken token, rt eller cookie-verdi skal inn her — kun tjeneste-ID-er.
// ?service= er et klientstyrt hint, så loggen er ikke komplett deteksjon: den
// fanger plantet cookie der login-handleren selv har satt service.
func (h *DispatchHandler) logServiceMismatch(r *http.Request, email, loginSvc, targetSvc string) {
	// Klientstyrt: renses, og siteres i Details så mellomrom ikke kan forfalske felt.
	loginSvc = sanitizeLogValue(loginSvc)
	slog.Warn("redirect_service_mismatch", "login_service", loginSvc, "target_service", targetSvc)
	if h.Audit == nil {
		return
	}
	// ServiceID skal bare peke på en ekte tjeneste.
	svcID := ""
	if loginSvc != "" && h.Registry.Resolve("", loginSvc, "") != nil {
		svcID = loginSvc
	}
	h.Audit.Log(r.Context(), audit.Event{
		Type:      "redirect_service_mismatch",
		Email:     email,
		ServiceID: svcID,
		IP:        ClientIP(r),
		UA:        r.Header.Get("User-Agent"),
		Success:   true,
		Details:   fmt.Sprintf("login_service=%q target_service=%q", loginSvc, targetSvc),
	})
}

// ServeLogout håndterer GET /logout.
// Sletter auth_token og refresh_token, redirecter til redirect_uri eller /login.
func (h *DispatchHandler) ServeLogout(w http.ResponseWriter, r *http.Request) {
	// Cross-site underressurs eller iframe skal ikke logge brukeren ut. Da
	// rører vi hverken familie eller cookies (en sletting ville uansett ikke
	// virke pålitelig cross-site, og ville etterlatt en levende familie uten eier).
	if !fetchmeta.LogoutAllowed(r) {
		slog.Info("logout: cross-site forespørsel avvist uten revokering",
			"sec_fetch_site", r.Header.Get("Sec-Fetch-Site"),
			"sec_fetch_mode", r.Header.Get("Sec-Fetch-Mode"),
			"sec_fetch_dest", r.Header.Get("Sec-Fetch-Dest"))
		h.redirectAfterLogout(w, r)
		return
	}

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

	// Familien revokeres før cookien slettes, ellers er tokenet allerede borte
	// fra requesten. Feil her skal aldri hindre at brukeren blir logget ut.
	h.revokeRefreshFamily(r)

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

	h.redirectAfterLogout(w, r)
}

// redirectAfterLogout sender til oppgitt redirect_uri hvis den er registrert,
// ellers /login. Felles for tillatt og avvist logout, slik at svaret ikke
// røper hvilken vei forespørselen tok.
func (h *DispatchHandler) redirectAfterLogout(w http.ResponseWriter, r *http.Request) {
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

// revokeRefreshFamily revokerer familien til refresh_token-cookien, hvis den
// finnes og er kjent. Uten cookie eller med ukjent verdi skjer ingenting.
func (h *DispatchHandler) revokeRefreshFamily(r *http.Request) {
	if h.Refresh == nil {
		return
	}
	c, err := r.Cookie("refresh_token")
	if err != nil || c.Value == "" {
		return
	}
	email, svcID, ok := h.Refresh.RevokeFamilyOfToken(r.Context(), c.Value, "user_logout")
	if !ok || h.Audit == nil {
		return
	}
	// WithoutCancel: auditen skal overleve at klienten kobler fra.
	h.Audit.Log(context.WithoutCancel(r.Context()), audit.Event{
		Type:      "user_logout",
		Email:     email,
		ServiceID: svcID,
		IP:        ClientIP(r),
		UA:        r.Header.Get("User-Agent"),
		Success:   true,
	})
}
