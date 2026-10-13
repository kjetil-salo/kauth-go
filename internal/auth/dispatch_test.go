package auth_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

func sPtr(s string) *string { return &s }

// dispatchFixture speiler prod-oppsettet: flere tjenester der brukerens orgs
// ikke sier noe om hvilken tjeneste han faktisk logget inn på.
// Rekkefølgen er som ListActiveServices (ORDER BY display_name).
func dispatchFixture() []gen.Service {
	return []gen.Service{
		{ID: "analyse", Domain: "analyse.klarsyn.net", DefaultOrg: sPtr("lars"),
			CallbackUrl: "https://analyse.klarsyn.net/auth/callback"},
		{ID: "klarsyn", Domain: "klarsyn.net", DefaultOrg: sPtr("lars"), IsDefault: 1,
			CallbackUrl: "https://klarsyn.net/auth/callback"},
		{ID: "vinkjeller", Domain: "kjeller.lilleklo.work", DefaultOrg: sPtr("vinkjeller"),
			CallbackUrl: "https://kjeller.lilleklo.work/auth/callback"},
	}
}

func newDispatchHandler(t *testing.T) (*auth.DispatchHandler, *token.Issuer) {
	t.Helper()
	iss := token.NewIssuerForTest()
	return &auth.DispatchHandler{
		Registry:     service.NewRegistryForTest(dispatchFixture()),
		Issuer:       iss,
		DefaultSvcID: "klarsyn",
	}, iss
}

// Regresjonstest: en bruker med orgs "playground, vinkjeller" logger
// inn på klarsyn. Org-claims peker mot vinkjeller, men login-flyten vet at
// tjenesten er klarsyn — den verifiserte service-IDen skal vinne.
func TestDispatch_VerifiedServiceIDBeatsOrgGuess(t *testing.T) {
	h, iss := newDispatchHandler(t)
	user := gen.User{Email: "bruker@example.com", Orgs: "playground, vinkjeller", Roles: "admin"}
	at, err := iss.IssueAccess(user, dispatchFixture()[1]) // klarsyn
	if err != nil {
		t.Fatalf("kunne ikke utstede token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at+"&service=klarsyn", nil)
	req.Host = "auth.klarsyn.net"
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)

	loc := w.Header().Get("Location")
	if got := w.Code; got != http.StatusSeeOther && got != http.StatusFound {
		t.Fatalf("forventet redirect, fikk %d", got)
	}
	if !hasPrefix(loc, "https://klarsyn.net/auth/callback") {
		t.Fatalf("skulle landet på klarsyn, havnet på: %s", loc)
	}
}

// En ukjent service-ID skal ikke kunne styre routingen.
func TestDispatch_UnknownServiceIDIgnored(t *testing.T) {
	h, iss := newDispatchHandler(t)
	user := gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}
	at, err := iss.IssueAccess(user, dispatchFixture()[1])
	if err != nil {
		t.Fatalf("kunne ikke utstede token: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at+"&service=finnes-ikke", nil)
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)

	loc := w.Header().Get("Location")
	if loc == "" || hasPrefix(loc, "/login") {
		t.Fatalf("skulle falt tilbake til en gyldig tjeneste, fikk: %s", loc)
	}
	for _, svc := range dispatchFixture() {
		if hasPrefix(loc, svc.CallbackUrl) {
			return // landet på en registrert tjeneste — greit
		}
	}
	t.Fatalf("landet utenfor registrerte callbacks: %s", loc)
}

// R5: /dispatch veksler bare access-tokens. Id-token og admin-token i ?token=
// sendes til /login og gir aldri redirect til en tjeneste.
func TestDispatch_RejectsNonAccessTokens(t *testing.T) {
	h, iss := newDispatchHandler(t)
	user := gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}
	idTok, err := iss.IssueIDToken(user, dispatchFixture()[1], "n")
	if err != nil {
		t.Fatalf("id-token: %v", err)
	}
	adminTok, err := iss.IssueAdmin(user, time.Hour)
	if err != nil {
		t.Fatalf("admin-token: %v", err)
	}
	for name, tok := range map[string]string{"id": idTok, "admin": adminTok} {
		req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+tok+"&service=klarsyn", nil)
		w := httptest.NewRecorder()
		h.ServeDispatch(w, req)
		if loc := w.Header().Get("Location"); loc != "/login" {
			t.Errorf("%s-token: forventet redirect til /login, fikk %q", name, loc)
		}
	}
}

var protoRelative = regexp.MustCompile(`^(https?:)?[/\\]{2}`)

var (
	cookieOnce sync.Once
	cookieH    *auth.DispatchHandler
	cookieTok  string
)

func dispatchWithCookie(t *testing.T, cookie, query string) *httptest.ResponseRecorder {
	t.Helper()
	// Nøkkelgenerering er dyr, så handler og token deles mellom tabellradene.
	cookieOnce.Do(func() {
		var iss *token.Issuer
		cookieH, iss = newDispatchHandler(t)
		user := gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}
		var err error
		if cookieTok, err = iss.IssueAccess(user, dispatchFixture()[1]); err != nil {
			t.Fatalf("token: %v", err)
		}
	})
	h, at := cookieH, cookieTok
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at+query, nil)
	if cookie != "" {
		req.Header.Set("Cookie", "redirect_uri="+cookie)
	}
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)
	return w
}

func redirectCookieClears(w *httptest.ResponseRecorder) []*http.Cookie {
	var out []*http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == "redirect_uri" {
			out = append(out, c)
		}
	}
	return out
}

// Cookien er usignert og kan plantes av en angriper; ingen verdi som ikke er
// eksakt lik en registrert callback_url skal påvirke Location.
func TestDispatch_RedirectCookieRejected(t *testing.T) {
	registered := map[string]bool{}
	for _, s := range dispatchFixture() {
		registered[s.CallbackUrl] = true
	}
	cases := map[string]string{
		"backslash":            `/%5Cevil.example`,
		"slash-backslash":      `/\evil.example`,
		"encoded-backslash":    `%2F%5Cevil.example`,
		"double-slash":         `//evil.example`,
		"encoded-double-slash": `/%2F%2Fevil.example`,
		"double-backslash":     `\\evil.example`,
		"encoded-dbl-bslash":   `%5C%5Cevil.example`,
		"tab":                  `/%09/evil.example`,
		"newline":              `/%0A/evil.example`,
		"cr":                   `/%0D/evil.example`,
		"nul":                  `/%00/evil.example`,
		"ctrl-in-path":         `/%01%1F%7Fevil`,
		"crlf-injection":       `/x%0D%0ASet-Cookie:%20a=b`,
		"admin-google":         `/admin/google-callback`,
		"relative":             `/relativ/sti`,
		"relative-no-slash":    `relativ/sti`,
		"root":                 `/`,
		"external":             `https://evil.example/auth/callback`,
		"proto-relative-https": `https:evil.example`,
		"trailing-slash":       `https://analyse.klarsyn.net/auth/callback/`,
		"query":                `https://analyse.klarsyn.net/auth/callback?x=1`,
		"host-casing":          `https://ANALYSE.klarsyn.net/auth/callback`,
		"scheme-casing":        `HTTPS://analyse.klarsyn.net/auth/callback`,
		"userinfo":             `https://analyse.klarsyn.net@evil.example/auth/callback`,
		"javascript":           `javascript:alert(1)`,
	}
	for name, cookie := range cases {
		for _, tc := range []struct{ label, query string }{{"med-service", "&service=klarsyn"}, {"uten-service", ""}} {
			t.Run(name+"/"+tc.label, func(t *testing.T) {
				w := dispatchWithCookie(t, cookie, tc.query)
				loc := w.Header().Get("Location")
				if w.Code != http.StatusSeeOther {
					t.Fatalf("forventet 303, fikk %d", w.Code)
				}
				// JWT-en i query kan tilfeldig inneholde «evil», så sjekk uten query.
				noQuery, _, _ := strings.Cut(loc, "?")
				if strings.Contains(noQuery, "evil") {
					t.Fatalf("Location peker mot cookie-verdien: %q", loc)
				}
				u, err := url.Parse(loc)
				if err != nil {
					t.Fatalf("Location kan ikke parses: %q", loc)
				}
				u.RawQuery, u.Fragment = "", ""
				if u.Host == "" {
					// Regexen gjelder Location uten registrert vert: tom-vert skal være /login.
					if protoRelative.MatchString(loc) || u.Path != "/login" {
						t.Fatalf("tom vert, men ikke /login: %q", loc)
					}
				} else if !registered[u.String()] {
					t.Fatalf("Location er ikke en registrert callback: %q", loc)
				}
				if tc.query != "" && !hasPrefix(loc, "https://klarsyn.net/auth/callback?token=") {
					t.Fatalf("skulle falt til nivå 2: %q", loc)
				}
				// Avvist cookie slettes også, så den ikke henger igjen.
				cs := redirectCookieClears(w)
				if len(cs) != 1 || cs[0].MaxAge != -1 {
					t.Fatalf("forventet nøyaktig én sletting (MaxAge=-1), fikk %+v", cs)
				}
			})
		}
	}
}

// R2: eksakt registrert callback rutes som før, og cookien slettes med
// samme attributter som da den ble satt.
func TestDispatch_RedirectCookieExactCallbackAccepted(t *testing.T) {
	t.Setenv("KAUTH_INSECURE_COOKIES", "")
	for _, cookie := range []string{
		"https://analyse.klarsyn.net/auth/callback",
		url.QueryEscape("https://analyse.klarsyn.net/auth/callback"),
	} {
		w := dispatchWithCookie(t, cookie, "&service=klarsyn")
		loc := w.Header().Get("Location")
		if !hasPrefix(loc, "https://analyse.klarsyn.net/auth/callback?token=") {
			t.Fatalf("cookie %q: fikk %q", cookie, loc)
		}
		cs := redirectCookieClears(w)
		if len(cs) != 1 || cs[0].MaxAge != -1 || cs[0].Path != "/" || !cs[0].HttpOnly || !cs[0].Secure || cs[0].SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie skal slettes med samme attributter: %+v", cs)
		}
	}
}

func TestDispatch_RedirectCookieExactCallbackWithRT(t *testing.T) {
	w := dispatchWithCookie(t, "https://klarsyn.net/auth/callback", "&rt=abc")
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "?token=") || !strings.HasSuffix(loc, "#rt=abc") || !hasPrefix(loc, "https://klarsyn.net/auth/callback") {
		t.Fatalf("forventet ?token=…#rt=abc, fikk %q", loc)
	}
}

// Uten cookie er nivå 2-5 uendret. Nivå 2-5 rydder alltid cookien (også uten
// at den fantes), så sletting forventes i begge kall.
func TestDispatch_NoCookieLevelsUnchanged(t *testing.T) {
	w := dispatchWithCookie(t, "", "&service=vinkjeller")
	if loc := w.Header().Get("Location"); !hasPrefix(loc, "https://kjeller.lilleklo.work/auth/callback?token=") {
		t.Fatalf("nivå 2: %q", loc)
	}
	if cs := redirectCookieClears(w); len(cs) != 1 {
		t.Fatalf("forventet én sletting, fikk %d", len(cs))
	}
	w = dispatchWithCookie(t, "", "")
	if loc := w.Header().Get("Location"); !hasPrefix(loc, "https://analyse.klarsyn.net/auth/callback?token=") {
		t.Fatalf("nivå 4: %q", loc)
	}
	if cs := redirectCookieClears(w); len(cs) != 1 {
		t.Fatalf("nivå 4: forventet én sletting, fikk %d", len(cs))
	}
}

// En cookie som er lest, slettes selv når ingen nivå ruter: tomt register
// gjør at rutingen ender i /login uten at nivå 2-5 setter noe.
func TestDispatch_RejectedCookieClearedWithEmptyRegistry(t *testing.T) {
	_, iss := newDispatchHandler(t)
	h := &auth.DispatchHandler{Registry: service.NewRegistryForTest(nil), Issuer: iss, DefaultSvcID: "klarsyn"}
	at, err := iss.IssueAccess(gen.User{Email: "k@example.com", Orgs: "lars", Roles: "konge"}, dispatchFixture()[1])
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at, nil)
	req.Header.Set("Cookie", `redirect_uri=/%5Cevil.example`)
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Fatalf("forventet /login, fikk %q", loc)
	}
	if cs := redirectCookieClears(w); len(cs) != 1 || cs[0].MaxAge != -1 {
		t.Fatalf("forventet én sletting med MaxAge=-1, fikk %+v", cs)
	}
}

// Nivå 0 returnerer før nivå 1, men skal likevel slette en gammel cookie.
func TestDispatch_OIDCLevelClearsRedirectCookie(t *testing.T) {
	h, iss := newDispatchHandler(t)
	at, err := iss.IssueAccess(gen.User{Email: "k@example.com", Orgs: "lars", Roles: "konge"}, dispatchFixture()[1])
	if err != nil {
		t.Fatal(err)
	}
	cw := httptest.NewRecorder()
	// Ukjent klient gir /login i nivå 0 uten databasetilgang.
	auth.SetOIDCAuthorizeCookie(cw, auth.OIDCAuthorizeRequest{ClientID: "ukjent", RedirectURI: "https://x.example/cb"})
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+at+"&service=klarsyn", nil)
	for _, c := range cw.Result().Cookies() {
		req.AddCookie(c)
	}
	req.AddCookie(&http.Cookie{Name: "redirect_uri", Value: "/%5Cevil.example"})
	w := httptest.NewRecorder()
	h.ServeDispatch(w, req)
	if loc := w.Header().Get("Location"); loc != "/login" {
		t.Fatalf("forventet /login, fikk %q", loc)
	}
	if cs := redirectCookieClears(w); len(cs) != 1 || cs[0].MaxAge != -1 {
		t.Fatalf("forventet én sletting med MaxAge=-1, fikk %+v", cs)
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// ── F9 / R21: tjenestemismatch på nivå 1 logges, men rutingen er uendret ──

type mismatchFixture struct {
	h    *auth.DispatchHandler
	q    *gen.Queries
	tok  string
	logs *strings.Builder
}

func newMismatchFixture(t *testing.T) *mismatchFixture {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqldb.Close() })
	// :memory: gir en egen tom database per tilkobling, og audit skriver fra en goroutine.
	sqldb.SetMaxOpenConns(1)

	svcs := dispatchFixture()
	// Delt callback: klarsyn og analyse peker begge til samme URL.
	shared := "https://shared.klarsyn.net/auth/callback"
	svcs[0].CallbackUrl = shared
	svcs[1].CallbackUrl = shared
	iss := token.NewIssuerForTest()
	tok, err := iss.IssueAccess(gen.User{Email: "konge@example.com", Orgs: "lars", Roles: "konge"}, svcs[1])
	if err != nil {
		t.Fatal(err)
	}

	// slog.SetDefault er global: mismatch-testene må ikke kjøres med t.Parallel().
	logs := &strings.Builder{}
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(logs, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })

	return &mismatchFixture{
		h: &auth.DispatchHandler{
			Registry: service.NewRegistryForTest(svcs), Issuer: iss,
			Audit: audit.NewService(q), DefaultSvcID: "klarsyn",
		},
		q: q, tok: tok, logs: logs,
	}
}

func (f *mismatchFixture) dispatch(cookie, query string) string {
	req := httptest.NewRequest(http.MethodGet, "/dispatch?token="+f.tok+query, nil)
	req.Header.Set("Cookie", "redirect_uri="+url.QueryEscape(cookie))
	w := httptest.NewRecorder()
	f.h.ServeDispatch(w, req)
	return w.Header().Get("Location")
}

func (f *mismatchFixture) events(t *testing.T) []gen.AuditEvent {
	t.Helper()
	// Audit.Log er asynkron: gi eventuelle events tid til å lande før vi teller.
	time.Sleep(200 * time.Millisecond)
	all, err := f.q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []gen.AuditEvent
	for _, e := range all {
		if e.EventType == "redirect_service_mismatch" {
			out = append(out, e)
		}
	}
	return out
}

const vinCallback = "https://kjeller.lilleklo.work/auth/callback"

// AK9.1 + AK9.4: A/B-mismatch gir ett event med begge ID-er og uendret Location.
func TestDispatchMismatch_LogsOneEventAndRedirectUnchanged(t *testing.T) {
	f := newMismatchFixture(t)
	loc := f.dispatch(vinCallback, "&service=klarsyn&rt=hemmelig-rt")
	if want := vinCallback + "?token=" + f.tok + "#rt=hemmelig-rt"; loc != want {
		t.Fatalf("Location endret: %q", loc)
	}
	evs := f.events(t)
	if len(evs) != 1 {
		t.Fatalf("forventet ett event, fikk %d", len(evs))
	}
	d := ""
	if evs[0].Details != nil {
		d = *evs[0].Details
	}
	if !strings.Contains(d, "klarsyn") || !strings.Contains(d, "vinkjeller") {
		t.Errorf("details mangler tjeneste-ID-er: %q", d)
	}
	if evs[0].ServiceID == nil || *evs[0].ServiceID != "klarsyn" {
		t.Errorf("service_id skal være innloggingstjenesten: %v", evs[0].ServiceID)
	}
	for _, secret := range []string{f.tok, "hemmelig-rt", "redirect_uri", "token=", "rt="} {
		if strings.Contains(d, secret) || strings.Contains(f.logs.String(), secret) {
			t.Errorf("hemmelighet %q lekket til audit-details eller slog", secret)
		}
	}
	if !strings.Contains(f.logs.String(), "redirect_service_mismatch") {
		t.Errorf("forventet slog.Warn, fikk %q", f.logs.String())
	}
}

// AK9.2: samsvar og delt callback gir ingen event.
func TestDispatchMismatch_MatchAndSharedCallbackNoEvent(t *testing.T) {
	f := newMismatchFixture(t)
	if loc := f.dispatch(vinCallback, "&service=vinkjeller"); !hasPrefix(loc, vinCallback) {
		t.Fatalf("Location: %q", loc)
	}
	shared := "https://shared.klarsyn.net/auth/callback"
	for _, svc := range []string{"klarsyn", "analyse"} {
		if loc := f.dispatch(shared, "&service="+svc); !hasPrefix(loc, shared) {
			t.Fatalf("Location: %q", loc)
		}
	}
	if n := len(f.events(t)); n != 0 {
		t.Fatalf("forventet ingen events, fikk %d", n)
	}
}

// AK9.3: manglende ?service= gir event med tom innloggingstjeneste.
func TestDispatchMismatch_MissingServiceLogsEvent(t *testing.T) {
	f := newMismatchFixture(t)
	loc := f.dispatch(vinCallback, "")
	if !hasPrefix(loc, vinCallback+"?token=") {
		t.Fatalf("Location endret: %q", loc)
	}
	evs := f.events(t)
	if len(evs) != 1 {
		t.Fatalf("forventet ett event, fikk %d", len(evs))
	}
	if evs[0].ServiceID != nil {
		t.Errorf("tom innloggingstjeneste skal gi NULL service_id: %v", *evs[0].ServiceID)
	}
	if evs[0].Details == nil || !strings.Contains(*evs[0].Details, `target_service="vinkjeller"`) {
		t.Errorf("details: %v", evs[0].Details)
	}
}

// Klientstyrt ?service= kan ikke forfalske felt i Details eller peke ServiceID på en ukjent verdi.
func TestDispatchMismatch_ForgedServiceSanitized(t *testing.T) {
	f := newMismatchFixture(t)
	f.dispatch(vinCallback, "&service="+url.QueryEscape("x target_service=klarsyn\nfake=1"))
	evs := f.events(t)
	if len(evs) != 1 {
		t.Fatalf("forventet ett event, fikk %d", len(evs))
	}
	d := *evs[0].Details
	// Newline fjernes, og mellomrommet blir værende inne i siteringen.
	if want := `login_service="x target_service=klarsynfake=1" target_service="vinkjeller"`; d != want {
		t.Errorf("details = %s, vil ha %s", d, want)
	}
	if evs[0].ServiceID != nil {
		t.Errorf("ukjent tjeneste skal gi NULL service_id: %v", *evs[0].ServiceID)
	}
	if strings.Contains(f.logs.String(), "\nfake") {
		t.Errorf("newline slapp gjennom i slog: %q", f.logs.String())
	}
}

// Delt callback der innloggingstjenesten er en tredje: målet er første registrerte deler.
func TestDispatchMismatch_SharedCallbackOtherLoginReportsFirst(t *testing.T) {
	f := newMismatchFixture(t)
	f.dispatch("https://shared.klarsyn.net/auth/callback", "&service=vinkjeller")
	evs := f.events(t)
	if len(evs) != 1 {
		t.Fatalf("forventet ett event, fikk %d", len(evs))
	}
	if want := `login_service="vinkjeller" target_service="analyse"`; *evs[0].Details != want {
		t.Errorf("details = %s, vil ha %s", *evs[0].Details, want)
	}
}

// Avvist cookie (ikke registrert callback) gir ingen event.
func TestDispatchMismatch_RejectedCookieNoEvent(t *testing.T) {
	f := newMismatchFixture(t)
	f.dispatch("https://evil.example/cb", "&service=klarsyn")
	f.dispatch("/\\evil.example", "")
	if n := len(f.events(t)); n != 0 {
		t.Fatalf("forventet ingen events, fikk %d", n)
	}
}
