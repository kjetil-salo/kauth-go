package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/auth"
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

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }
