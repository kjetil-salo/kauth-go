package admin

import (
	"bytes"
	"context"
	"database/sql"
	"html"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// 007 F4 (H1): lagring av en tjeneste skal bare endre feltene som finnes i skjemaet.

type svcEnv struct {
	sqldb *sql.DB
	q     *gen.Queries
	reg   *service.Registry
	mux   http.Handler
}

func setupServicesEnv(t *testing.T) *svcEnv {
	t.Helper()
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	// :memory: gir en egen database per tilkobling; den asynkrone audit-skrivingen trenger samme.
	sqldb.SetMaxOpenConns(1)
	t.Cleanup(func() { sqldb.Close() })
	t.Chdir("../..") // templates/ ligger relativt til prosjektroten

	reg := service.NewRegistry(q)
	h := NewServicesHandler(q, reg, audit.NewService(q))
	r := chi.NewRouter()
	r.Get("/admin/services/{id}/edit", h.HandleEdit)
	r.Post("/admin/services/{id}", h.HandleUpdate)
	r.Post("/admin/services", h.HandleCreate)
	return &svcEnv{sqldb: sqldb, q: q, reg: reg, mux: r}
}

func sp(s string) *string { return &s }

func (e *svcEnv) seed(t *testing.T, id, domain string) {
	t.Helper()
	require.NoError(t, e.q.CreateService(context.Background(), gen.CreateServiceParams{
		ID:                    id,
		DisplayName:           "Seed " + id,
		Tagline:               sp("slagord"),
		Domain:                domain,
		AuthHost:              sp("auth." + domain),
		CallbackUrl:           "https://app." + domain + "/cb",
		LogoHtml:              sp(`<svg onload="x">logo & "q"</svg>`),
		BgImage:               sp("/bg.jpg"),
		BgCss:                 sp("linear-gradient(red, blue)"),
		Theme:                 "dark",
		AccentColor:           "#112233",
		EmailFromName:         "Seed",
		EmailFromAddress:      sp("noreply@" + domain),
		AutoRegister:          1,
		DefaultRole:           sp("user"),
		DefaultOrg:            sp("acme"),
		RequireRole:           sp("admin"),
		EnforceOrg:            1,
		IsDefault:             0,
		AuthGoogle:            1,
		AuthMicrosoft:         1,
		AuthMagicLink:         1,
		AuthPassword:          1,
		GoogleClientID:        sp("g-id-" + id),
		GoogleClientSecret:    sp("g-secret-" + id),
		MicrosoftClientID:     sp("m-id-" + id),
		MicrosoftClientSecret: sp("m-secret-" + id),
		JwtCookieName:         "tok",
		AccessTokenTtl:        "PT30M",
		RefreshTokenMaxAge:    sp("P30D"),
		Active:                1,
		UpdatedAt:             "2026-01-01T00:00:00Z",
	}))
}

func (e *svcEnv) row(t *testing.T, id string) gen.Service {
	t.Helper()
	all, err := e.q.ListAllServices(context.Background())
	require.NoError(t, err)
	for _, s := range all {
		if s.ID == id {
			return s
		}
	}
	t.Fatalf("tjeneste %s finnes ikke", id)
	return gen.Service{}
}

var (
	inputTagRe = regexp.MustCompile(`(?s)<input\b[^>]*>`)
	selectRe   = regexp.MustCompile(`(?s)<select\b[^>]*name="([^"]+)"[^>]*>(.*?)</select>`)
	optionRe   = regexp.MustCompile(`(?s)<option\b([^>]*)>`)
	attrRe     = regexp.MustCompile(`([a-zA-Z-]+)(?:="([^"]*)")?`)
)

func parseAttrs(tag string) map[string]string {
	m := map[string]string{}
	for _, a := range attrRe.FindAllStringSubmatch(tag, -1) {
		m[a[1]] = html.UnescapeString(a[2])
	}
	return m
}

// renderedFormValues rendrer redigeringsskjemaet og gjenskaper det en nettleser ville sendt:
// tekstfelt med value, avkryssede checkbokser og valgt option i select.
func (e *svcEnv) renderedFormValues(t *testing.T, id string) (url.Values, string) {
	t.Helper()
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/services/"+id+"/edit", nil))
	require.Equal(t, http.StatusOK, w.Code)
	body := w.Body.String()
	require.Contains(t, body, "</html>")
	return parseFormValues(t, body), body
}

// parseFormValues gjenskaper det en nettleser ville sendt fra et rendret skjema.
func parseFormValues(t *testing.T, body string) url.Values {
	t.Helper()
	vals := url.Values{}
	for _, tag := range inputTagRe.FindAllString(body, -1) {
		a := parseAttrs(tag)
		name := a["name"]
		if name == "" {
			continue
		}
		switch a["type"] {
		case "file", "submit", "button":
		case "checkbox":
			if _, ok := a["checked"]; ok {
				vals.Set(name, a["value"])
			}
		default:
			vals.Set(name, a["value"])
		}
	}
	for _, m := range selectRe.FindAllStringSubmatch(body, -1) {
		for _, o := range optionRe.FindAllStringSubmatch(m[2], -1) {
			oa := parseAttrs(o[1])
			if _, ok := oa["selected"]; ok {
				vals.Set(m[1], oa["value"])
			}
		}
	}
	return vals
}

func (e *svcEnv) postCreate(vals url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/services", strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

func (e *svcEnv) post(id string, vals url.Values) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/admin/services/"+id, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	return w
}

// AK4.1: uendret skjema-POST lar hele raden være lik, særlig ikke-skjemafeltene.
func TestServiceUpdate_UnchangedFormPreservesHiddenFields(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	e.seed(t, "beta", "beta.test")
	beforeAlpha := e.row(t, "alpha")
	beforeBeta := e.row(t, "beta")

	vals, body := e.renderedFormValues(t, "alpha")
	// Ingen secret-felt skal vises i skjemaet.
	for _, secret := range []string{"g-secret-alpha", "m-secret-alpha", "google_client_secret", "microsoft_client_secret"} {
		assert.NotContains(t, body, secret)
	}

	w := e.post("alpha", vals)
	require.Equal(t, http.StatusSeeOther, w.Code)

	afterAlpha := e.row(t, "alpha")
	assert.NotEqual(t, beforeAlpha.UpdatedAt, afterAlpha.UpdatedAt)
	// Alt unntatt updated_at er identisk, inkludert alle skjulte felt.
	beforeAlpha.UpdatedAt, afterAlpha.UpdatedAt = "", ""
	assert.Equal(t, beforeAlpha, afterAlpha)
	assert.Equal(t, "g-secret-alpha", *afterAlpha.GoogleClientSecret)
	assert.Equal(t, "m-secret-alpha", *afterAlpha.MicrosoftClientSecret)
	assert.Equal(t, `<svg onload="x">logo & "q"</svg>`, *afterAlpha.LogoHtml)
	assert.Equal(t, "linear-gradient(red, blue)", *afterAlpha.BgCss)

	// Tenant-isolasjon: den andre tjenesten er urørt.
	assert.Equal(t, beforeBeta, e.row(t, "beta"))
}

// AK4.2: require_role og enforce_org vises med eksisterende verdi.
func TestServiceEdit_RendersRequireRoleAndEnforceOrg(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	vals, _ := e.renderedFormValues(t, "alpha")
	assert.Equal(t, "admin", vals.Get("require_role"))
	assert.Equal(t, "1", vals.Get("enforce_org"))
}

// AK4.2/4.3: require_role og enforce_org kan endres og tømmes; tomt gir NULL.
func TestServiceUpdate_RequireRoleAndEnforceOrgEditable(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("require_role", "editor")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	got := e.row(t, "alpha")
	require.NotNil(t, got.RequireRole)
	assert.Equal(t, "editor", *got.RequireRole)
	assert.EqualValues(t, 1, got.EnforceOrg)

	vals.Set("require_role", "   ")
	vals.Del("enforce_org") // ikke avkrysset boks sendes ikke
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	got = e.row(t, "alpha")
	assert.Nil(t, got.RequireRole, "tomt require_role skal være NULL, ikke tom streng")
	assert.EqualValues(t, 0, got.EnforceOrg)

	vals.Set("enforce_org", "1")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	got = e.row(t, "alpha")
	assert.EqualValues(t, 1, got.EnforceOrg)
	// Skjulte felt overlevde alle tre lagringene.
	assert.Equal(t, "g-secret-alpha", *got.GoogleClientSecret)
}

// AK4.5: ukjent id gir 404 og ingen skriving.
func TestServiceUpdate_UnknownIDIs404AndWritesNothing(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals := url.Values{
		"display_name": {"X"}, "domain": {"x.test"}, "callback_url": {"https://x.test/cb"},
	}
	w := e.post("finnes-ikke", vals)
	assert.Equal(t, http.StatusNotFound, w.Code)

	assert.Equal(t, before, e.row(t, "alpha"))
	all, err := e.q.ListAllServices(context.Background())
	require.NoError(t, err)
	for _, s := range all {
		assert.NotEqual(t, "finnes-ikke", s.ID)
	}
}

// En deaktivert tjeneste kan fortsatt lagres og reaktiveres. GetServiceByID filtrerer på
// active = 1 og ville gitt 404 her.
func TestServiceUpdate_InactiveServiceCanBeReactivated(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	_, err := e.sqldb.Exec(`UPDATE services SET active = 0 WHERE id = 'alpha'`)
	require.NoError(t, err)

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("active", "1")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	got := e.row(t, "alpha")
	assert.EqualValues(t, 1, got.Active)
	assert.Equal(t, "g-secret-alpha", *got.GoogleClientSecret)
}

// Audit-event skrives uten secret-verdier, og registry-cachen viser nye skjemaverdier
// samtidig som de bevarte secrets.
func TestServiceUpdate_AuditAndRegistryCache(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	require.NoError(t, e.reg.Warmup(context.Background()))

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("display_name", "Nytt navn")
	vals.Set("require_role", "editor")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)

	var svc *gen.Service
	for _, s := range e.reg.All() {
		if s.ID == "alpha" {
			svc = s
		}
	}
	require.NotNil(t, svc)
	assert.Equal(t, "Nytt navn", svc.DisplayName)
	require.NotNil(t, svc.RequireRole)
	assert.Equal(t, "editor", *svc.RequireRole)
	require.NotNil(t, svc.GoogleClientSecret)
	assert.Equal(t, "g-secret-alpha", *svc.GoogleClientSecret)
	assert.Equal(t, "m-secret-alpha", *svc.MicrosoftClientSecret)

	// audit.Service skriver asynkront.
	var details string
	require.Eventually(t, func() bool {
		err := e.sqldb.QueryRow(
			`SELECT COALESCE(details,'') FROM audit_events WHERE event_type = 'service_edited' AND service_id = 'alpha'`,
		).Scan(&details)
		return err == nil
	}, 2*time.Second, 10*time.Millisecond)
	assert.NotContains(t, details, "secret")
	assert.NotContains(t, details, "g-id-alpha")
}

// A1: 422-siden ved update skal ikke miste felt. Admin retter feilen i det rendrede skjemaet
// og lagrer på nytt; hele raden skal da være lik seed-raden.
func TestServiceUpdate_ErrorPageRoundTripPreservesRow(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("auth_host", "https://feil")
	vals.Set("tagline", "nytt slagord")
	vals.Set("default_org", "neworg")
	vals.Set("require_role", "editor")
	w := e.post("alpha", vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "auth_host")
	assert.Equal(t, before, e.row(t, "alpha"), "feilet lagring skal ikke skrive")

	fixed := parseFormValues(t, w.Body.String())
	assert.Equal(t, "nytt slagord", fixed.Get("tagline"))
	assert.Equal(t, "neworg", fixed.Get("default_org"))
	assert.Equal(t, "editor", fixed.Get("require_role"))
	assert.Equal(t, "1", fixed.Get("enforce_org"))
	fixed.Set("auth_host", "auth.alpha.test")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", fixed).Code)

	after := e.row(t, "alpha")
	assert.Equal(t, "nytt slagord", *after.Tagline)
	assert.Equal(t, "neworg", *after.DefaultOrg)
	assert.Equal(t, "editor", *after.RequireRole)
	// Resten av raden (inkludert skjulte felt) er som seed.
	before.UpdatedAt, after.UpdatedAt = "", ""
	before.Tagline, after.Tagline = nil, nil
	before.DefaultOrg, after.DefaultOrg = nil, nil
	before.RequireRole, after.RequireRole = nil, nil
	assert.Equal(t, before, after)
}

// A1 (create): feilsiden ved opprettelse beholder alle innskrevne felt.
func TestServiceCreate_ErrorPageRoundTrip(t *testing.T) {
	e := setupServicesEnv(t)
	vals := url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "tagline": {"slag"}, "domain": {"gamma.test"},
		"auth_host": {"ugyldig host"}, "callback_url": {"https://gamma.test/cb"},
		"email_from_name": {"Gamma Mail"}, "email_from_address": {"n@gamma.test"},
		"accent_color": {"#445566"}, "theme": {"dark"}, "bg_image": {"/g.jpg"},
		"access_token_ttl": {"PT20M"}, "refresh_token_max_age": {"P10D"}, "jwt_cookie_name": {"gt"},
		"default_org": {"acme"}, "default_role": {"user"}, "require_role": {"admin"},
		"enforce_org": {"1"}, "auto_register": {"1"}, "auth_google": {"1"}, "active": {"1"},
	}
	w := e.postCreate(vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)

	fixed := parseFormValues(t, w.Body.String())
	fixed.Set("auth_host", "auth.gamma.test")
	require.Equal(t, http.StatusSeeOther, e.postCreate(fixed).Code)

	got := e.row(t, "gamma")
	assert.Equal(t, "slag", *got.Tagline)
	assert.Equal(t, "auth.gamma.test", *got.AuthHost)
	assert.Equal(t, "Gamma Mail", got.EmailFromName)
	assert.Equal(t, "/g.jpg", *got.BgImage)
	assert.Equal(t, "P10D", *got.RefreshTokenMaxAge)
	assert.Equal(t, "acme", *got.DefaultOrg)
	assert.Equal(t, "user", *got.DefaultRole)
	assert.Equal(t, "admin", *got.RequireRole)
	assert.EqualValues(t, 1, got.EnforceOrg)
	assert.EqualValues(t, 1, got.AutoRegister)
	assert.Equal(t, "dark", got.Theme)
	assert.Equal(t, "PT20M", got.AccessTokenTtl)
}

// M1: enforce_org uten default_org gir 422 med tydelig melding, ved update og create.
func TestServiceUpdate_EnforceOrgWithoutDefaultOrgRejected(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("default_org", "  ")
	w := e.post("alpha", vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "enforce_org")
	assert.Contains(t, w.Body.String(), "standard org")
	assert.Equal(t, before, e.row(t, "alpha"))

	// Uten enforce_org er tom default_org lov.
	vals.Del("enforce_org")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.Nil(t, e.row(t, "alpha").DefaultOrg)
}

func TestServiceCreate_EnforceOrgWithoutDefaultOrgRejected(t *testing.T) {
	e := setupServicesEnv(t)
	vals := url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "domain": {"gamma.test"},
		"callback_url": {"https://gamma.test/cb"}, "enforce_org": {"1"},
	}
	w := e.postCreate(vals)
	require.Equal(t, http.StatusUnprocessableEntity, w.Code)
	assert.Contains(t, w.Body.String(), "enforce_org")
	all, err := e.q.ListAllServices(context.Background())
	require.NoError(t, err)
	assert.Empty(t, all)
}

// Punkt 3: create leser ikke secrets fra skjemaet; feltene blir NULL som ved update.
func TestServiceCreate_IgnoresClientCredentialsInForm(t *testing.T) {
	e := setupServicesEnv(t)
	vals := url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "domain": {"gamma.test"},
		"callback_url":     {"https://gamma.test/cb"},
		"google_client_id": {"x"}, "google_client_secret": {"y"},
		"microsoft_client_id": {"x"}, "microsoft_client_secret": {"y"},
	}
	require.Equal(t, http.StatusSeeOther, e.postCreate(vals).Code)
	got := e.row(t, "gamma")
	assert.Nil(t, got.GoogleClientID)
	assert.Nil(t, got.GoogleClientSecret)
	assert.Nil(t, got.MicrosoftClientID)
	assert.Nil(t, got.MicrosoftClientSecret)
}

// Punkt 6: verdier med HTML-metategn rendres escaped og overlever lagring uendret.
func TestServiceUpdate_HTMLMetacharactersEscapedAndSurvive(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	const evil = `"><script>alert(1)</script>`
	_, err := e.sqldb.Exec(`UPDATE services SET require_role = ?, default_org = ? WHERE id = 'alpha'`, evil, evil)
	require.NoError(t, err)
	before := e.row(t, "alpha")

	vals, body := e.renderedFormValues(t, "alpha")
	assert.NotContains(t, body, "<script>alert(1)")
	assert.Contains(t, body, "&lt;script&gt;")
	assert.Equal(t, evil, vals.Get("require_role"))
	assert.Equal(t, evil, vals.Get("default_org"))

	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	after := e.row(t, "alpha")
	assert.Equal(t, evil, *after.RequireRole)
	assert.Equal(t, evil, *after.DefaultOrg)
	before.UpdatedAt, after.UpdatedAt = "", ""
	assert.Equal(t, before, after)
}

// M2: avkortet multipart-body gir 400 og ingen skriving, ikke en tom lagring.
func TestServiceUpdate_TruncatedMultipartIs400AndWritesNothing(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	require.NoError(t, mw.WriteField("display_name", "Endret"))
	require.NoError(t, mw.WriteField("domain", "alpha.test"))
	require.NoError(t, mw.WriteField("callback_url", "https://app.alpha.test/cb"))
	// Ikke Close(): avslutningsgrensen mangler.
	req := httptest.NewRequest(http.MethodPost, "/admin/services/alpha", bytes.NewReader(buf.Bytes()[:buf.Len()-10]))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Equal(t, before, e.row(t, "alpha"))

	// Samme for create.
	buf.Reset()
	mw = multipart.NewWriter(&buf)
	require.NoError(t, mw.WriteField("id", "gamma"))
	req = httptest.NewRequest(http.MethodPost, "/admin/services", bytes.NewReader(buf.Bytes()[:buf.Len()-5]))
	req.Header.Set("Content-Type", mw.FormDataContentType())
	w = httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	all, err := e.q.ListAllServices(context.Background())
	require.NoError(t, err)
	assert.Len(t, all, 1)
}

// Urlencoded POST virker fortsatt, og tomme påkrevde felt gir 422 uten skriving.
func TestServiceUpdate_UrlencodedWorksAndEmptyRequiredIs422(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals, _ := e.renderedFormValues(t, "alpha")
	vals.Set("display_name", "Ok")
	require.Equal(t, http.StatusSeeOther, e.post("alpha", vals).Code)
	assert.Equal(t, "Ok", e.row(t, "alpha").DisplayName)

	for _, f := range []string{"display_name", "domain", "callback_url"} {
		v := url.Values{}
		for k, vs := range vals {
			v[k] = vs
		}
		v.Set(f, " ")
		w := e.post("alpha", v)
		assert.Equal(t, http.StatusUnprocessableEntity, w.Code, f)
	}
	after := e.row(t, "alpha")
	assert.Equal(t, "Ok", after.DisplayName)
	assert.Equal(t, before.Domain, after.Domain)
	assert.Equal(t, before.CallbackUrl, after.CallbackUrl)
}

// Defense-in-depth: secrets når aldri malen, verken på feilsiden eller i edit.
func TestServiceErrorPage_DoesNotCarrySecretsToTemplate(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("display_name=x"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	require.NoError(t, r.ParseForm())
	got := overlayForm(e.row(t, "alpha"), r)
	assert.Nil(t, got.GoogleClientSecret)
	assert.Nil(t, got.MicrosoftClientSecret)
	assert.Nil(t, got.GoogleClientID)
	assert.Nil(t, got.MicrosoftClientID)
}
