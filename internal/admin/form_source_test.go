package admin

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
)

// K13: skjemafelt leses bare fra POST-kroppen. Et felt i query kan ellers
// smugles inn via en lenke som ikke går gjennom samme-origin-sjekken.

func TestAdminWrite_QueryFieldsIgnored(t *testing.T) {
	e := setupDeactEnv(t)
	u := e.mkUser(t, "a@example.com")
	h := NewUsersHandler(e.q, audit.NewService(e.q))
	r := chi.NewRouter()
	r.Post("/admin/users/{id}", h.HandleUpdate)

	body := url.Values{"name": {"Fra body"}}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/users/"+strconv.FormatInt(u.ID, 10)+"?name=Fra+query&roles=admin",
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)

	got, err := e.q.GetUserByEmail(context.Background(), "a@example.com")
	require.NoError(t, err)
	require.NotNil(t, got.Name)
	assert.Equal(t, "Fra body", *got.Name)
	assert.NotContains(t, got.Roles, "admin")

	// Navnet bare i query: uendret (tomt navn i body nuller det, query teller ikke).
	req = httptest.NewRequest(http.MethodPost,
		"/admin/users/"+strconv.FormatInt(u.ID, 10)+"?name=Kun+query", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)
	got, err = e.q.GetUserByEmail(context.Background(), "a@example.com")
	require.NoError(t, err)
	if got.Name != nil {
		assert.NotEqual(t, "Kun query", *got.Name)
	}
}

func TestServiceUpdate_QueryFieldsIgnored(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	before := e.row(t, "alpha")

	vals, _ := e.renderedFormValues(t, "alpha")
	req := httptest.NewRequest(http.MethodPost,
		"/admin/services/alpha?display_name=Smuglet&domain=evil.test&callback_url=https://evil.test/cb",
		strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)

	after := e.row(t, "alpha")
	assert.Equal(t, before.DisplayName, after.DisplayName)
	assert.Equal(t, before.Domain, after.Domain)
	assert.Equal(t, before.CallbackUrl, after.CallbackUrl)
}

// Checkbox-felt i query kan ikke slå på noe: uavkrysset i body betyr 0.
func TestServiceUpdate_QueryCheckboxesIgnored(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	vals, _ := e.renderedFormValues(t, "alpha")
	for _, f := range []string{"active", "auth_google", "auth_password", "is_default", "enforce_org"} {
		vals.Del(f)
	}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/services/alpha?active=1&auth_google=1&auth_password=1&is_default=1&enforce_org=1&theme=light&accent_color=%23ffffff",
		strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)

	after := e.row(t, "alpha")
	assert.EqualValues(t, 0, after.Active)
	assert.EqualValues(t, 0, after.AuthGoogle)
	assert.EqualValues(t, 0, after.AuthPassword)
	assert.EqualValues(t, 0, after.IsDefault)
	assert.EqualValues(t, 0, after.EnforceOrg)
	assert.Equal(t, "dark", after.Theme)
	assert.Equal(t, "#112233", after.AccentColor)
}

func TestServiceCreate_QueryFieldsIgnored(t *testing.T) {
	e := setupServicesEnv(t)
	body := url.Values{
		"id": {"gamma"}, "display_name": {"Gamma"}, "domain": {"gamma.test"},
		"callback_url": {"https://app.gamma.test/cb"},
	}
	req := httptest.NewRequest(http.MethodPost,
		"/admin/services?display_name=Smuglet&auth_google=1&is_default=1&bg_image=/x.jpg&tagline=smuglet",
		strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	row := e.row(t, "gamma")
	assert.Equal(t, "Gamma", row.DisplayName)
	assert.EqualValues(t, 0, row.AuthGoogle)
	assert.EqualValues(t, 0, row.IsDefault)
	assert.Nil(t, row.BgImage)
	assert.Nil(t, row.Tagline)
}

func multipartWithPNG(t *testing.T, fields map[string]string) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	for k, v := range fields {
		require.NoError(t, mw.WriteField(k, v))
	}
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", `form-data; name="bg_image_upload"; filename="bg.png"`)
	hdr.Set("Content-Type", "image/png")
	part, err := mw.CreatePart(hdr)
	require.NoError(t, err)
	_, err = part.Write([]byte("\x89PNG\r\n\x1a\nliten"))
	require.NoError(t, err)
	require.NoError(t, mw.Close())
	return &buf, mw.FormDataContentType()
}

// Opplastet bilde må havne i bg_image, og query kan ikke overstyre det.
func TestServiceUpdate_BgImageUpload_Persisted(t *testing.T) {
	e := setupServicesEnv(t)
	e.seed(t, "alpha", "alpha.test")
	vals, _ := e.renderedFormValues(t, "alpha")
	fields := map[string]string{}
	for k := range vals {
		fields[k] = vals.Get(k)
	}

	// Opplastingen skriver til static/ relativt til arbeidsmappen.
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "static"), 0o755))
	t.Chdir(dir)

	buf, ct := multipartWithPNG(t, fields)
	req := httptest.NewRequest(http.MethodPost, "/admin/services/alpha?bg_image=/x.jpg", buf)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	row := e.row(t, "alpha")
	require.NotNil(t, row.BgImage)
	assert.NotEqual(t, "/x.jpg", *row.BgImage)
	assert.NotEqual(t, "/bg.jpg", *row.BgImage)
	assert.Regexp(t, `^/alpha-bg-[0-9a-f]{8}\.png$`, *row.BgImage)
	_, err := os.Stat(filepath.Join(dir, "static", strings.TrimPrefix(*row.BgImage, "/")))
	assert.NoError(t, err)
}

func TestServiceCreate_BgImageUpload_Persisted(t *testing.T) {
	e := setupServicesEnv(t)
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "static"), 0o755))
	t.Chdir(dir)

	buf, ct := multipartWithPNG(t, map[string]string{
		"id": "gamma", "display_name": "Gamma", "domain": "gamma.test", "callback_url": "https://app.gamma.test/cb",
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/services?bg_image=/x.jpg", buf)
	req.Header.Set("Content-Type", ct)
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code, w.Body.String())

	row := e.row(t, "gamma")
	require.NotNil(t, row.BgImage)
	assert.Regexp(t, `^/gamma-bg-[0-9a-f]{8}\.png$`, *row.BgImage)
}

func TestUserCreate_QueryFieldsIgnored(t *testing.T) {
	e := setupDeactEnv(t)
	h := NewUsersHandler(e.q, audit.NewService(e.q))
	r := chi.NewRouter()
	r.Post("/admin/users", h.HandleCreate)

	// Bare query: e-post mangler, ingen bruker opprettes.
	req := httptest.NewRequest(http.MethodPost, "/admin/users?email=q@example.com&roles=konge", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.ServeHTTP(httptest.NewRecorder(), req)
	_, err := e.q.GetUserByEmail(context.Background(), "q@example.com")
	assert.Error(t, err)

	// E-post i body, roller bare i query: rollene smugles ikke inn.
	req = httptest.NewRequest(http.MethodPost, "/admin/users?roles=konge&orgs=evil&name=Smuglet",
		strings.NewReader(url.Values{"email": {"b@example.com"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	require.Equal(t, http.StatusSeeOther, w.Code)
	u, err := e.q.GetUserByEmail(context.Background(), "b@example.com")
	require.NoError(t, err)
	assert.Empty(t, u.Roles)
	assert.Empty(t, u.Orgs)
	assert.Nil(t, u.Name)
}

func TestAdminLogin_QueryEmailIgnored(t *testing.T) {
	h, m, count := newLoginFixture(t)
	req := httptest.NewRequest(http.MethodPost, "/admin/login?email=konge@example.com", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.HandleLoginPost(w, req)
	h.sendWG.Wait()
	assert.Equal(t, 0, count("1=1"))
	assert.Equal(t, 0, m.count())
}

func TestAdminVerify_QueryTokenIgnored(t *testing.T) {
	h, q, _ := newVerifyFixture(t)
	insertMagic(t, q, "tok-i-query", nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/verify?token=tok-i-query", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	w := httptest.NewRecorder()
	h.HandleVerifyPost(w, req)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "/admin/login", w.Header().Get("Location"))
	assert.EqualValues(t, 0, usedCount(t, q, "tok-i-query"), "tokenet skal ikke være brukt")
}
