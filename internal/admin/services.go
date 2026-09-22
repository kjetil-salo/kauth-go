package admin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
)

// ServicesHandler håndterer administrasjon av tjenester i admin-panelet.
type ServicesHandler struct {
	queries  *gen.Queries
	registry *service.Registry
	auditor  *audit.Service
	listTpl  *template.Template
	editTpl  *template.Template
}

func NewServicesHandler(
	queries *gen.Queries,
	registry *service.Registry,
	auditor *audit.Service,
) *ServicesHandler {
	listTpl := template.Must(template.ParseFiles("templates/admin/services.html"))
	editTpl := template.Must(template.ParseFiles("templates/admin/service-edit.html"))
	return &ServicesHandler{
		queries:  queries,
		registry: registry,
		auditor:  auditor,
		listTpl:  listTpl,
		editTpl:  editTpl,
	}
}

// HandleList viser alle tjenester (aktive og inaktive).
func (h *ServicesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	services, err := h.queries.ListAllServices(r.Context())
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.listTpl.Execute(w, map[string]interface{}{"Services": services})
}

// HandleNew rendrer skjema for ny tjeneste med fornuftige standardverdier.
func (h *ServicesHandler) HandleNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew": true,
		"Service": gen.Service{
			AuthGoogle:     1,
			AuthMagicLink:  1,
			Active:         1,
			AccentColor:    "#2563EB",
			Theme:          "light",
			JwtCookieName:  "auth_token",
			AccessTokenTtl: "PT15M",
		},
	})
}

// HandleCreate oppretter ny tjeneste fra POST-skjema.
func (h *ServicesHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		_ = r.ParseForm()
	}

	svcID := strings.TrimSpace(r.FormValue("id"))
	if svcID == "" {
		h.renderServiceError(w, serviceFromForm(r), true, "Tjeneste-ID er påkrevd.")
		return
	}

	if err := validateAuthHost(r.FormValue("auth_host")); err != nil {
		h.renderServiceError(w, serviceFromForm(r), true, err.Error())
		return
	}

	uploaded, uploadedPath, uploadErr := handleBgImageUpload(r, svcID)
	if uploadErr != "" {
		h.renderServiceError(w, serviceFromForm(r), true, uploadErr)
		return
	}
	if uploaded {
		r.Form.Set("bg_image", uploadedPath)
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	params := buildCreateParams(r, svcID, now)
	if err := h.queries.CreateService(r.Context(), params); err != nil {
		h.renderServiceError(w, serviceFromForm(r), true, "Feil ved opprettelse: "+err.Error())
		return
	}

	// Ugyldiggjør cache — ikke kritisk hvis det feiler.
	_ = h.registry.Invalidate(r.Context())

	details := "service_created"
	if uploaded {
		details = "service_created bg_image_uploaded=" + uploadedPath
	}
	h.auditor.Log(r.Context(), audit.Event{
		Type:      "service_created",
		ServiceID: svcID,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Details:   details,
		Success:   true,
	})
	http.Redirect(w, r, "/admin/services", http.StatusSeeOther)
}

// HandleEdit rendrer redigeringsskjema for eksisterende tjeneste.
func (h *ServicesHandler) HandleEdit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	services, err := h.queries.ListAllServices(r.Context())
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	var found *gen.Service
	for i := range services {
		if services[i].ID == id {
			found = &services[i]
			break
		}
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":   false,
		"Service": *found,
	})
}

// HandleUpdate lagrer endringer på eksisterende tjeneste.
func (h *ServicesHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := r.ParseMultipartForm(2 << 20); err != nil {
		_ = r.ParseForm()
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	if err := validateAuthHost(r.FormValue("auth_host")); err != nil {
		svc := serviceFromForm(r)
		svc.ID = id
		h.renderServiceError(w, svc, false, err.Error())
		return
	}

	uploaded, uploadedPath, uploadErr := handleBgImageUpload(r, id)
	if uploadErr != "" {
		svc := serviceFromForm(r)
		svc.ID = id
		h.renderServiceError(w, svc, false, uploadErr)
		return
	}
	if uploaded {
		r.Form.Set("bg_image", uploadedPath)
	}

	params := buildUpdateParams(r, id, now)
	if err := h.queries.UpdateService(r.Context(), params); err != nil {
		svc := serviceFromForm(r)
		svc.ID = id
		h.renderServiceError(w, svc, false, "Databasefeil: "+err.Error())
		return
	}

	_ = h.registry.Invalidate(r.Context())

	details := "service_edited"
	if uploaded {
		details = "service_edited bg_image_uploaded=" + uploadedPath
	}
	h.auditor.Log(r.Context(), audit.Event{
		Type:      "service_edited",
		ServiceID: id,
		IP:        extractIP(r),
		UA:        r.UserAgent(),
		Details:   details,
		Success:   true,
	})
	http.Redirect(w, r, "/admin/services", http.StatusSeeOther)
}

// handleBgImageUpload leser bg_image_upload fra multipart-skjema.
// Returnerer (uploaded bool, webPath string, errMsg string).
// webPath er på formen /filename.ext — klar til lagring i bg_image-kolonnen.
// Hvis ingen fil er lastet opp returneres (false, "", "").
// Hvis filen er ugyldig returneres (false, "", feilmelding).
func handleBgImageUpload(r *http.Request, svcID string) (bool, string, string) {
	file, header, err := r.FormFile("bg_image_upload")
	if err != nil {
		// Ingen fil valgt — ikke en feil.
		return false, "", ""
	}
	defer file.Close()

	if header.Size == 0 {
		return false, "", ""
	}
	if header.Size > 1<<20 {
		return false, "", "Bildet er for stort (maks 1 MB)."
	}

	// Valider MIME-type fra Content-Type-header på filfeltet.
	ct := header.Header.Get("Content-Type")
	mediaType, _, _ := mime.ParseMediaType(ct)
	var ext string
	switch mediaType {
	case "image/jpeg":
		ext = ".jpg"
	case "image/webp":
		ext = ".webp"
	case "image/png":
		ext = ".png"
	default:
		return false, "", fmt.Sprintf("Ugyldig filtype (%s). Kun JPEG, WebP og PNG er tillatt.", ct)
	}

	// Generer unikt filnavn: <service-id>-bg-<8 hex-tegn>.<ext>
	randBytes := make([]byte, 4)
	if _, rerr := rand.Read(randBytes); rerr != nil {
		return false, "", "Kunne ikke generere filnavn."
	}
	filename := svcID + "-bg-" + hex.EncodeToString(randBytes) + ext
	destPath := filepath.Join("static", filename)

	dest, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if err != nil {
		return false, "", "Kunne ikke lagre bildet: " + err.Error()
	}
	defer dest.Close()

	if _, err := io.Copy(dest, file); err != nil {
		_ = os.Remove(destPath)
		return false, "", "Kunne ikke lagre bildet."
	}

	return true, "/" + filename, ""
}

// buildCreateParams bygger CreateServiceParams fra HTTP-skjema-verdier.
func buildCreateParams(r *http.Request, id, now string) gen.CreateServiceParams {
	return gen.CreateServiceParams{
		ID:                    id,
		DisplayName:           r.FormValue("display_name"),
		Tagline:               nullableStr(r.FormValue("tagline")),
		Domain:                r.FormValue("domain"),
		AuthHost:              nullableStr(r.FormValue("auth_host")),
		CallbackUrl:           r.FormValue("callback_url"),
		LogoHtml:              nullableStr(r.FormValue("logo_html")),
		BgImage:               nullableStr(r.FormValue("bg_image")),
		BgCss:                 nullableStr(r.FormValue("bg_css")),
		Theme:                 defaultStr(r.FormValue("theme"), "light"),
		AccentColor:           defaultStr(r.FormValue("accent_color"), "#2563EB"),
		EmailFromName:         defaultStr(r.FormValue("email_from_name"), id),
		EmailFromAddress:      nullableStr(r.FormValue("email_from_address")),
		AutoRegister:          checkboxInt(r, "auto_register"),
		DefaultRole:           nullableStr(r.FormValue("default_role")),
		DefaultOrg:            nullableStr(r.FormValue("default_org")),
		RequireRole:           nullableStr(r.FormValue("require_role")),
		EnforceOrg:            checkboxInt(r, "enforce_org"),
		IsDefault:             checkboxInt(r, "is_default"),
		AuthGoogle:            checkboxInt(r, "auth_google"),
		AuthMicrosoft:         checkboxInt(r, "auth_microsoft"),
		AuthMagicLink:         checkboxInt(r, "auth_magic_link"),
		AuthPassword:          checkboxInt(r, "auth_password"),
		GoogleClientID:        nullableStr(r.FormValue("google_client_id")),
		GoogleClientSecret:    nullableStr(r.FormValue("google_client_secret")),
		MicrosoftClientID:     nullableStr(r.FormValue("microsoft_client_id")),
		MicrosoftClientSecret: nullableStr(r.FormValue("microsoft_client_secret")),
		JwtCookieName:         defaultStr(r.FormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:        defaultStr(r.FormValue("access_token_ttl"), "PT15M"),
		RefreshTokenMaxAge:    nullableStr(r.FormValue("refresh_token_max_age")),
		Active:                checkboxInt(r, "active"),
		UpdatedAt:             now,
	}
}

// buildUpdateParams bygger UpdateServiceParams fra buildCreateParams.
func buildUpdateParams(r *http.Request, id, now string) gen.UpdateServiceParams {
	cp := buildCreateParams(r, id, now)
	return gen.UpdateServiceParams{
		DisplayName:           cp.DisplayName,
		Tagline:               cp.Tagline,
		Domain:                cp.Domain,
		AuthHost:              cp.AuthHost,
		CallbackUrl:           cp.CallbackUrl,
		LogoHtml:              cp.LogoHtml,
		BgImage:               cp.BgImage,
		BgCss:                 cp.BgCss,
		Theme:                 cp.Theme,
		AccentColor:           cp.AccentColor,
		EmailFromName:         cp.EmailFromName,
		EmailFromAddress:      cp.EmailFromAddress,
		AutoRegister:          cp.AutoRegister,
		DefaultRole:           cp.DefaultRole,
		DefaultOrg:            cp.DefaultOrg,
		RequireRole:           cp.RequireRole,
		EnforceOrg:            cp.EnforceOrg,
		IsDefault:             cp.IsDefault,
		AuthGoogle:            cp.AuthGoogle,
		AuthMicrosoft:         cp.AuthMicrosoft,
		AuthMagicLink:         cp.AuthMagicLink,
		AuthPassword:          cp.AuthPassword,
		GoogleClientID:        cp.GoogleClientID,
		GoogleClientSecret:    cp.GoogleClientSecret,
		MicrosoftClientID:     cp.MicrosoftClientID,
		MicrosoftClientSecret: cp.MicrosoftClientSecret,
		JwtCookieName:         cp.JwtCookieName,
		AccessTokenTtl:        cp.AccessTokenTtl,
		RefreshTokenMaxAge:    cp.RefreshTokenMaxAge,
		Active:                cp.Active,
		UpdatedAt:             now,
		ID:                    id,
	}
}

// Hjelpefunksjoner for skjemabehandling — delt mellom auth.go, users.go og services.go.

// 126 F2 (BACKLOG F19): auth_host konkateneres rått inn i magic-link-URL-en
// (resolveMagicLinkBaseURL i internal/auth/magic.go: "https://" + auth_host + "/magic-login/" + token).
// Ingen sjekk fantes tidligere — en feilkonfigurasjon (skrivefeil, skjema inkludert ved
// et uhell, eller en kompromittert konge-admin) kunne sende bearer-ekvivalente tokens
// til feil host i stedet for å feile trygt. Regexen er bevisst enkel (alfanumerisk +
// punktum + bindestrek) — dekker feilkonfigurasjon, ikke eksotisk-men-gyldige vertsnavn
// (internasjonaliserte domener). Tom streng er fortsatt gyldig (bruk global default).
var authHostPattern = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)+$`)

func validateAuthHost(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if strings.Contains(s, "://") {
		return fmt.Errorf("auth_host skal ikke inneholde skjema (fjern https://)")
	}
	if strings.ContainsAny(s, "/ \t\n") {
		return fmt.Errorf("auth_host skal være et rent vertsnavn, ikke inneholde sti eller mellomrom")
	}
	if !authHostPattern.MatchString(s) {
		return fmt.Errorf("auth_host er ikke et gyldig vertsnavn")
	}
	return nil
}

func nullableStr(s string) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	return &s
}

func defaultStr(s, def string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return def
	}
	return s
}

func checkboxInt(r *http.Request, name string) int64 {
	if r.FormValue(name) == "1" {
		return 1
	}
	return 0
}

// serviceFromForm bygger en gen.Service fra skjemafelter for feilrendering.
func serviceFromForm(r *http.Request) gen.Service {
	return gen.Service{
		ID:               r.FormValue("id"),
		DisplayName:      r.FormValue("display_name"),
		Domain:           r.FormValue("domain"),
		EmailFromAddress: nullableStr(r.FormValue("email_from_address")),
		CallbackUrl:      r.FormValue("callback_url"),
		AccentColor:      defaultStr(r.FormValue("accent_color"), "#2563EB"),
		Theme:            defaultStr(r.FormValue("theme"), "light"),
		JwtCookieName:    defaultStr(r.FormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:   defaultStr(r.FormValue("access_token_ttl"), "PT15M"),
		Active:           checkboxInt(r, "active"),
		AuthGoogle:       checkboxInt(r, "auth_google"),
		AuthMagicLink:    checkboxInt(r, "auth_magic_link"),
		AuthMicrosoft:    checkboxInt(r, "auth_microsoft"),
		AuthPassword:     checkboxInt(r, "auth_password"),
		IsDefault:        checkboxInt(r, "is_default"),
		AutoRegister:     checkboxInt(r, "auto_register"),
	}
}

func (h *ServicesHandler) renderServiceError(w http.ResponseWriter, svc gen.Service, isNew bool, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":   isNew,
		"Service": svc,
		"Error":   errMsg,
	})
}
