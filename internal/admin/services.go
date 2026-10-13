package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log/slog"
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

// invalidateCache returnerer redirect-målet. Lagringen er allerede utført og rulles
// ikke tilbake; ellers ville admin tro at tjenesten er aktiv når cachen er utdatert.
func (h *ServicesHandler) invalidateCache(r *http.Request, serviceID string) string {
	if err := h.registry.Invalidate(r.Context()); err != nil {
		slog.Error("admin: cache-invalidering feilet etter lagring av tjeneste", "service_id", serviceID, "error", err)
		return "/admin/services?warn=cache"
	}
	return "/admin/services"
}

// HandleList viser alle tjenester (aktive og inaktive).
func (h *ServicesHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	services, err := h.queries.ListAllServices(r.Context())
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Bare faste koder gir tekst i malen; verdien fra query-strengen speiles aldri.
	warn := ""
	if r.URL.Query().Get("warn") == "cache" {
		warn = "cache"
	}
	_ = h.listTpl.Execute(w, map[string]interface{}{"Services": services, "Warn": warn})
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
	if err := r.ParseMultipartForm(2 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, "ugyldig skjema", http.StatusBadRequest)
		return
	}

	svcID := strings.TrimSpace(r.PostFormValue("id"))
	if svcID == "" {
		h.renderServiceError(w, serviceFromForm(r), true, "Tjeneste-ID er påkrevd.")
		return
	}

	if err := validateAuthHost(r.PostFormValue("auth_host")); err != nil {
		h.renderServiceError(w, serviceFromForm(r), true, err.Error())
		return
	}

	if err := validateEnforceOrg(r); err != nil {
		h.renderServiceError(w, serviceFromForm(r), true, err.Error())
		return
	}

	uploaded, uploadedPath, uploadErr := handleBgImageUpload(r, svcID)
	if uploadErr != "" {
		h.renderServiceError(w, serviceFromForm(r), true, uploadErr)
		return
	}
	if uploaded {
		r.PostForm.Set("bg_image", uploadedPath)
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	params := buildCreateParams(r, svcID, now)
	if err := h.queries.CreateService(r.Context(), params); err != nil {
		h.renderServiceError(w, serviceFromForm(r), true, "Feil ved opprettelse: "+err.Error())
		return
	}

	redirectTo := h.invalidateCache(r, svcID)

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
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
}

// HandleEdit rendrer redigeringsskjema for eksisterende tjeneste.
func (h *ServicesHandler) HandleEdit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	found, err := h.findService(r.Context(), id)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":   false,
		"Service": withoutSecrets(*found),
	})
}

// HandleUpdate lagrer endringer på eksisterende tjeneste.
func (h *ServicesHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")

	// Les-så-skriv har et lost-update-vindu: felt utenfor skjemaet (for eksempel en secret
	// som roteres direkte i SQL mellom lesing og skriving) overskrives med den leste verdien.
	// Akseptert så lenge det finnes én admin.
	existing, err := h.findService(r.Context(), id)
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	if existing == nil {
		// Sjekkes før opplasting, slik at ukjent id ikke etterlater filer i static/.
		http.NotFound(w, r)
		return
	}

	if err := r.ParseMultipartForm(2 << 20); err != nil && !errors.Is(err, http.ErrNotMultipart) {
		http.Error(w, "ugyldig skjema", http.StatusBadRequest)
		return
	}
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")

	if err := validateAuthHost(r.PostFormValue("auth_host")); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), false, err.Error())
		return
	}

	if strings.TrimSpace(r.PostFormValue("display_name")) == "" ||
		strings.TrimSpace(r.PostFormValue("domain")) == "" ||
		strings.TrimSpace(r.PostFormValue("callback_url")) == "" {
		h.renderServiceError(w, overlayForm(*existing, r), false, "Visningsnavn, domene og callback-URL er påkrevd.")
		return
	}

	if err := validateEnforceOrg(r); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), false, err.Error())
		return
	}

	uploaded, uploadedPath, uploadErr := handleBgImageUpload(r, id)
	if uploadErr != "" {
		h.renderServiceError(w, overlayForm(*existing, r), false, uploadErr)
		return
	}
	if uploaded {
		r.PostForm.Set("bg_image", uploadedPath)
	}

	params := buildUpdateParams(r, *existing, now)
	if err := h.queries.UpdateService(r.Context(), params); err != nil {
		h.renderServiceError(w, overlayForm(*existing, r), false, "Databasefeil: "+err.Error())
		return
	}

	redirectTo := h.invalidateCache(r, id)

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
	http.Redirect(w, r, redirectTo, http.StatusSeeOther)
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
		ID:                 id,
		DisplayName:        r.PostFormValue("display_name"),
		Tagline:            nullableStr(r.PostFormValue("tagline")),
		Domain:             r.PostFormValue("domain"),
		AuthHost:           nullableStr(r.PostFormValue("auth_host")),
		CallbackUrl:        r.PostFormValue("callback_url"),
		LogoHtml:           nullableStr(r.PostFormValue("logo_html")),
		BgImage:            nullableStr(r.PostFormValue("bg_image")),
		BgCss:              nullableStr(r.PostFormValue("bg_css")),
		Theme:              defaultStr(r.PostFormValue("theme"), "light"),
		AccentColor:        defaultStr(r.PostFormValue("accent_color"), "#2563EB"),
		EmailFromName:      defaultStr(r.PostFormValue("email_from_name"), id),
		EmailFromAddress:   nullableStr(r.PostFormValue("email_from_address")),
		AutoRegister:       checkboxInt(r, "auto_register"),
		DefaultRole:        nullableStr(r.PostFormValue("default_role")),
		DefaultOrg:         nullableStr(r.PostFormValue("default_org")),
		RequireRole:        nullableStr(r.PostFormValue("require_role")),
		EnforceOrg:         checkboxInt(r, "enforce_org"),
		IsDefault:          checkboxInt(r, "is_default"),
		AuthGoogle:         checkboxInt(r, "auth_google"),
		AuthMicrosoft:      checkboxInt(r, "auth_microsoft"),
		AuthMagicLink:      checkboxInt(r, "auth_magic_link"),
		AuthPassword:       checkboxInt(r, "auth_password"),
		JwtCookieName:      defaultStr(r.PostFormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:     defaultStr(r.PostFormValue("access_token_ttl"), "PT15M"),
		RefreshTokenMaxAge: nullableStr(r.PostFormValue("refresh_token_max_age")),
		Active:             checkboxInt(r, "active"),
		UpdatedAt:          now,
	}
}

// buildUpdateParams bygger UpdateServiceParams med den eksisterende raden som baseline.
// UpdateService skriver alle kolonner, så felt uten skjemainput (google_*, microsoft_*,
// logo_html, bg_css) må hentes fra raden — ellers nulles de ved hver lagring.
func buildUpdateParams(r *http.Request, existing gen.Service, now string) gen.UpdateServiceParams {
	cp := buildCreateParams(r, existing.ID, now)
	return gen.UpdateServiceParams{
		DisplayName:           cp.DisplayName,
		Tagline:               cp.Tagline,
		Domain:                cp.Domain,
		AuthHost:              cp.AuthHost,
		CallbackUrl:           cp.CallbackUrl,
		LogoHtml:              existing.LogoHtml,
		BgImage:               cp.BgImage,
		BgCss:                 existing.BgCss,
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
		GoogleClientID:        existing.GoogleClientID,
		GoogleClientSecret:    existing.GoogleClientSecret,
		MicrosoftClientID:     existing.MicrosoftClientID,
		MicrosoftClientSecret: existing.MicrosoftClientSecret,
		JwtCookieName:         cp.JwtCookieName,
		AccessTokenTtl:        cp.AccessTokenTtl,
		RefreshTokenMaxAge:    cp.RefreshTokenMaxAge,
		Active:                cp.Active,
		UpdatedAt:             now,
		ID:                    existing.ID,
	}
}

// findService henter en tjeneste uavhengig av active-flagget. GetServiceByID filtrerer
// på active = 1, og admin må kunne redigere (og reaktivere) deaktiverte tjenester.
func (h *ServicesHandler) findService(ctx context.Context, id string) (*gen.Service, error) {
	services, err := h.queries.ListAllServices(ctx)
	if err != nil {
		return nil, err
	}
	for i := range services {
		if services[i].ID == id {
			return &services[i], nil
		}
	}
	return nil, nil
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
	if r.PostFormValue(name) == "1" {
		return 1
	}
	return 0
}

// validateEnforceOrg avviser enforce_org uten default_org. checkPolicy (internal/auth/google.go)
// krever DefaultOrg != nil, så kombinasjonen ville slått av org-håndhevingen uten varsel.
func validateEnforceOrg(r *http.Request) error {
	if checkboxInt(r, "enforce_org") == 1 && nullableStr(r.PostFormValue("default_org")) == nil {
		return fmt.Errorf("Krev org-samsvar (enforce_org) forutsetter en standard org. Fyll ut standard org eller fjern avkryssingen.")
	}
	return nil
}

// serviceFromForm bygger en gen.Service fra alle skjemafelt for feilrendering.
func serviceFromForm(r *http.Request) gen.Service {
	return gen.Service{
		ID:                 r.PostFormValue("id"),
		DisplayName:        r.PostFormValue("display_name"),
		Tagline:            nullableStr(r.PostFormValue("tagline")),
		Domain:             r.PostFormValue("domain"),
		AuthHost:           nullableStr(r.PostFormValue("auth_host")),
		EmailFromName:      r.PostFormValue("email_from_name"),
		EmailFromAddress:   nullableStr(r.PostFormValue("email_from_address")),
		CallbackUrl:        r.PostFormValue("callback_url"),
		BgImage:            nullableStr(r.PostFormValue("bg_image")),
		AccentColor:        defaultStr(r.PostFormValue("accent_color"), "#2563EB"),
		Theme:              defaultStr(r.PostFormValue("theme"), "light"),
		JwtCookieName:      defaultStr(r.PostFormValue("jwt_cookie_name"), "auth_token"),
		AccessTokenTtl:     defaultStr(r.PostFormValue("access_token_ttl"), "PT15M"),
		RefreshTokenMaxAge: nullableStr(r.PostFormValue("refresh_token_max_age")),
		DefaultRole:        nullableStr(r.PostFormValue("default_role")),
		DefaultOrg:         nullableStr(r.PostFormValue("default_org")),
		RequireRole:        nullableStr(r.PostFormValue("require_role")),
		EnforceOrg:         checkboxInt(r, "enforce_org"),
		Active:             checkboxInt(r, "active"),
		AuthGoogle:         checkboxInt(r, "auth_google"),
		AuthMagicLink:      checkboxInt(r, "auth_magic_link"),
		AuthMicrosoft:      checkboxInt(r, "auth_microsoft"),
		AuthPassword:       checkboxInt(r, "auth_password"),
		IsDefault:          checkboxInt(r, "is_default"),
		AutoRegister:       checkboxInt(r, "auto_register"),
	}
}

// withoutSecrets nuller client id/secret i strukturen som går til malen, slik at et
// fremtidig malfelt ikke kan lekke dem. Skriving bruker den uavkortede raden.
func withoutSecrets(s gen.Service) gen.Service {
	s.GoogleClientID, s.GoogleClientSecret = nil, nil
	s.MicrosoftClientID, s.MicrosoftClientSecret = nil, nil
	return s
}

// overlayForm legger skjemaverdiene over den eksisterende raden, slik at feilsiden ved
// update beholder felt som ikke kommer fra skjemaet. Raden og dens id er autoritativ.
func overlayForm(existing gen.Service, r *http.Request) gen.Service {
	f := serviceFromForm(r)
	f.ID = existing.ID
	out := withoutSecrets(existing)
	out.DisplayName, out.Tagline, out.Domain, out.AuthHost = f.DisplayName, f.Tagline, f.Domain, f.AuthHost
	out.EmailFromName, out.EmailFromAddress, out.CallbackUrl, out.BgImage = f.EmailFromName, f.EmailFromAddress, f.CallbackUrl, f.BgImage
	out.AccentColor, out.Theme, out.JwtCookieName = f.AccentColor, f.Theme, f.JwtCookieName
	out.AccessTokenTtl, out.RefreshTokenMaxAge = f.AccessTokenTtl, f.RefreshTokenMaxAge
	out.DefaultRole, out.DefaultOrg, out.RequireRole, out.EnforceOrg = f.DefaultRole, f.DefaultOrg, f.RequireRole, f.EnforceOrg
	out.Active, out.AuthGoogle, out.AuthMagicLink, out.AuthMicrosoft = f.Active, f.AuthGoogle, f.AuthMagicLink, f.AuthMicrosoft
	out.AuthPassword, out.IsDefault, out.AutoRegister = f.AuthPassword, f.IsDefault, f.AutoRegister
	return out
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
