package admin

import (
	"context"
	"database/sql"
	"encoding/csv"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/go-chi/chi/v5"
	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
)

const usersPerPage = 25

// UsersHandler håndterer alle bruker-CRUD-ruter i admin-panelet.
type UsersHandler struct {
	queries *gen.Queries
	auditor *audit.Service
	listTpl *template.Template
	editTpl *template.Template
}

func NewUsersHandler(queries *gen.Queries, auditor *audit.Service) *UsersHandler {
	listTpl := template.Must(template.ParseFiles("templates/admin/users.html"))
	editTpl := template.Must(template.ParseFiles("templates/admin/user-edit.html"))
	return &UsersHandler{
		queries: queries,
		auditor: auditor,
		listTpl: listTpl,
		editTpl: editTpl,
	}
}

// HandleList rendrer bruker-tabellen med paginering og filtrering.
func (h *UsersHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	org := strings.TrimSpace(r.URL.Query().Get("org"))
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}

	var users []gen.User
	var total int64

	if search != "" || org != "" {
		// Hent stor window, filtrer i Go, paginer det filtrerte resultatet.
		var all []gen.User
		var err error
		if org != "" {
			all, err = h.queries.ListUsersByOrg(ctx, gen.ListUsersByOrgParams{
				Orgs:   "%" + org + "%",
				Limit:  1000,
				Offset: 0,
			})
		} else {
			all, err = h.queries.ListUsers(ctx, gen.ListUsersParams{
				Limit:  1000,
				Offset: 0,
			})
		}
		if err != nil {
			http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
			return
		}

		needle := strings.ToLower(search)
		var filtered []gen.User
		for _, u := range all {
			if needle != "" && !strings.Contains(strings.ToLower(u.Email), needle) {
				continue
			}
			filtered = append(filtered, u)
		}
		total = int64(len(filtered))
		start := (page - 1) * usersPerPage
		end := start + usersPerPage
		if start > len(filtered) {
			start = len(filtered)
		}
		if end > len(filtered) {
			end = len(filtered)
		}
		users = filtered[start:end]
	} else {
		offset := int64((page - 1) * usersPerPage)
		var err error
		users, err = h.queries.ListUsers(ctx, gen.ListUsersParams{
			Limit:  usersPerPage,
			Offset: offset,
		})
		if err != nil {
			http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
			return
		}
		total, err = h.queries.CountUsers(ctx)
		if err != nil {
			http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	totalPages := int(math.Ceil(float64(total) / float64(usersPerPage)))
	if totalPages < 1 {
		totalPages = 1
	}

	var prevPage, nextPage int
	if page > 1 {
		prevPage = page - 1
	}
	if page < totalPages {
		nextPage = page + 1
	}

	type pageData struct {
		Users      []gen.User
		Search     string
		Org        string
		Page       int
		TotalPages int
		PrevPage   int
		NextPage   int
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.listTpl.Execute(w, pageData{
		Users: users, Search: search, Org: org,
		Page: page, TotalPages: totalPages,
		PrevPage: prevPage, NextPage: nextPage,
	})
}

// HandleNew rendrer skjema for ny bruker.
func (h *UsersHandler) HandleNew(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew": true,
		"User":  gen.User{},
	})
}

// HandleCreate oppretter ny bruker fra POST-skjema.
func (h *UsersHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	email := strings.TrimSpace(strings.ToLower(r.PostFormValue("email")))
	password := r.PostFormValue("password")
	name := strings.TrimSpace(r.PostFormValue("name"))
	roles := strings.TrimSpace(r.PostFormValue("roles"))
	orgs := strings.TrimSpace(r.PostFormValue("orgs"))

	if email == "" {
		h.renderEditError(w, gen.User{Roles: roles, Orgs: orgs}, true, email, "E-post er påkrevd.")
		return
	}

	var passwordHash *string
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			h.renderEditError(w, gen.User{}, true, email, "Feil ved hashing av passord.")
			return
		}
		hs := string(hash)
		passwordHash = &hs
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	_, err := h.queries.CreateUser(r.Context(), gen.CreateUserParams{
		Email:        email,
		PasswordHash: passwordHash,
		Name:         namePtr,
		Roles:        roles,
		Orgs:         orgs,
		CreatedAt:    now,
	})
	if err != nil {
		h.renderEditError(w, gen.User{Roles: roles, Orgs: orgs}, true, email, "Feil ved opprettelse: "+err.Error())
		return
	}

	h.auditor.Log(r.Context(), audit.Event{
		Type:    "user_created",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
	})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// HandleEdit rendrer redigeringsskjema for eksisterende bruker.
func (h *UsersHandler) HandleEdit(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	// ListUsers med høy limit for å finne bruker på ID (ingen GetUserByID-query nødvendig).
	users, err := h.queries.ListUsers(r.Context(), gen.ListUsersParams{Limit: 10000, Offset: 0})
	if err != nil {
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}
	var found *gen.User
	for i := range users {
		if users[i].ID == id {
			found = &users[i]
			break
		}
	}
	if found == nil {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew": false,
		"User":  *found,
	})
}

// HandleUpdate lagrer endringer på eksisterende bruker.
func (h *UsersHandler) HandleUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	_ = r.ParseForm()
	name := strings.TrimSpace(r.PostFormValue("name"))
	roles := strings.TrimSpace(r.PostFormValue("roles"))
	orgs := strings.TrimSpace(r.PostFormValue("orgs"))

	var namePtr *string
	if name != "" {
		namePtr = &name
	}

	err = h.queries.UpdateUser(r.Context(), gen.UpdateUserParams{
		Name:  namePtr,
		Roles: roles,
		Orgs:  orgs,
		ID:    id,
	})
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	h.auditor.Log(r.Context(), audit.Event{
		Type:    "user_edited",
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: fmt.Sprintf("id=%d", id),
	})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// HandleDeactivate deaktiverer en bruker.
func (h *UsersHandler) HandleDeactivate(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	// E-posten kommer fra brukerraden (RETURNING), ikke fra URL/skjema:
	// refresh_tokens.email matches eksakt og må ha samme case som lagret.
	email, err := h.queries.DeactivateUser(r.Context(), gen.DeactivateUserParams{
		DeactivatedAt: &now,
		ID:            id,
	})
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		slog.Error("admin: deaktivering feilet", "id", id, "err", err)
		http.Error(w, "databasefeil", http.StatusInternalServerError)
		return
	}

	// WithoutCancel: revokeringen skal fullføres selv om admin kobler fra.
	// Feiler den, står deaktiveringen; refresh for en deaktivert bruker avvises
	// uansett (refresh_user_inactive).
	ctx := context.WithoutCancel(r.Context())
	reason := "user_deactivated"
	var details string
	revoked, err := h.queries.RevokeUserRefreshTokens(ctx, gen.RevokeUserRefreshTokensParams{
		RevokedReason: &reason,
		Email:         email,
	})
	if err != nil {
		slog.Error("admin: revokering av refresh-tokens etter deaktivering feilet", "id", id, "err", err)
		details = fmt.Sprintf("id=%d revoke_failed", id)
	} else {
		details = fmt.Sprintf("id=%d revoked=%d", id, revoked)
	}

	h.auditor.Log(ctx, audit.Event{
		Type:    "user_deactivated",
		Email:   email,
		IP:      extractIP(r),
		UA:      r.UserAgent(),
		Success: true,
		Details: details,
	})
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

// HandleExport skriver alle brukere som CSV.
// ALDRI password_hash i eksporten.
func (h *UsersHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	users, err := h.queries.ListUsers(ctx, gen.ListUsersParams{Limit: 100000, Offset: 0})
	if err != nil {
		http.Error(w, "databasefeil: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="kauth-users.csv"`)

	wr := csv.NewWriter(w)
	_ = wr.Write([]string{"id", "email", "name", "roles", "orgs", "created_at", "last_login"})

	for _, u := range users {
		name := ""
		if u.Name != nil {
			name = *u.Name
		}
		lastLogin := ""
		if u.LastLogin != nil {
			lastLogin = *u.LastLogin
		}
		_ = wr.Write([]string{
			csvEsc(strconv.FormatInt(u.ID, 10)),
			csvEsc(u.Email),
			csvEsc(name),
			csvEsc(u.Roles),
			csvEsc(u.Orgs),
			csvEsc(u.CreatedAt),
			csvEsc(lastLogin),
		})
	}
	wr.Flush()
}

// csvEsc beskytter mot CSV-injeksjon (formelinjeksjon).
// Quoting av felt med komma/anførselstegn/newline håndteres av csv.NewWriter.
func csvEsc(s string) string {
	if len(s) == 0 {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func (h *UsersHandler) renderEditError(w http.ResponseWriter, user gen.User, isNew bool, formEmail, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = h.editTpl.Execute(w, map[string]interface{}{
		"IsNew":     isNew,
		"User":      user,
		"FormEmail": formEmail,
		"Error":     errMsg,
	})
}
