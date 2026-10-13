package auth

import (
	"encoding/json"
	"net/http"

	"github.com/zral/kauth-go/internal/token"
)

// MeResponse er JSON-svaret fra GET /api/me.
type MeResponse struct {
	Email  string   `json:"email"`
	Org    []string `json:"org"`
	Groups []string `json:"groups"`
	Name   string   `json:"name"`
}

// MeHandler håndterer GET /api/me.
type MeHandler struct {
	Issuer     *token.Issuer
	CookieName string // typisk "auth_token"
}

// ServeMe håndterer GET /api/me.
// Leser auth_token-cookie, validerer JWT, returnerer claims som JSON.
// Returnerer 401 ved manglende eller ugyldig token.
func (h *MeHandler) ServeMe(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(h.CookieName)
	if err != nil || c.Value == "" {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"unauthenticated"}`, http.StatusUnauthorized)
		return
	}

	claims, err := h.Issuer.Verify(c.Value, token.ExpectAccess)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
		return
	}

	org := claims.Org
	if org == nil {
		org = []string{}
	}
	groups := claims.Groups
	if groups == nil {
		groups = []string{}
	}

	resp := MeResponse{
		Email:  claims.Email,
		Org:    org,
		Groups: groups,
		Name:   claims.Name,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}
