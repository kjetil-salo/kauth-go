package token

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/zral/kauth-go/internal/db/gen"
)

// Claims er JWT-payload for kauth-tokens.
type Claims struct {
	jwt.RegisteredClaims
	Email    string   `json:"email"`
	Org      []string `json:"org"`
	Groups   []string `json:"groups"`
	Name     string   `json:"name,omitempty"`
	TokenUse string   `json:"token_use"`
	// Nonce speiles fra authorization-requesten (kun id_token, OIDC Core §2)
	// — lar klienten koble et id_token til nettopp sin egen /authorize-runde
	// og avvise et gjenbrukt/stjålet token fra en annen økt.
	Nonce string `json:"nonce,omitempty"`
}

// Issuer utsteder og validerer RS256 JWTs.
type Issuer struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	issuer     string
	defaultTTL time.Duration
	adminTTL   time.Duration
}

// NewIssuer oppretter en ny Issuer. Begge nøkler og issuer er påkrevd.
func NewIssuer(priv *rsa.PrivateKey, pub *rsa.PublicKey, issuer string, defaultTTL, adminTTL time.Duration) (*Issuer, error) {
	if priv == nil || pub == nil {
		return nil, fmt.Errorf("nøkler er påkrevd")
	}
	if issuer == "" {
		return nil, fmt.Errorf("issuer kan ikke være tom")
	}
	return &Issuer{
		privateKey: priv,
		publicKey:  pub,
		issuer:     issuer,
		defaultTTL: defaultTTL,
		adminTTL:   adminTTL,
	}, nil
}

// ParseISO8601Duration konverterer en ISO 8601-varighetsstreng til time.Duration.
// Støtter P[n]D, PT[n]H, PT[n]M, PT[n]S og kombinasjoner.
// Måneder (M utenfor T) behandles som 30 dager (tilnærming).
func ParseISO8601Duration(s string) (time.Duration, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "P") {
		return 0, fmt.Errorf("må starte med P: %s", s)
	}
	s = s[1:]
	inTime := false
	var total time.Duration
	for len(s) > 0 {
		if s[0] == 'T' {
			inTime = true
			s = s[1:]
			continue
		}
		i := 0
		for i < len(s) && s[i] >= '0' && s[i] <= '9' {
			i++
		}
		if i == 0 || i >= len(s) {
			return 0, fmt.Errorf("ugyldig varighet: %s", s)
		}
		n := 0
		for _, c := range s[:i] {
			n = n*10 + int(c-'0')
		}
		unit := s[i]
		s = s[i+1:]
		switch unit {
		case 'D':
			total += time.Duration(n) * 24 * time.Hour
		case 'H':
			if inTime {
				total += time.Duration(n) * time.Hour
			}
		case 'M':
			if inTime {
				total += time.Duration(n) * time.Minute
			} else {
				total += time.Duration(n) * 30 * 24 * time.Hour
			}
		case 'S':
			total += time.Duration(n) * time.Second
		default:
			return 0, fmt.Errorf("ukjent enhet %c", unit)
		}
	}
	return total, nil
}

// splitCSV deler en kommaseparert streng og trimmer whitespace. Tomme deler hoppes over.
func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (i *Issuer) buildClaims(user gen.User, ttl time.Duration, tokenUse string) Claims {
	now := time.Now().UTC()
	name := ""
	if user.Name != nil {
		name = *user.Name
	}
	return Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuer,
			Subject:   user.Email,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
		Email:    user.Email,
		Org:      splitCSV(user.Orgs),
		Groups:   splitCSV(user.Roles),
		Name:     name,
		TokenUse: tokenUse,
	}
}

func (i *Issuer) sign(claims Claims) (string, error) {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	s, err := tok.SignedString(i.privateKey)
	if err != nil {
		return "", fmt.Errorf("signere JWT: %w", err)
	}
	return s, nil
}

// IssueAccess utsteder et access-token for brukeren med TTL fra tjenestekonfigurasjon.
// Faller tilbake til defaultTTL hvis tjenestens AccessTokenTtl ikke kan tolkes.
func (i *Issuer) IssueAccess(user gen.User, svc gen.Service) (string, error) {
	ttl := i.defaultTTL
	if d, err := ParseISO8601Duration(svc.AccessTokenTtl); err == nil && d > 0 {
		ttl = d
	}
	return i.sign(i.buildClaims(user, ttl, "access"))
}

// IssueWithTTL utsteder et access-token med eksplisitt TTL. Brukes bl.a. for negative TTL i tester.
func (i *Issuer) IssueWithTTL(user gen.User, svc gen.Service, ttl time.Duration) (string, error) {
	return i.sign(i.buildClaims(user, ttl, "access"))
}

// IssueIDToken utsteder et ekte OIDC id_token (OIDC Core §2): aud=client_id
// (=tjeneste-ID, se service.Registry) og nonce speilet fra
// /authorize-requesten. Atskilt fra IssueAccess — et access-token har ingen
// aud/nonce og skal ikke tolkes som identitetsbevis av en klient, kun som
// bearer-credential mot ressursservere som stoler på kauth.
func (i *Issuer) IssueIDToken(user gen.User, svc gen.Service, nonce string) (string, error) {
	ttl := i.defaultTTL
	if d, err := ParseISO8601Duration(svc.AccessTokenTtl); err == nil && d > 0 {
		ttl = d
	}
	claims := i.buildClaims(user, ttl, "id")
	claims.Audience = jwt.ClaimStrings{svc.ID}
	claims.Nonce = nonce
	return i.sign(claims)
}

// IssueAdmin utsteder et admin-token. Hvis adminTTL <= 0 brukes Issuer sin standard adminTTL.
func (i *Issuer) IssueAdmin(user gen.User, adminTTL time.Duration) (string, error) {
	if adminTTL <= 0 {
		adminTTL = i.adminTTL
	}
	return i.sign(i.buildClaims(user, adminTTL, "admin"))
}

// Verify validerer et JWT-token og returnerer claims. Avviser utløpte tokens.
func (i *Issuer) Verify(tokenStr string) (*Claims, error) {
	claims := &Claims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("uventet signeringsmetode: %v", t.Header["alg"])
		}
		return i.publicKey, nil
	}, jwt.WithIssuer(i.issuer), jwt.WithExpirationRequired())
	if err != nil {
		return nil, fmt.Errorf("ugyldig token: %w", err)
	}
	if !tok.Valid {
		return nil, fmt.Errorf("token er ikke gyldig")
	}
	return claims, nil
}

// JWKSHandler returnerer den offentlige nøkkelen som JSON Web Key Set (RFC 7517).
func (i *Issuer) JWKSHandler(w http.ResponseWriter, r *http.Request) {
	pub := i.publicKey
	key := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "kauth-1",
		"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{key}})
}

// DiscoveryHandler returnerer et OpenID Connect discovery-dokument.
func (i *Issuer) DiscoveryHandler() http.HandlerFunc {
	doc := map[string]any{
		"issuer":                                i.issuer,
		"jwks_uri":                              i.issuer + "/.well-known/jwks.json",
		"authorization_endpoint":                i.issuer + "/login",
		"token_endpoint":                        i.issuer + "/token",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}
}
