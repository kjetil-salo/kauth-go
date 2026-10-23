package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
)

var ErrTokenReuse = errors.New("refresh-token gjenbruk oppdaget — familie tilbakekalt")
var ErrTokenRevoked = errors.New("refresh-token er tilbakekalt")

type RotationResult struct {
	NewToken, Email, FamilyID string
	// Resource og Scope er fullmakten raden ble utstedt med (RFC 8707 +
	// RFC 6749 §3.3), lest fra den konsumerte raden. Tom Resource betyr at
	// tokenet ikke ble utstedt mot noen ressursindikator — da skal
	// access-tokenet utstedes uten aud, som før.
	Resource, Scope string
}

// RefreshQuerier er interfacet RefreshService trenger fra DB-laget.
// Eksportert slik at tester kan injisere stubs.
type RefreshQuerier interface {
	InsertRefreshToken(ctx context.Context, params gen.InsertRefreshTokenParams) error
	ConsumeRefreshToken(ctx context.Context, arg gen.ConsumeRefreshTokenParams) (gen.RefreshToken, error)
	GetRefreshTokenByHash(ctx context.Context, tokenHash string) (gen.RefreshToken, error)
	RevokeFamilyTokens(ctx context.Context, params gen.RevokeFamilyTokensParams) error
}

type RefreshService struct {
	db    RefreshQuerier
	audit *audit.Service
}

func NewRefreshService(db RefreshQuerier, audit *audit.Service) *RefreshService {
	return &RefreshService{db: db, audit: audit}
}

func generatePlainToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// tomSomNull lagrer "" som NULL, slik at en rad uten fullmakt ikke kan
// forveksles med en som ba om en tom aud.
func tomSomNull(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}

func strEllerTom(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func hashToken(plain string) string {
	s := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(s[:])
}

func generateFamilyID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// computeExpiresAt returnerer min(now+30d, familyExpiresAt).
func computeExpiresAt(now time.Time, familyExpStr *string) (time.Time, error) {
	std := now.Add(30 * 24 * time.Hour)
	if familyExpStr == nil {
		return std, nil
	}
	t, err := time.Parse(time.RFC3339, *familyExpStr)
	if err != nil {
		return time.Time{}, fmt.Errorf("tolke family_expires_at: %w", err)
	}
	if t.Before(std) {
		return t, nil
	}
	return std, nil
}

// Issue utsteder et refresh-token uten fullmakt — bespoke-flyten (magic
// link, passord, Google, Microsoft), der tokenet bare beviser innlogging.
func (s *RefreshService) Issue(ctx context.Context, user gen.User, svc gen.Service, ip, ua string) (string, error) {
	return s.IssueForResource(ctx, user, svc, ip, ua, "", "")
}

// IssueForResource er Issue, men lagrer resource og scope på raden slik at
// hver fornyelse kan utstede et access-token med samme aud og scope som det
// første. Brukt av authorization_code-grant: uten dette lever en delegert
// fullmakt bare til access-tokenet utløper, siden autorisasjonskoden er
// konsumert og ingenting annet husker hva klienten fikk.
func (s *RefreshService) IssueForResource(ctx context.Context, user gen.User, svc gen.Service, ip, ua, resource, scope string) (string, error) {
	plain, err := generatePlainToken()
	if err != nil {
		return "", err
	}
	familyID, err := generateFamilyID()
	if err != nil {
		return "", err
	}
	now := time.Now().UTC()

	var familyExpStr *string
	if svc.RefreshTokenMaxAge != nil && *svc.RefreshTokenMaxAge != "" {
		d, err := ParseISO8601Duration(*svc.RefreshTokenMaxAge)
		if err != nil {
			return "", fmt.Errorf("tolke RefreshTokenMaxAge: %w", err)
		}
		t := now.Add(d).Format(time.RFC3339)
		familyExpStr = &t
	}

	exp, err := computeExpiresAt(now, familyExpStr)
	if err != nil {
		return "", err
	}

	svcID := svc.ID
	if err := s.db.InsertRefreshToken(ctx, gen.InsertRefreshTokenParams{
		TokenHash:       hashToken(plain),
		Email:           user.Email,
		ServiceID:       &svcID,
		FamilyID:        familyID,
		ParentID:        nil,
		CreatedAt:       now.Format(time.RFC3339),
		ExpiresAt:       exp.Format(time.RFC3339),
		FamilyExpiresAt: familyExpStr,
		IpAddress:       nil,
		UserAgent:       nil,
		Resource:        tomSomNull(resource),
		Scope:           tomSomNull(scope),
	}); err != nil {
		return "", fmt.Errorf("lagre refresh-token: %w", err)
	}
	s.audit.Log(ctx, audit.Event{Type: "refresh_token_issued", Email: user.Email, ServiceID: svc.ID, IP: ip, UA: ua, Success: true})
	return plain, nil
}

func (s *RefreshService) Rotate(ctx context.Context, plainToken, ip, ua string) (*RotationResult, error) {
	hash := hashToken(plainToken)
	now := time.Now().UTC()
	consumed, err := s.db.ConsumeRefreshToken(ctx, gen.ConsumeRefreshTokenParams{
		TokenHash: hash,
		ExpiresAt: now.Format(time.RFC3339),
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// ErrNoRows means: token not found, OR used=1, OR revoked=1, OR expired.
			// Look up the row unconditionally to distinguish reuse from unknown token.
			existing, fetchErr := s.db.GetRefreshTokenByHash(ctx, hash)
			if fetchErr == nil {
				if existing.Used != 0 {
					// REPLAY DETECTED: revoke the whole family.
					reason := "reuse_detected"
					_ = s.db.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
						RevokedReason: &reason,
						FamilyID:      existing.FamilyID,
					})
					s.audit.Log(ctx, audit.Event{
						Type: "refresh_token_reuse", Email: existing.Email,
						IP: ip, UA: ua, Success: false,
					})
					return nil, ErrTokenReuse
				}
				// Revoked or expired — treat as revoked/invalid.
				return nil, ErrTokenRevoked
			}
			// Truly unknown token.
			return nil, ErrTokenRevoked
		}
		return nil, fmt.Errorf("consume token: %w", err)
	}

	newPlain, err := generatePlainToken()
	if err != nil {
		return nil, err
	}
	exp, err := computeExpiresAt(now, consumed.FamilyExpiresAt)
	if err != nil {
		return nil, err
	}

	parentID := consumed.ID
	if err := s.db.InsertRefreshToken(ctx, gen.InsertRefreshTokenParams{
		TokenHash:       hashToken(newPlain),
		Email:           consumed.Email,
		ServiceID:       consumed.ServiceID,
		FamilyID:        consumed.FamilyID,
		ParentID:        &parentID,
		CreatedAt:       now.Format(time.RFC3339),
		ExpiresAt:       exp.Format(time.RFC3339),
		FamilyExpiresAt: consumed.FamilyExpiresAt,
		IpAddress:       nil,
		UserAgent:       nil,
		// Fullmakten arves fra forelderen, aldri fra request-en: klienten
		// skal ikke kunne utvide aud eller scope ved å fornye.
		Resource: consumed.Resource,
		Scope:    consumed.Scope,
	}); err != nil {
		return nil, fmt.Errorf("lagre rotert token: %w", err)
	}

	svcID := ""
	if consumed.ServiceID != nil {
		svcID = *consumed.ServiceID
	}
	s.audit.Log(ctx, audit.Event{Type: "refresh_token_rotated", Email: consumed.Email, ServiceID: svcID, IP: ip, UA: ua, Success: true})
	return &RotationResult{
		NewToken: newPlain, Email: consumed.Email, FamilyID: consumed.FamilyID,
		Resource: strEllerTom(consumed.Resource), Scope: strEllerTom(consumed.Scope),
	}, nil
}
