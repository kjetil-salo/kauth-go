package token

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
)

var ErrTokenReuse = errors.New("refresh-token gjenbruk oppdaget — familie tilbakekalt")
var ErrTokenRevoked = errors.New("refresh-token er tilbakekalt")

// ServiceID er tjenesten lagret på den konsumerte raden; tom når raden har NULL.
type RotationResult struct{ NewToken, Email, FamilyID, ServiceID string }

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

func (s *RefreshService) Issue(ctx context.Context, user gen.User, svc gen.Service, ip, ua string) (string, error) {
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
	}); err != nil {
		return nil, fmt.Errorf("lagre rotert token: %w", err)
	}

	svcID := ""
	if consumed.ServiceID != nil {
		svcID = *consumed.ServiceID
	}
	s.audit.Log(ctx, audit.Event{Type: "refresh_token_rotated", Email: consumed.Email, ServiceID: svcID, IP: ip, UA: ua, Success: true})
	return &RotationResult{NewToken: newPlain, Email: consumed.Email, FamilyID: consumed.FamilyID, ServiceID: svcID}, nil
}

// RevokeFamily tilbakekaller alle ubrukte tokens i familien, inkludert barnet
// en rotasjon nettopp har laget. Feil logges bare: kalleren avviser uansett.
func (s *RefreshService) RevokeFamily(ctx context.Context, familyID, reason string) {
	if err := s.db.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
		RevokedReason: &reason,
		FamilyID:      familyID,
	}); err != nil {
		slog.Error("kunne ikke revokere refresh-familie", "family_id", familyID, "reason", reason, "err", err)
	}
}
