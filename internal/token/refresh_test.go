package token_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

type stubRefreshDB struct {
	tokens []gen.RefreshToken
	nextID int64
}

func (s *stubRefreshDB) InsertRefreshToken(_ context.Context, p gen.InsertRefreshTokenParams) error {
	s.tokens = append(s.tokens, gen.RefreshToken{
		ID: s.nextID, TokenHash: p.TokenHash, Email: p.Email,
		ServiceID: p.ServiceID, FamilyID: p.FamilyID, ParentID: p.ParentID,
		ExpiresAt: p.ExpiresAt, FamilyExpiresAt: p.FamilyExpiresAt,
		Used: 0, Revoked: 0,
	})
	s.nextID++
	return nil
}

func (s *stubRefreshDB) ConsumeRefreshToken(_ context.Context, arg gen.ConsumeRefreshTokenParams) (gen.RefreshToken, error) {
	for i, t := range s.tokens {
		if t.TokenHash == arg.TokenHash {
			// Real SQL filters: used=0 AND revoked=0 AND expires_at > ?
			if t.Used != 0 || t.Revoked != 0 {
				return gen.RefreshToken{}, sql.ErrNoRows
			}
			s.tokens[i].Used = 1
			return t, nil // return pre-update row (valid token, just marked used)
		}
	}
	return gen.RefreshToken{}, sql.ErrNoRows
}

func (s *stubRefreshDB) GetRefreshTokenByHash(_ context.Context, hash string) (gen.RefreshToken, error) {
	for _, t := range s.tokens {
		if t.TokenHash == hash {
			return t, nil
		}
	}
	return gen.RefreshToken{}, sql.ErrNoRows
}

func (s *stubRefreshDB) RevokeFamilyTokens(_ context.Context, p gen.RevokeFamilyTokensParams) error {
	for i, t := range s.tokens {
		if t.FamilyID == p.FamilyID {
			s.tokens[i].Revoked = 1
			s.tokens[i].RevokedReason = p.RevokedReason
		}
	}
	return nil
}

func newTestRefreshSvc(db token.RefreshQuerier) *token.RefreshService {
	return token.NewRefreshService(db, audit.NewNoop())
}

func TestRotate_IssueAndRotate(t *testing.T) {
	db := &stubRefreshDB{}
	svc := newTestRefreshSvc(db)
	ctx := context.Background()
	plain, err := svc.Issue(ctx, testUser(), testService(), "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	result, err := svc.Rotate(ctx, plain, "127.0.0.1", "ua")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if result.Email != "test@example.com" {
		t.Errorf("feil email")
	}
	if result.NewToken == plain {
		t.Error("token ikke rotert")
	}
}

func TestRotate_Reuse_RevokeFamily(t *testing.T) {
	db := &stubRefreshDB{}
	svc := newTestRefreshSvc(db)
	ctx := context.Background()
	plain, _ := svc.Issue(ctx, testUser(), testService(), "127.0.0.1", "ua")
	result, _ := svc.Rotate(ctx, plain, "127.0.0.1", "ua")
	// Gjenbruk av originalt token
	_, err := svc.Rotate(ctx, plain, "127.0.0.1", "ua")
	if err == nil {
		t.Fatal("forventet ErrTokenReuse")
	}
	// Nytt token (fra rotasjon) skal også være ugyldig
	_, err = svc.Rotate(ctx, result.NewToken, "127.0.0.1", "ua")
	if err == nil {
		t.Fatal("forventet feil — familie tilbakekalt")
	}
}

func TestRotate_FamilyExpiresAt_Inherited(t *testing.T) {
	maxAge := "P7D"
	svcWithAge := gen.Service{ID: "s", AccessTokenTtl: "PT15M", RefreshTokenMaxAge: &maxAge}
	db := &stubRefreshDB{}
	svc := newTestRefreshSvc(db)
	ctx := context.Background()
	plain, _ := svc.Issue(ctx, testUser(), svcWithAge, "127.0.0.1", "ua")
	if db.tokens[0].FamilyExpiresAt == nil {
		t.Fatal("family_expires_at skal være satt")
	}
	svc.Rotate(ctx, plain, "127.0.0.1", "ua")
	if len(db.tokens) < 2 {
		t.Fatal("mangler rotert token")
	}
	if *db.tokens[0].FamilyExpiresAt != *db.tokens[1].FamilyExpiresAt {
		t.Error("family_expires_at ikke arvet ved rotasjon")
	}
}
