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
	GetRefreshChild(ctx context.Context, arg gen.GetRefreshChildParams) (string, error)
}

// TxRunner kjører fn i én transaksjon. fn får en querier bundet til
// transaksjonen; feil fra fn gir rollback, nil gir commit.
type TxRunner func(ctx context.Context, fn func(q RefreshQuerier) error) error

// SQLTxRunner lager produksjonsløperen. Standard (deferred) BEGIN beholdes med
// vilje: rotasjonen starter med en UPDATE, så skrivelåsen tas ved første
// setning og busy_timeout gjelder. Det er ingen les-så-skriv i transaksjonen,
// så SQLITE_BUSY_SNAPSHOT kan ikke oppstå.
func SQLTxRunner(sqlDB *sql.DB) TxRunner {
	return func(ctx context.Context, fn func(q RefreshQuerier) error) (err error) {
		tx, err := sqlDB.BeginTx(ctx, nil)
		if err != nil {
			return fmt.Errorf("start transaksjon: %w", err)
		}
		// Panikk i fn må ikke etterlate en åpen transaksjon som holder skrivelåsen.
		defer func() {
			if p := recover(); p != nil {
				// Rollback-feil kan ikke rapporteres videre; panikken er viktigere.
				_ = tx.Rollback()
				panic(p)
			}
		}()
		if err := fn(gen.New(sqlDB).WithTx(tx)); err != nil {
			// Returnerer fn sin feil, ikke rollback-feilen: den er årsaken kalleren trenger.
			if rbErr := tx.Rollback(); rbErr != nil && !errors.Is(rbErr, sql.ErrTxDone) {
				slog.Error("rollback av refresh-transaksjon feilet", "err", rbErr)
			}
			return err
		}
		if err := tx.Commit(); err != nil {
			return fmt.Errorf("commit transaksjon: %w", err)
		}
		return nil
	}
}

type RefreshService struct {
	db    RefreshQuerier
	run   TxRunner
	audit *audit.Service
}

// NewRefreshService bygger både querier og transaksjonsløper fra samme
// *sql.DB, slik at produksjon ikke kan glemme transaksjonen.
func NewRefreshService(sqlDB *sql.DB, audit *audit.Service) *RefreshService {
	return &RefreshService{db: gen.New(sqlDB), run: SQLTxRunner(sqlDB), audit: audit}
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

	// Konsum og innsetting av barnet må være atomisk: feiler innsettingen, skal
	// forelderen fortsatt være ubrukt, ellers mister klienten sesjonen uten å
	// ha gjort noe galt. Bare q (tx-querieren) brukes inne i fn; s.db ville gitt
	// vranglås mot den åpne transaksjonen.
	var consumed gen.RefreshToken
	var newPlain string
	err := s.run(ctx, func(q RefreshQuerier) error {
		c, err := q.ConsumeRefreshToken(ctx, gen.ConsumeRefreshTokenParams{
			TokenHash: hash,
			ExpiresAt: now.Format(time.RFC3339),
		})
		if err != nil {
			return err
		}
		consumed = c

		newPlain, err = generatePlainToken()
		if err != nil {
			return err
		}
		exp, err := computeExpiresAt(now, consumed.FamilyExpiresAt)
		if err != nil {
			return err
		}
		parentID := consumed.ID
		if err := q.InsertRefreshToken(ctx, gen.InsertRefreshTokenParams{
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
			return fmt.Errorf("lagre rotert token: %w", err)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, s.classifyRejected(ctx, hash, ip, ua)
		}
		return nil, fmt.Errorf("rotere token: %w", err)
	}

	svcID := ""
	if consumed.ServiceID != nil {
		svcID = *consumed.ServiceID
	}
	// Audit etter COMMIT: en audit-feil eller -forsinkelse skal ikke holde
	// skrivelåsen, og en rullet tilbake rotasjon skal ikke logges som vellykket.
	s.audit.Log(ctx, audit.Event{Type: "refresh_token_rotated", Email: consumed.Email, ServiceID: svcID, IP: ip, UA: ua, Success: true})
	return &RotationResult{NewToken: newPlain, Email: consumed.Email, FamilyID: consumed.FamilyID, ServiceID: svcID}, nil
}

// classifyRejected skiller gjenbruk fra ukjent/utløpt/revokert token etter at
// konsum ga ErrNoRows. Kjøres utenfor transaksjonen: revokeringen er én UPDATE
// og atomisk i seg selv, og en samtidig rotasjons barn er committet før
// taperens konsum slipper til, så revokeringen treffer også barnet.
func (s *RefreshService) classifyRejected(ctx context.Context, hash, ip, ua string) error {
	// WithoutCancel: revokeringen og auditen må fullføres selv om klienten
	// kobler fra, ellers kan familien (og et samtidig barn) overleve gjenbruket.
	ctx = context.WithoutCancel(ctx)
	existing, err := s.db.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTokenRevoked
		}
		// Ikke maskér DB-feil som «ugyldig token»: da ville gjenbruk gå uoppdaget
		// og klienten få 401 for en feil den ikke har gjort.
		slog.Error("refresh: oppslag etter avvist token feilet", "err", err)
		return fmt.Errorf("slå opp avvist refresh-token: %w", err)
	}
	svcID := ""
	if existing.ServiceID != nil {
		svcID = *existing.ServiceID
	}
	if existing.Used == 1 {
		return s.handleReuse(ctx, existing, svcID, ip, ua)
	}
	if existing.Revoked == 1 {
		// Et revokert token som dukker opp igjen er en klient (eller angriper) med
		// et token fra en avsluttet sesjon. Resten av familien kan fortsatt leve,
		// så den tas ned. Utløpt-men-ikke-revokert er vanlig klokkeslitasje og
		// skal ikke koste brukeren de andre enhetene sine.
		reason := "revoked_token_presented"
		if err := s.db.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
			RevokedReason: &reason,
			FamilyID:      existing.FamilyID,
		}); err != nil {
			slog.Error("kunne ikke revokere refresh-familie ved revokert token", "family_id", existing.FamilyID, "err", err)
		}
		s.audit.Log(ctx, audit.Event{
			Type: "refresh_token_revoked_presented", Email: existing.Email,
			ServiceID: svcID, IP: ip, UA: ua, Success: false,
		})
	}
	return ErrTokenRevoked
}

func (s *RefreshService) handleReuse(ctx context.Context, existing gen.RefreshToken, svcID, ip, ua string) error {
	reason := "reuse_detected"
	if err := s.db.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
		RevokedReason: &reason,
		FamilyID:      existing.FamilyID,
	}); err != nil {
		slog.Error("kunne ikke revokere refresh-familie ved gjenbruk", "family_id", existing.FamilyID, "err", err)
	}
	// Gapet mellom rotasjonen og gjenbruket skiller en klient-race (sekunder)
	// fra et stjålet token (timer/dager).
	s.audit.Log(ctx, audit.Event{
		Type: "refresh_token_reuse", Email: existing.Email, ServiceID: svcID,
		IP: ip, UA: ua, Success: false, Details: s.reuseGap(ctx, existing),
	})
	return ErrTokenReuse
}

// reuseGap gir «gap_s=<n>» fra barnets opprettelse til nå, eller «gap_s=unknown»
// når barnet mangler eller tiden ikke lar seg tolke. Aldri feil: dette er bare
// diagnostikk og skal ikke hindre reuse-svaret.
func (s *RefreshService) reuseGap(ctx context.Context, existing gen.RefreshToken) string {
	parentID := existing.ID
	created, err := s.db.GetRefreshChild(ctx, gen.GetRefreshChildParams{FamilyID: existing.FamilyID, ParentID: &parentID})
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Error("refresh: oppslag av barn for reuse-gap feilet", "family_id", existing.FamilyID, "err", err)
		}
		return "gap_s=unknown"
	}
	return gapLabel(created, time.Now())
}

// gapLabel er ren for å kunne testes uten klokke. Framtidig created_at (klokkeskjev)
// gir 0 og ugyldig tid «unknown», så detaljfeltet alltid matcher mønsteret.
func gapLabel(created string, now time.Time) string {
	t, err := time.Parse(time.RFC3339, created)
	if err != nil {
		return "gap_s=unknown"
	}
	gap := int64(now.Sub(t).Seconds())
	if gap < 0 {
		gap = 0
	}
	return fmt.Sprintf("gap_s=%d", gap)
}

// RevokeFamily tilbakekaller hele familien (også brukte rader, som beholder
// første revoked_reason), inkludert barnet en rotasjon nettopp har laget. Feil logges bare: kalleren avviser uansett.
func (s *RefreshService) RevokeFamily(ctx context.Context, familyID, reason string) {
	if err := s.db.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
		RevokedReason: &reason,
		FamilyID:      familyID,
	}); err != nil {
		slog.Error("kunne ikke revokere refresh-familie", "family_id", familyID, "reason", reason, "err", err)
	}
}
