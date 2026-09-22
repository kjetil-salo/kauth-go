package jobs

import (
	"context"
	"log"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
)

type Cleanup struct {
	queries *gen.Queries
}

func NewCleanup(queries *gen.Queries) *Cleanup {
	return &Cleanup{queries: queries}
}

// Run starter tre cleanup-goroutiner med 1-times intervall.
// Blokkerer til ctx er kansellert.
func (c *Cleanup) Run(ctx context.Context) {
	magicTicker := time.NewTicker(1 * time.Hour)
	refreshTicker := time.NewTicker(1 * time.Hour)
	auditTicker := time.NewTicker(1 * time.Hour)
	authCodeTicker := time.NewTicker(1 * time.Hour)
	defer magicTicker.Stop()
	defer refreshTicker.Stop()
	defer auditTicker.Stop()
	defer authCodeTicker.Stop()

	// Kjør alle cleanup-runder umiddelbart ved oppstart
	c.cleanMagicTokens(ctx)
	c.cleanRefreshTokens(ctx)
	c.cleanAuditEvents(ctx)
	c.cleanAuthorizationCodes(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Println("cleanup: avslutter bakgrunnsjobber")
			return
		case <-magicTicker.C:
			c.cleanMagicTokens(ctx)
		case <-refreshTicker.C:
			c.cleanRefreshTokens(ctx)
		case <-auditTicker.C:
			c.cleanAuditEvents(ctx)
		case <-authCodeTicker.C:
			c.cleanAuthorizationCodes(ctx)
		}
	}
}

// cleanMagicTokens sletter brukte tokens og tokens eldre enn 24 timer.
// SQL: DELETE WHERE (used = 1 AND expires_at < ?) OR expires_at < ?
// Param 1 (ExpiresAt):   nåtid → sletter alle brukte tokens som allerede er utløpt
// Param 2 (ExpiresAt_2): 24t siden → sletter ubrukte tokens som er mer enn 24t gamle
func (c *Cleanup) cleanMagicTokens(ctx context.Context) {
	now := time.Now().UTC()
	err := c.queries.DeleteExpiredMagicTokens(ctx, gen.DeleteExpiredMagicTokensParams{
		ExpiresAt:   now.Format("2006-01-02T15:04:05Z"),
		ExpiresAt_2: now.Add(-24 * time.Hour).Format("2006-01-02T15:04:05Z"),
	})
	if err != nil {
		log.Printf("cleanup: feil ved sletting av magic tokens: %v", err)
		return
	}
	log.Printf("cleanup: slettet utløpte magic tokens (kjørt %s)", now.Format("15:04:05"))
}

// cleanRefreshTokens sletter refresh tokens der expires_at er passert
// og family_expires_at enten ikke er satt eller også er passert.
func (c *Cleanup) cleanRefreshTokens(ctx context.Context) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	err := c.queries.DeleteExpiredRefreshTokens(ctx, gen.DeleteExpiredRefreshTokensParams{
		ExpiresAt:       now,
		FamilyExpiresAt: &now,
	})
	if err != nil {
		log.Printf("cleanup: feil ved sletting av refresh tokens: %v", err)
		return
	}
	log.Printf("cleanup: slettet utløpte refresh tokens (kjørt %s)", time.Now().UTC().Format("15:04:05"))
}

// cleanAuthorizationCodes sletter autorisasjonskoder — de er kortlevde (60s)
// og engangsbrukte, så dette er ren opprydning, ikke en sikkerhetsmekanisme
// i seg selv (used=1-koder er allerede ubrukelige, jf. ConsumeAuthorizationCode).
func (c *Cleanup) cleanAuthorizationCodes(ctx context.Context) {
	now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
	err := c.queries.DeleteExpiredAuthorizationCodes(ctx, now)
	if err != nil {
		log.Printf("cleanup: feil ved sletting av authorization codes: %v", err)
		return
	}
	log.Printf("cleanup: slettet utløpte authorization codes (kjørt %s)", time.Now().UTC().Format("15:04:05"))
}

// cleanAuditEvents sletter audit-hendelser eldre enn 90 dager.
func (c *Cleanup) cleanAuditEvents(ctx context.Context) {
	cutoff := time.Now().UTC().Add(-90 * 24 * time.Hour).Format("2006-01-02T15:04:05Z")
	err := c.queries.DeleteOldAuditEvents(ctx, cutoff)
	if err != nil {
		log.Printf("cleanup: feil ved sletting av audit events: %v", err)
		return
	}
	log.Printf("cleanup: slettet audit events eldre enn 90 dager (grense: %s)", cutoff)
}
