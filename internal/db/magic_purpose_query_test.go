package db_test

import (
	"context"
	"database/sql"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

// purpose må stå i WHERE: en rad utstedt for én flyt skal ikke kunne hentes
// eller brukes opp av den andre, uansett hva Go-laget gjør etterpå.
func TestMagicTokenQueries_PurposeInWhere(t *testing.T) {
	_, q := openTestDB(t)
	ctx := context.Background()
	const now = "2026-06-01T12:00:00Z"
	const exp = "2026-06-01T12:15:00Z"
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "s", DisplayName: "S", Domain: "s.no", CallbackUrl: "https://s.no/cb",
		Theme: "light", AccentColor: "#000", EmailFromName: "S", JwtCookieName: "c",
		AccessTokenTtl: "PT15M", Active: 1, UpdatedAt: now,
	}))
	sid := "s"
	rows := []struct {
		hash, purpose string
		sid           *string
	}{{"h-admin", "admin", nil}, {"h-service", "service", &sid}}
	for _, r := range rows {
		require.NoError(t, seedMagic(ctx, q, gen.InsertMagicTokenLimitedParams{
			TokenHash: r.hash, Email: "a@x.no", ServiceID: r.sid, Purpose: r.purpose, CreatedAt: now, ExpiresAt: exp,
		}))
	}
	other := map[string]string{"admin": "service", "service": "admin"}
	for _, r := range rows {
		_, err := q.GetValidMagicTokenByHash(ctx, gen.GetValidMagicTokenByHashParams{TokenHash: r.hash, Purpose: other[r.purpose], Now: now})
		require.ErrorIs(t, err, sql.ErrNoRows, "Get "+r.hash)
		_, err = q.ConsumeMagicToken(ctx, gen.ConsumeMagicTokenParams{TokenHash: r.hash, Purpose: other[r.purpose], Now: now})
		require.ErrorIs(t, err, sql.ErrNoRows, "Consume feil formål "+r.hash)

		_, err = q.GetValidMagicTokenByHash(ctx, gen.GetValidMagicTokenByHashParams{TokenHash: r.hash, Purpose: r.purpose, Now: now})
		require.NoError(t, err)
		_, err = q.ConsumeMagicToken(ctx, gen.ConsumeMagicTokenParams{TokenHash: r.hash, Purpose: r.purpose, Now: now})
		require.NoError(t, err, "Consume riktig formål "+r.hash)
	}
}

// Henter SQL-en sqlc genererte for GetActiveUserByEmail, slik at planen
// vurderes på den faktiske spørringen og ikke en håndskrevet kopi.
func generatedQuery(t *testing.T, file, constName string) string {
	t.Helper()
	b, err := os.ReadFile("gen/" + file)
	require.NoError(t, err)
	m := regexp.MustCompile("(?s)const " + constName + " = `-- name: [^\n]*\n(.*?)`").FindStringSubmatch(string(b))
	require.NotNil(t, m, constName)
	return regexp.MustCompile(`\?\d+`).ReplaceAllString(strings.TrimSpace(m[1]), "?")
}

// seedMagic setter inn en rad uten å gå via kvoten: vindusstart i fremtiden
// gir alltid telling 0.
func seedMagic(ctx context.Context, q *gen.Queries, p gen.InsertMagicTokenLimitedParams) error {
	p.WindowStart = "9999"
	_, err := q.InsertMagicTokenLimited(ctx, p)
	return err
}
