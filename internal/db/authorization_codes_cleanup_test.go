package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

// TestDeleteExpiredAuthorizationCodes_RunsAgainstMigratedSchema kjører selve
// spørringen mot en ekte (migrert) SQLite-database, ikke bare mot
// .sql-kildefilen. Dette er den eneste testen som ville fanget
// sqlc-genereringsbuggen der den innebygde SQL-strengen for denne
// spørringen ble kuttet til "DELETE FROM authorization_codes WHERE expires"
// (ugyldig kolonnenavn) — cleanup.go feilet dermed hver time i prod uten at
// noen eksisterende test kalte DeleteExpiredAuthorizationCodes i det hele
// tatt. Se CHANGELOG for detaljer om selve sqlc-buggen.
func TestDeleteExpiredAuthorizationCodes_RunsAgainstMigratedSchema(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)

	now := time.Now().UTC()
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
		CallbackUrl: "https://veivakt.app/auth/callback",
		Theme:       "light", AccentColor: "#000", EmailFromName: "Veivakt",
		AutoRegister: 1, AuthGoogle: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now.Format(time.RFC3339),
	}))

	insert := func(code, expires string) {
		t.Helper()
		require.NoError(t, q.InsertAuthorizationCode(ctx, gen.InsertAuthorizationCodeParams{
			Code: code, ServiceID: "veivakt", Email: "sjafor@example.com",
			RedirectUri: "https://veivakt.app/auth/callback",
			CodeChallenge: "challenge", CodeChallengeMethod: "S256",
			CreatedAt: now.Add(-2 * time.Minute).Format("2006-01-02T15:04:05Z"),
			ExpiresAt: expires,
		}))
	}

	insert("expired", now.Add(-1*time.Minute).Format("2006-01-02T15:04:05Z"))
	insert("still-valid", now.Add(1*time.Minute).Format("2006-01-02T15:04:05Z"))

	err := q.DeleteExpiredAuthorizationCodes(ctx, now.Format("2006-01-02T15:04:05Z"))
	require.NoError(t, err, "spørringen må kjøre mot den faktiske authorization_codes-tabellen uten SQL-feil")

	var remaining []string
	rows, err := sqldb.QueryContext(ctx, "SELECT code FROM authorization_codes")
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var code string
		require.NoError(t, rows.Scan(&code))
		remaining = append(remaining, code)
	}
	require.NoError(t, rows.Err())

	assert.Equal(t, []string{"still-valid"}, remaining, "kun den utløpte koden skal være slettet")
}
