package db_test

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

type revokeRow struct {
	revoked int64
	reason  sql.NullString
}

func insertRT(t *testing.T, q *gen.Queries, seed, email, family string, parent *int64) {
	t.Helper()
	require.NoError(t, q.InsertRefreshToken(context.Background(), gen.InsertRefreshTokenParams{
		TokenHash: hash64(seed), Email: email, FamilyID: family, ParentID: parent,
		CreatedAt: "2026-10-01T10:00:00Z", ExpiresAt: "2027-01-01T10:00:00Z",
	}))
}

func rtState(t *testing.T, sqldb *sql.DB, seed string) revokeRow {
	t.Helper()
	var r revokeRow
	require.NoError(t, sqldb.QueryRow(
		"SELECT revoked, revoked_reason FROM refresh_tokens WHERE token_hash = ?", hash64(seed)).
		Scan(&r.revoked, &r.reason))
	return r
}

// Brukte rader må revokeres: et barn fra en samtidig rotasjon kan ha used=1
// når reuse oppdages, og skal ikke overleve familie-revokeringen.
func TestRevokeFamilyTokens_IncludesUsedRows(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)

	insertRT(t, q, "unused", "a@x.no", "fam-1", nil)
	insertRT(t, q, "used", "a@x.no", "fam-1", nil)
	insertRT(t, q, "other", "a@x.no", "fam-2", nil)
	_, err := sqldb.Exec("UPDATE refresh_tokens SET used = 1 WHERE token_hash = ?", hash64("used"))
	require.NoError(t, err)

	reason := "reuse"
	require.NoError(t, q.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
		RevokedReason: &reason, FamilyID: "fam-1",
	}))

	assert.EqualValues(t, 1, rtState(t, sqldb, "unused").revoked)
	assert.EqualValues(t, 1, rtState(t, sqldb, "used").revoked)
	assert.EqualValues(t, 0, rtState(t, sqldb, "other").revoked, "annen familie skal være urørt")
}

func TestRevokeFamilyTokens_KeepsFirstReason(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)

	insertRT(t, q, "old", "a@x.no", "fam-1", nil)
	insertRT(t, q, "new", "a@x.no", "fam-1", nil)
	_, err := sqldb.Exec("UPDATE refresh_tokens SET revoked = 1, revoked_reason = 'user_logout' WHERE token_hash = ?", hash64("old"))
	require.NoError(t, err)

	reason := "reuse"
	require.NoError(t, q.RevokeFamilyTokens(ctx, gen.RevokeFamilyTokensParams{
		RevokedReason: &reason, FamilyID: "fam-1",
	}))

	assert.Equal(t, "user_logout", rtState(t, sqldb, "old").reason.String)
	assert.Equal(t, "reuse", rtState(t, sqldb, "new").reason.String)
}

func TestRevokeUserRefreshTokens_OnlyThatUser(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)

	insertRT(t, q, "a1", "a@x.no", "fam-1", nil)
	insertRT(t, q, "a2", "a@x.no", "fam-2", nil)
	insertRT(t, q, "a3", "a@x.no", "fam-3", nil)
	insertRT(t, q, "b1", "b@x.no", "fam-4", nil)
	insertRT(t, q, "upper", "A@x.no", "fam-5", nil)
	_, err := sqldb.Exec("UPDATE refresh_tokens SET revoked = 1, revoked_reason = 'user_logout' WHERE token_hash = ?", hash64("a3"))
	require.NoError(t, err)

	reason := "user_deactivated"
	n, err := q.RevokeUserRefreshTokens(ctx, gen.RevokeUserRefreshTokensParams{
		RevokedReason: &reason, Email: "a@x.no",
	})
	require.NoError(t, err)
	assert.EqualValues(t, 2, n, "bare ikke-revokerte rader telles")

	assert.Equal(t, "user_deactivated", rtState(t, sqldb, "a1").reason.String)
	assert.Equal(t, "user_deactivated", rtState(t, sqldb, "a2").reason.String)
	assert.Equal(t, "user_logout", rtState(t, sqldb, "a3").reason.String)
	assert.EqualValues(t, 0, rtState(t, sqldb, "b1").revoked)
	assert.EqualValues(t, 0, rtState(t, sqldb, "upper").revoked, "e-post matches eksakt")
}

func TestGetRefreshChild(t *testing.T) {
	ctx := context.Background()
	sqldb, q := openTestDB(t)

	insertRT(t, q, "parent", "a@x.no", "fam-1", nil)
	var parentID int64
	require.NoError(t, sqldb.QueryRow("SELECT id FROM refresh_tokens WHERE token_hash = ?", hash64("parent")).Scan(&parentID))
	insertRT(t, q, "child", "a@x.no", "fam-1", &parentID)

	created, err := q.GetRefreshChild(ctx, gen.GetRefreshChildParams{FamilyID: "fam-1", ParentID: &parentID})
	require.NoError(t, err)
	assert.Equal(t, "2026-10-01T10:00:00Z", created)

	var childID int64
	require.NoError(t, sqldb.QueryRow("SELECT id FROM refresh_tokens WHERE token_hash = ?", hash64("child")).Scan(&childID))
	_, err = q.GetRefreshChild(ctx, gen.GetRefreshChildParams{FamilyID: "fam-1", ParentID: &childID})
	assert.ErrorIs(t, err, sql.ErrNoRows)
}
