package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)

func openRaw(t *testing.T) *sql.DB {
	t.Helper()
	d, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "m.db")+"?_pragma=foreign_keys(1)")
	require.NoError(t, err)
	t.Cleanup(func() { d.Close() })
	setupGoose.Do(func() {
		goose.SetBaseFS(migrations)
		goose.SetDialect("sqlite3") //nolint:errcheck
		goose.SetLogger(goose.NopLogger())
	})
	return d
}

func hasColumn(t *testing.T, d *sql.DB, table, col string) bool {
	t.Helper()
	rows, err := d.Query("SELECT name FROM pragma_table_info(?)", table)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var n string
		require.NoError(t, rows.Scan(&n))
		if n == col {
			return true
		}
	}
	return false
}

func hasIndex(t *testing.T, d *sql.DB, name string) bool {
	t.Helper()
	var n int
	require.NoError(t, d.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?", name).Scan(&n))
	return n == 1
}

func TestMigrations_UpDownUp(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.Up(d, "migrations"))
	require.True(t, hasColumn(t, d, "magic_tokens", "purpose"))
	require.True(t, hasColumn(t, d, "authorization_codes", "family_id"))
	require.True(t, hasIndex(t, d, "idx_users_email_norm"))

	require.NoError(t, goose.DownTo(d, "migrations", 7))
	require.False(t, hasColumn(t, d, "magic_tokens", "purpose"))
	require.False(t, hasColumn(t, d, "authorization_codes", "family_id"))
	require.False(t, hasIndex(t, d, "idx_users_email_norm"))

	require.NoError(t, goose.Up(d, "migrations"))
	require.True(t, hasColumn(t, d, "magic_tokens", "purpose"))
	require.True(t, hasIndex(t, d, "idx_users_email_norm"))
}

func TestMigration008_EmptiesTables(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 7))
	_, err := d.Exec(`INSERT INTO magic_tokens (token,email,expires_at) VALUES ('klartekst','a@x.no','2099-01-01T00:00:00Z')`)
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO services (id,display_name,domain,callback_url,email_from_name,updated_at) VALUES ('s','S','s.no','https://s.no/cb','S','2026-01-01T00:00:00Z')`)
	require.NoError(t, err)
	_, err = d.Exec(`INSERT INTO authorization_codes (code,service_id,email,redirect_uri,code_challenge,code_challenge_method,expires_at) VALUES ('klartekst','s','a@x.no','https://s.no/cb','c','S256','2099-01-01T00:00:00Z')`)
	require.NoError(t, err)

	require.NoError(t, goose.UpTo(d, "migrations", 8))
	for _, tbl := range []string{"magic_tokens", "authorization_codes"} {
		var n int
		require.NoError(t, d.QueryRow("SELECT COUNT(*) FROM "+tbl).Scan(&n))
		require.Zero(t, n, tbl)
	}
}

func TestMigration009_FailsOnCaseDuplicates(t *testing.T) {
	d := openRaw(t)
	require.NoError(t, goose.UpTo(d, "migrations", 8))
	for _, e := range []string{"A@x.no", "a@x.no "} {
		_, err := d.Exec(`INSERT INTO users (email,roles,orgs,created_at) VALUES (?, 'user','o','2026-01-01T00:00:00Z')`, e)
		require.NoError(t, err)
	}
	require.Error(t, goose.UpTo(d, "migrations", 9))
}
