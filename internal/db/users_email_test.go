package db_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

func TestUsersEmailNormIndex_RejectsCaseDuplicate(t *testing.T) {
	_, q := openTestDB(t)
	ctx := context.Background()
	_, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "a@x.no", Roles: "user", Orgs: "o", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	_, err = q.CreateUser(ctx, gen.CreateUserParams{Email: " A@X.no", Roles: "user", Orgs: "o", CreatedAt: "2026-01-01T00:00:00Z"})
	require.Error(t, err)
}

func TestGetActiveUserByEmail_CaseInsensitive(t *testing.T) {
	_, q := openTestDB(t)
	ctx := context.Background()
	_, err := q.CreateUser(ctx, gen.CreateUserParams{Email: "a@x.no", Roles: "user", Orgs: "o", CreatedAt: "2026-01-01T00:00:00Z"})
	require.NoError(t, err)
	u, err := q.GetActiveUserByEmail(ctx, " A@X.NO ")
	require.NoError(t, err)
	require.Equal(t, "a@x.no", u.Email)
	u, err = q.GetUserByEmail(ctx, "A@x.no")
	require.NoError(t, err)
	require.Equal(t, "a@x.no", u.Email)
}

func TestGetActiveUserByEmail_UsesNormIndex(t *testing.T) {
	sqldb, _ := openTestDB(t)
	query := generatedQuery(t, "users.sql.go", "getActiveUserByEmail")
	require.Contains(t, query, "lower(trim(email))")
	rows, err := sqldb.Query("EXPLAIN QUERY PLAN "+query, "A@x.no")
	require.NoError(t, err)
	defer rows.Close()
	var plan []string
	for rows.Next() {
		var id, parent, notused int
		var detail string
		require.NoError(t, rows.Scan(&id, &parent, &notused, &detail))
		plan = append(plan, detail)
	}
	require.Contains(t, strings.Join(plan, "\n"), "idx_users_email_norm")
}
