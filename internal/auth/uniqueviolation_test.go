package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

func TestIsUniqueViolation(t *testing.T) {
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	sqldb.SetMaxOpenConns(1)
	ctx := context.Background()
	p := gen.CreateUserParams{Email: "a@b.no", Roles: "user", CreatedAt: "2026-01-01T00:00:00Z"}
	_, err = q.CreateUser(ctx, p)
	require.NoError(t, err)

	_, err = q.CreateUser(ctx, gen.CreateUserParams{Email: "A@B.no", Roles: "user", CreatedAt: p.CreatedAt})
	require.Error(t, err)
	require.True(t, isUniqueViolation(err))

	require.False(t, isUniqueViolation(nil))
	require.False(t, isUniqueViolation(errors.New("annen feil")))

	require.NoError(t, sqldb.Close())
	_, err = q.CreateUser(ctx, gen.CreateUserParams{Email: "c@d.no", Roles: "user", CreatedAt: p.CreatedAt})
	require.Error(t, err)
	require.False(t, isUniqueViolation(err))
}
