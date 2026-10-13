package auth_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
)

var emailCases = []struct{ name, in, want string }{
	{"mellomrom rundt", "  Lars@X.no  ", "lars@x.no"},
	{"store bokstaver", "LARS@X.NO", "lars@x.no"},
	{"tom streng", "", ""},
	{"bare mellomrom", "   ", ""},
	{"tab og linjeskift", "\t\n Lars@X.no \r\n", "lars@x.no"},
	{"unicode bevares og bretter", "ÅSE@Ø.no", "åse@ø.no"},
	{"alt er allerede normalt", "a@x.no", "a@x.no"},
	{"indre mellomrom bevares", "a b@x.no", "a b@x.no"},
}

func TestNormalizeEmail(t *testing.T) {
	for _, c := range emailCases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, auth.NormalizeEmail(c.in))
		})
	}
}

// SS1: NormalizeEmail må være et fast punkt for SQLite lower(trim(x)), ellers
// treffer ikke brukeroppslaget og den unike indeksen den normaliserte raden.
func TestNormalizeEmail_FixedPointInSQLite(t *testing.T) {
	sqldb, _, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	inputs := []string{
		"A@X.no", " a@x.no ", "\ta@x.no\t", "\n a@x.no\r\n", "É@X.no", "ÅSE@Ø.no",
		"İ@x.no", "K@x.no", "ß@X.no", "a@x.no ", " A@x.no ",
		"a\tb@x.no", "", "   ", "\t", "a@x.no\x00", "\xffA@x.no", "Σ@x.no",
	}
	for _, in := range inputs {
		n := auth.NormalizeEmail(in)
		var sqlForm string
		require.NoError(t, sqldb.QueryRow(`SELECT lower(trim(?))`, n).Scan(&sqlForm))
		require.Equal(t, n, sqlForm, "inn: %q", in)
	}
}
