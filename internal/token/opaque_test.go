package token_test

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/token"
)

func TestHashOpaque(t *testing.T) {
	h := token.HashOpaque("hemmelig")
	require.Regexp(t, regexp.MustCompile(`^[0-9a-f]{64}$`), h)
	require.Equal(t, h, token.HashOpaque("hemmelig"))
	require.NotEqual(t, h, token.HashOpaque("hemmelig2"))
}

func TestCheckMagicPurpose(t *testing.T) {
	svc := "klarsyn"
	cases := []struct {
		name    string
		purpose string
		svc     *string
		ok      bool
	}{
		{"service med tjeneste", token.MagicPurposeService, &svc, true},
		{"service uten tjeneste", token.MagicPurposeService, nil, false},
		{"admin uten tjeneste", token.MagicPurposeAdmin, nil, true},
		{"admin med tjeneste", token.MagicPurposeAdmin, &svc, false},
		{"ukjent formål", "annet", nil, false},
		{"tomt formål", "", &svc, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := token.CheckMagicPurpose(c.purpose, c.svc)
			if c.ok {
				require.NoError(t, err)
			} else {
				require.Error(t, err)
			}
		})
	}
}
