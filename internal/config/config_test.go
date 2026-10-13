package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseISO8601(t *testing.T) {
	cases := []struct {
		input    string
		expected string
	}{
		{"PT15M", "15m0s"},
		{"PT8H", "8h0m0s"},
		{"P30D", "720h0m0s"},
		{"PT1H30M", "1h30m0s"},
		{"P1DT2H", "26h0m0s"},
	}
	for _, c := range cases {
		d, err := parseISO8601(c.input)
		require.NoError(t, err, c.input)
		assert.Equal(t, c.expected, d.String(), c.input)
	}
}

func TestParseISO8601_Invalid(t *testing.T) {
	_, err := parseISO8601("invalid")
	assert.Error(t, err)
}

// setMinimalEnv gir en gyldig konfig slik at bare bryteren varierer.
func setMinimalEnv(t *testing.T) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	priv := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	pubDER, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
	require.NoError(t, err)
	pub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	t.Setenv("KAUTH_DB_PATH", ":memory:")
	t.Setenv("KAUTH_ISSUER", "https://i.test")
	t.Setenv("KAUTH_BASE_URL", "https://i.test")
	t.Setenv("KAUTH_PRIVATE_KEY_PEM", base64.StdEncoding.EncodeToString(priv))
	t.Setenv("KAUTH_PUBLIC_KEY_PEM", base64.StdEncoding.EncodeToString(pub))
	t.Setenv("KAUTH_OIDC_STATE_SECRET", base64.StdEncoding.EncodeToString(make([]byte, 32)))
	t.Setenv("KAUTH_SMTP_MOCK", "true")
}

func TestLoad_PasswordLoginEnabled(t *testing.T) {
	setMinimalEnv(t)

	t.Run("ikke satt", func(t *testing.T) {
		t.Setenv("KAUTH_PASSWORD_LOGIN_ENABLED", "")
		os.Unsetenv("KAUTH_PASSWORD_LOGIN_ENABLED")
		c, err := Load()
		require.NoError(t, err)
		assert.False(t, c.PasswordLoginEnabled)
	})
	for v, want := range map[string]bool{"": false, "false": false, "true": true} {
		t.Run("verdi "+v, func(t *testing.T) {
			t.Setenv("KAUTH_PASSWORD_LOGIN_ENABLED", v)
			c, err := Load()
			require.NoError(t, err)
			assert.Equal(t, want, c.PasswordLoginEnabled)
		})
	}
	for _, v := range []string{"TRUE", "True", "1", "yes", "on", " true"} {
		t.Run("ugyldig "+v, func(t *testing.T) {
			t.Setenv("KAUTH_PASSWORD_LOGIN_ENABLED", v)
			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "KAUTH_PASSWORD_LOGIN_ENABLED")
		})
	}
}
