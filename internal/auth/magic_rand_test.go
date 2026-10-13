package auth

import (
	"errors"
	"html/template"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/config"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/mail"
	"github.com/zral/kauth-go/internal/service"
)

// 008 F6 (K16): feil i tilfeldighetskilden skal ikke gi lagret eller sendt token.
func TestMagicRequest_RandFailure_NoTokenNoMail(t *testing.T) {
	sqldb, q, err := db.OpenMemory()
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	old := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("ingen entropi") }
	t.Cleanup(func() { randRead = old })

	// Mock-mailen skriver til stdout; fanger den for å bevise at ingenting ble sendt.
	pr, pw, err := os.Pipe()
	require.NoError(t, err)
	oldOut := os.Stdout
	os.Stdout = pw
	t.Cleanup(func() { os.Stdout = oldOut })

	cfg := config.Config{SMTPMock: true}
	h := NewMagicHandlers(cfg, q, mail.New(cfg), nil, nil, service.NewRegistry(q), nil, template.New("x"))
	req := httptest.NewRequest(http.MethodPost, "/magic-login", strings.NewReader(url.Values{"email": {"a@b.no"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.RequestLink(w, req)

	os.Stdout = oldOut
	require.NoError(t, pw.Close())
	out, _ := io.ReadAll(pr)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.NotContains(t, w.Body.String(), "ingen entropi")
	assert.NotContains(t, string(out), "MAIL MOCK")
	var n int
	require.NoError(t, sqldb.QueryRow("SELECT COUNT(*) FROM magic_tokens").Scan(&n))
	assert.Zero(t, n)
}
