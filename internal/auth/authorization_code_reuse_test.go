package auth_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/auth"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/service"
	"github.com/zral/kauth-go/internal/token"
)

const reuseRedirect = "https://veivakt.app/auth/callback"

// setupReuseTest bruker fil-DB (ikke :memory:) slik at parallelle forespørsler
// faktisk konkurrerer om skrivelåsen, og ekte audit slik at hendelsene kan leses.
func setupReuseTest(t *testing.T, withAudit bool) (*auth.PasswordHandlers, *sql.DB, *gen.Queries, gen.User, *token.RefreshService) {
	t.Helper()
	ctx := context.Background()
	sqldb, q, err := db.Open(filepath.Join(t.TempDir(), "reuse.db"))
	require.NoError(t, err)
	t.Cleanup(func() { sqldb.Close() })

	now := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.CreateService(ctx, gen.CreateServiceParams{
		ID: "veivakt", DisplayName: "Veivakt", Domain: "veivakt.app",
		CallbackUrl: reuseRedirect,
		Theme:       "light", AccentColor: "#000", EmailFromName: "Veivakt",
		AutoRegister: 1, AuthGoogle: 1, AuthMagicLink: 1,
		JwtCookieName: "auth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: now,
	}))
	user, err := q.CreateUser(ctx, gen.CreateUserParams{
		Email: "sjafor@example.com", Roles: "user", Orgs: "drivstoffprisene", CreatedAt: now,
	})
	require.NoError(t, err)

	aud := audit.NewNoop()
	if withAudit {
		aud = audit.NewService(q)
	}
	refSvc := token.NewRefreshService(sqldb, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(ctx))
	h := auth.NewPasswordHandlers(q, token.NewIssuerForTest(), refSvc, reg, aud, true)
	return h, sqldb, q, user, refSvc
}

func redeem(h *auth.PasswordHandlers, code, redirectURI, clientID, verifier string) *httptest.ResponseRecorder {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {redirectURI}, "client_id": {clientID},
		"code_verifier": {verifier},
	}
	req := httptest.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, req)
	return w
}

func codeRow(t *testing.T, q *gen.Queries, code string) gen.AuthorizationCode {
	t.Helper()
	row, err := q.GetAuthorizationCodeByHash(context.Background(), token.HashOpaque(code))
	require.NoError(t, err)
	return row
}

// auditDetails venter på at den asynkrone audit-skrivingen lander, og gir
// details for første hendelse av typen.
func auditDetails(t *testing.T, q *gen.Queries, eventType string) string {
	t.Helper()
	var found *gen.AuditEvent
	require.Eventually(t, func() bool {
		evs, err := q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
		require.NoError(t, err)
		for i := range evs {
			if evs[i].EventType == eventType {
				found = &evs[i]
				return true
			}
		}
		return false
	}, 3*time.Second, 20*time.Millisecond, "audit-hendelse %s", eventType)
	if found.Details == nil {
		return ""
	}
	return *found.Details
}

func auditCount(t *testing.T, q *gen.Queries, eventType string) int {
	t.Helper()
	evs, err := q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 100})
	require.NoError(t, err)
	n := 0
	for _, e := range evs {
		if e.EventType == eventType {
			n++
		}
	}
	return n
}

func familyRows(t *testing.T, sqldb *sql.DB, familyID string) (revoked, live int, reasons []string) {
	t.Helper()
	rows, err := sqldb.Query(`SELECT revoked, COALESCE(revoked_reason,'') FROM refresh_tokens WHERE family_id = ?`, familyID)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var rv int
		var reason string
		require.NoError(t, rows.Scan(&rv, &reason))
		if rv == 1 {
			revoked++
			reasons = append(reasons, reason)
		} else {
			live++
		}
	}
	require.NoError(t, rows.Err())
	return
}

// K21: en feil klient, redirect_uri eller verifier skal ikke brenne koden.
func TestAuthorizationCodeGrant_MismatchDoesNotBurnCode(t *testing.T) {
	verifier, challenge := pkcePair()
	otherVerifier := "en-helt-annen-code-verifier-som-ogsa-er-lang-nok-til-a-vaere-gyldig"
	cases := []struct {
		name, redirect, client, verifier, reason string
	}{
		{"client", reuseRedirect, "annen-klient", verifier, "client"},
		{"redirect_uri", "https://evil.example.com/cb", "veivakt", verifier, "redirect_uri"},
		{"pkce", reuseRedirect, "veivakt", otherVerifier, "pkce"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _, q, user, _ := setupReuseTest(t, true)
			insertAuthCode(t, q, "kode-mm", user.Email, reuseRedirect, challenge, "S256", "openid", "")

			w := redeem(h, "kode-mm", tc.redirect, tc.client, tc.verifier)
			require.Equal(t, http.StatusBadRequest, w.Code)
			require.Contains(t, w.Body.String(), "invalid_grant")

			require.Equal(t, "reason="+tc.reason, auditDetails(t, q, "authorization_code_mismatch"))
			row := codeRow(t, q, "kode-mm")
			require.EqualValues(t, 0, row.Used, "avvist forsøk skal ikke brenne koden")
			require.Nil(t, row.FamilyID)

			w = redeem(h, "kode-mm", reuseRedirect, "veivakt", verifier)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		})
	}
}

// K22: gjenbruk av en konsumert kode revokerer familien som den ga.
func TestAuthorizationCodeGrant_ReuseRevokesFamily(t *testing.T) {
	h, sqldb, q, user, refSvc := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-reuse", user.Email, reuseRedirect, challenge, "S256", "openid", "")

	w := redeem(h, "kode-reuse", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	rt := jsonField(t, w.Body.Bytes(), "refresh_token")
	require.NotEmpty(t, rt)

	row := codeRow(t, q, "kode-reuse")
	require.NotNil(t, row.FamilyID)
	_, live, _ := familyRows(t, sqldb, *row.FamilyID)
	require.Equal(t, 1, live)

	w = redeem(h, "kode-reuse", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Contains(t, w.Body.String(), "invalid_grant")

	revoked, live, reasons := familyRows(t, sqldb, *row.FamilyID)
	require.Equal(t, 0, live)
	require.Equal(t, 1, revoked)
	require.Equal(t, []string{"authorization_code_reuse"}, reasons)
	auditDetails(t, q, "authorization_code_reuse")

	_, err := refSvc.Rotate(context.Background(), rt, "ip", "ua")
	require.Error(t, err, "refresh-tokenet fra første innløsning skal være revokert")
}

// Utløpt kode er ikke gjenbruk: ingen revokering.
func TestAuthorizationCodeGrant_ExpiredIsInvalidNotReuse(t *testing.T) {
	h, sqldb, q, user, _ := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	require.NoError(t, q.InsertAuthorizationCode(context.Background(), gen.InsertAuthorizationCodeParams{
		Code: token.HashOpaque("kode-old"), ServiceID: "veivakt", Email: user.Email, RedirectUri: reuseRedirect,
		CodeChallenge: challenge, CodeChallengeMethod: "S256",
		CreatedAt: time.Now().UTC().Add(-2 * time.Minute).Format("2006-01-02T15:04:05Z"),
		ExpiresAt: time.Now().UTC().Add(-time.Minute).Format("2006-01-02T15:04:05Z"),
	}))

	w := redeem(h, "kode-old", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusBadRequest, w.Code)

	auditDetails(t, q, "authorization_code_invalid")
	require.Equal(t, 0, auditCount(t, q, "authorization_code_reuse"))
	var n int
	require.NoError(t, sqldb.QueryRow(`SELECT COUNT(*) FROM refresh_tokens`).Scan(&n))
	require.Equal(t, 0, n)
}

// K23: åtte samtidige innløsninger av samme kode gir høyst én 200, og taperne
// som ble klassifisert som gjenbruk etterlater ingen levende rad i familien.
func TestAuthorizationCodeGrant_ParallelRedeem_AtMostOneWins(t *testing.T) {
	h, sqldb, q, user, _ := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-par", user.Email, reuseRedirect, challenge, "S256", "openid", "")

	const n = 8
	codes := make([]int, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			codes[i] = redeem(h, "kode-par", reuseRedirect, "veivakt", verifier).Code
		}(i)
	}
	close(start)
	wg.Wait()

	ok := 0
	for _, c := range codes {
		require.Contains(t, []int{http.StatusOK, http.StatusBadRequest}, c, "ingen 500 under kappløp")
		if c == http.StatusOK {
			ok++
		}
	}
	require.Equal(t, 1, ok, "nøyaktig én vinner")

	row := codeRow(t, q, "kode-par")
	require.NotNil(t, row.FamilyID)
	_, live, _ := familyRows(t, sqldb, *row.FamilyID)
	require.Equal(t, 0, live, "taperne er gjenbruk og skal ha revokert vinnerens familie")
	require.Eventually(t, func() bool { return auditCount(t, q, "authorization_code_reuse") == n-1 },
		3*time.Second, 20*time.Millisecond, "alle taperne skal klassifiseres som gjenbruk")
}

// Gjenbruk uten bevis (feil verifier) skal ikke revokere: en lekket kode alene
// skal ikke kunne logge ut brukeren.
func TestAuthorizationCodeGrant_ReuseWithoutProofDoesNotRevoke(t *testing.T) {
	h, sqldb, q, user, _ := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-unv", user.Email, reuseRedirect, challenge, "S256", "openid", "")
	require.Equal(t, http.StatusOK, redeem(h, "kode-unv", reuseRedirect, "veivakt", verifier).Code)
	row := codeRow(t, q, "kode-unv")

	wrong := "en-helt-annen-code-verifier-som-ogsa-er-lang-nok-til-a-vaere-gyldig"
	w := redeem(h, "kode-unv", reuseRedirect, "veivakt", wrong)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "reason=unverified", auditDetails(t, q, "authorization_code_reuse"))
	_, live, _ := familyRows(t, sqldb, *row.FamilyID)
	require.Equal(t, 1, live, "familien skal ikke revokeres uten bevis")
}

type failingRevoke struct{ token.RefreshQuerier }

func (failingRevoke) RevokeFamilyTokens(context.Context, gen.RevokeFamilyTokensParams) error {
	return errors.New("simulert revokeringsfeil")
}

func TestAuthorizationCodeGrant_ReuseRevokeFailureIsAudited(t *testing.T) {
	h0, sqldb, q, user, _ := setupReuseTest(t, true)
	_ = h0
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-rf", user.Email, reuseRedirect, challenge, "S256", "openid", "")
	_, err := sqldb.Exec(`UPDATE authorization_codes SET used = 1, family_id = 'fam-x' WHERE code = ?`, token.HashOpaque("kode-rf"))
	require.NoError(t, err)

	aud := audit.NewService(q)
	ref := token.NewRefreshServiceWithRunner(failingRevoke{q}, nil, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(context.Background()))
	h := auth.NewPasswordHandlers(q, token.NewIssuerForTest(), ref, reg, aud, true)

	w := redeem(h, "kode-rf", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusBadRequest, w.Code)
	require.Equal(t, "revoke_failed", auditDetails(t, q, "authorization_code_reuse"))
}

// Deterministisk tapt kappløp: konsumet gir ErrNoRows fordi en vinner nettopp
// committet; omlesingen ser used=1 og må revokere vinnerens familie.
func TestAuthorizationCodeGrant_LostRaceIsClassifiedAsReuse(t *testing.T) {
	_, sqldb, q, user, _ := setupReuseTest(t, true)
	verifier, challenge := pkcePair()
	insertAuthCode(t, q, "kode-lr", user.Email, reuseRedirect, challenge, "S256", "openid", "")

	winner := func(ctx context.Context, fn func(token.CodeQuerier) error) error {
		_, err := sqldb.ExecContext(ctx, `UPDATE authorization_codes SET used = 1, family_id = 'fam-win' WHERE code = ?`, token.HashOpaque("kode-lr"))
		require.NoError(t, err)
		_, err = sqldb.ExecContext(ctx, `INSERT INTO refresh_tokens (token_hash, email, service_id, family_id, created_at, expires_at) VALUES ('' || printf('%064d', 7) || '', ?, 'veivakt', 'fam-win', '2026-01-01T00:00:00Z', '2099-01-01T00:00:00Z')`, user.Email)
		require.NoError(t, err)
		return sql.ErrNoRows
	}
	aud := audit.NewService(q)
	ref := token.NewRefreshServiceWithCodeRunner(q, winner, aud)
	reg := service.NewRegistry(q)
	require.NoError(t, reg.Warmup(context.Background()))
	h := auth.NewPasswordHandlers(q, token.NewIssuerForTest(), ref, reg, aud, true)

	w := redeem(h, "kode-lr", reuseRedirect, "veivakt", verifier)
	require.Equal(t, http.StatusBadRequest, w.Code)
	_, live, reasons := familyRows(t, sqldb, "fam-win")
	require.Equal(t, 0, live)
	require.Empty(t, reasons[1:])
	require.Equal(t, "authorization_code_reuse", reasons[0])
	auditDetails(t, q, "authorization_code_reuse")
}

func jsonField(t *testing.T, body []byte, key string) string {
	t.Helper()
	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m))
	s, _ := m[key].(string)
	return s
}
