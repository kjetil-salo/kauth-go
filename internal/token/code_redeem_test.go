package token_test

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

func seedCode(t *testing.T, sqlDB *sql.DB, user gen.User) token.CodeRedemption {
	t.Helper()
	q := gen.New(sqlDB)
	if _, err := q.CreateUser(context.Background(), gen.CreateUserParams{
		Email: user.Email, Roles: "user", Orgs: "x", CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if err := q.InsertAuthorizationCode(context.Background(), gen.InsertAuthorizationCodeParams{
		Code: token.HashOpaque("kode"), ServiceID: "testsvc", Email: user.Email,
		RedirectUri: "https://testsvc.test/cb", CodeChallenge: "chal", CodeChallengeMethod: "S256",
		CreatedAt: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		ExpiresAt: time.Now().UTC().Add(time.Minute).Format("2006-01-02T15:04:05Z"),
	}); err != nil {
		t.Fatalf("InsertAuthorizationCode: %v", err)
	}
	return token.CodeRedemption{
		CodeHash: token.HashOpaque("kode"), ServiceID: "testsvc",
		RedirectURI: "https://testsvc.test/cb", CodeChallenge: "chal",
	}
}

type failingCodeInsert struct{ token.CodeQuerier }

func (failingCodeInsert) InsertRefreshToken(context.Context, gen.InsertRefreshTokenParams) error {
	return errors.New("simulert innsettingsfeil")
}

func TestRedeemAuthorizationCode_InsertFailureRollsBackConsume(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	p := seedCode(t, sqlDB, testUser())

	txr := token.SQLCodeTxRunner(sqlDB)
	failing := token.NewRefreshServiceWithCodeRunner(gen.New(sqlDB),
		func(ctx context.Context, fn func(token.CodeQuerier) error) error {
			return txr(ctx, func(q token.CodeQuerier) error { return fn(failingCodeInsert{q}) })
		}, audit.NewNoop())
	_, err := failing.RedeemAuthorizationCode(ctx, p, testUser(), testService(), "ip", "ua")
	if err == nil || errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("forventet intern feil, fikk %v", err)
	}

	row, err := gen.New(sqlDB).GetAuthorizationCodeByHash(ctx, p.CodeHash)
	if err != nil {
		t.Fatalf("GetAuthorizationCodeByHash: %v", err)
	}
	if row.Used != 0 || row.FamilyID != nil {
		t.Fatalf("koden skal være urørt etter rollback: used=%d family_id=%v", row.Used, row.FamilyID)
	}
}

func TestRedeemAuthorizationCode_FamilyIDMatchesRefreshRow(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	p := seedCode(t, sqlDB, testUser())

	svc := token.NewRefreshService(sqlDB, audit.NewNoop())
	plain, err := svc.RedeemAuthorizationCode(ctx, p, testUser(), testService(), "ip", "ua")
	if err != nil {
		t.Fatalf("RedeemAuthorizationCode: %v", err)
	}
	code, err := gen.New(sqlDB).GetAuthorizationCodeByHash(ctx, p.CodeHash)
	if err != nil {
		t.Fatalf("GetAuthorizationCodeByHash: %v", err)
	}
	rt := rowByPlain(t, sqlDB, plain)
	if code.Used != 1 || code.FamilyID == nil || *code.FamilyID != rt.FamilyID {
		t.Fatalf("family_id på kode (%v) må være lik refresh-raden (%s), used=%d", code.FamilyID, rt.FamilyID, code.Used)
	}

	// Andre innløsning: ingen rad oppfyller predikatene.
	if _, err := svc.RedeemAuthorizationCode(ctx, p, testUser(), testService(), "ip", "ua"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("forventet sql.ErrNoRows, fikk %v", err)
	}
}

// Hvert predikat i UPDATE-en er en uavhengig siste vakt: en rad som bryter
// akkurat ett av dem skal gi ErrNoRows og la koden stå ubrukt.
func TestConsumeAuthorizationCodeChecked_EachPredicateGuards(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(p *gen.ConsumeAuthorizationCodeCheckedParams)
	}{
		{"redirect_uri", func(p *gen.ConsumeAuthorizationCodeCheckedParams) { p.RedirectUri = "https://evil.test/cb" }},
		{"code_challenge", func(p *gen.ConsumeAuthorizationCodeCheckedParams) { p.CodeChallenge = "annen" }},
		{"service_id", func(p *gen.ConsumeAuthorizationCodeCheckedParams) { p.ServiceID = "annen-tjeneste" }},
		{"expires_at", func(p *gen.ConsumeAuthorizationCodeCheckedParams) {
			p.Now = time.Now().UTC().Add(time.Hour).Format("2006-01-02T15:04:05Z")
		}},
		{"code_hash", func(p *gen.ConsumeAuthorizationCodeCheckedParams) { p.CodeHash = token.HashOpaque("ukjent") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sqlDB := openTxDB(t)
			ctx := context.Background()
			r := seedCode(t, sqlDB, testUser())
			fam := "fam"
			p := gen.ConsumeAuthorizationCodeCheckedParams{
				FamilyID: &fam, CodeHash: r.CodeHash, ServiceID: r.ServiceID, RedirectUri: r.RedirectURI,
				CodeChallenge: r.CodeChallenge, Now: time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			}
			q := gen.New(sqlDB)
			if _, err := q.ConsumeAuthorizationCodeChecked(ctx, p); err != nil {
				t.Fatalf("kontroll: gyldige parametre skal konsumere: %v", err)
			}
			// Tilbakestill raden og prøv med nøyaktig ett brutt predikat.
			if _, err := sqlDB.Exec(`UPDATE authorization_codes SET used = 0, family_id = NULL`); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&p)
			if _, err := q.ConsumeAuthorizationCodeChecked(ctx, p); !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("forventet sql.ErrNoRows, fikk %v", err)
			}
			row, err := q.GetAuthorizationCodeByHash(ctx, r.CodeHash)
			if err != nil {
				t.Fatal(err)
			}
			if row.Used != 0 {
				t.Fatalf("koden skal være ubrukt, used=%d", row.Used)
			}
		})
	}
}
