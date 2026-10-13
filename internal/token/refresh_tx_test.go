package token_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
	"github.com/zral/kauth-go/internal/token"
)

// openTxDB åpner en fil-DB (ikke :memory:) slik at parallelle tilkoblinger
// faktisk konkurrerer om skrivelåsen, som i produksjon.
func openTxDB(t *testing.T) *sql.DB {
	t.Helper()
	sqlDB, q, err := db.Open(filepath.Join(t.TempDir(), "tx.db"))
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	seedService(t, q)
	return sqlDB
}

func seedService(t *testing.T, q *gen.Queries) {
	t.Helper()
	err := q.CreateService(context.Background(), gen.CreateServiceParams{
		ID: "testsvc", DisplayName: "testsvc", Domain: "testsvc.test",
		CallbackUrl: "https://testsvc.test/cb",
		Theme:       "light", AccentColor: "#000", EmailFromName: "t",
		AutoRegister: 1, AuthMagicLink: 1,
		JwtCookieName: "kauth_token", AccessTokenTtl: "PT15M",
		Active: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("CreateService: %v", err)
	}
}

type failingInsert struct{ token.RefreshQuerier }

func (failingInsert) InsertRefreshToken(context.Context, gen.InsertRefreshTokenParams) error {
	return errors.New("simulert innsettingsfeil")
}

func rowByPlain(t *testing.T, sqlDB *sql.DB, plain string) gen.RefreshToken {
	t.Helper()
	// hashToken er privat; slå opp via nyeste rad når bare én er aktuell er skjørt,
	// så vi bruker samme sha256 som tjenesten.
	row, err := gen.New(sqlDB).GetRefreshTokenByHash(context.Background(), token.HashForTest(plain))
	if err != nil {
		t.Fatalf("GetRefreshTokenByHash: %v", err)
	}
	return row
}

func TestRotate_InsertFailureRollsBackConsume(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	real := token.NewRefreshService(sqlDB, audit.NewNoop())
	plain, err := real.Issue(ctx, testUser(), testService(), "ip", "ua")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	txr := token.SQLTxRunner(sqlDB)
	failing := token.NewRefreshServiceWithRunner(gen.New(sqlDB),
		func(ctx context.Context, fn func(token.RefreshQuerier) error) error {
			return txr(ctx, func(q token.RefreshQuerier) error { return fn(failingInsert{q}) })
		}, audit.NewNoop())
	if _, err := failing.Rotate(ctx, plain, "ip", "ua"); err == nil {
		t.Fatal("forventet feil når innsetting feiler")
	}
	if got := rowByPlain(t, sqlDB, plain); got.Used != 0 || got.Revoked != 0 {
		t.Fatalf("forelder skulle være ubrukt etter rollback: used=%d revoked=%d", got.Used, got.Revoked)
	}
	res, err := real.Rotate(ctx, plain, "ip", "ua")
	if err != nil {
		t.Fatalf("ny Rotate etter rollback: %v", err)
	}
	if res.NewToken == "" {
		t.Fatal("forventet nytt barn")
	}
}

func TestRotate_ReuseRevokesChildOfConcurrentRotation(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	svc := token.NewRefreshService(sqlDB, audit.NewNoop())
	a, _ := svc.Issue(ctx, testUser(), testService(), "ip", "ua")
	res, err := svc.Rotate(ctx, a, "ip", "ua")
	if err != nil {
		t.Fatalf("Rotate(A): %v", err)
	}
	if _, err := svc.Rotate(ctx, a, "ip", "ua"); !errors.Is(err, token.ErrTokenReuse) {
		t.Fatalf("forventet ErrTokenReuse, fikk %v", err)
	}
	if got := rowByPlain(t, sqlDB, res.NewToken); got.Revoked != 1 {
		t.Fatal("barnet B skulle vært revokert")
	}
	if got := rowByPlain(t, sqlDB, a); got.Revoked != 1 {
		t.Fatal("A skulle vært revokert")
	}
	if _, err := svc.Rotate(ctx, res.NewToken, "ip", "ua"); err == nil {
		t.Fatal("Rotate(B) skulle feile")
	}
}

func TestRotate_ParallelPresentation_AtMostOneWins(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	svc := token.NewRefreshService(sqlDB, audit.NewNoop())
	plain, _ := svc.Issue(ctx, testUser(), testService(), "ip", "ua")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	oks := make([]bool, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, errs[i] = svc.Rotate(ctx, plain, "ip", "ua")
			oks[i] = errs[i] == nil
		}(i)
	}
	close(start)
	wg.Wait()

	wins, reuse := 0, 0
	for i := range errs {
		switch {
		case oks[i]:
			wins++
		case errors.Is(errs[i], token.ErrTokenReuse):
			reuse++
		default:
			t.Errorf("uventet feil (SQLITE_BUSY?): %v", errs[i])
		}
	}
	if wins != 1 {
		t.Fatalf("nøyaktig én skal lykkes, fikk %d", wins)
	}
	if reuse > 0 {
		var live int
		if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM refresh_tokens WHERE revoked = 0`).Scan(&live); err != nil {
			t.Fatal(err)
		}
		if live != 0 {
			t.Fatalf("reuse oppdaget, men %d rader i familien er ikke revokert", live)
		}
	}
}

func TestSQLTxRunner_PanicRollsBack(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	svc := token.NewRefreshService(sqlDB, audit.NewNoop())
	plain, _ := svc.Issue(ctx, testUser(), testService(), "ip", "ua")

	func() {
		defer func() {
			if recover() == nil {
				t.Error("panikken skulle propagere")
			}
		}()
		_ = token.SQLTxRunner(sqlDB)(ctx, func(q token.RefreshQuerier) error {
			if _, err := q.ConsumeRefreshToken(ctx, gen.ConsumeRefreshTokenParams{
				TokenHash: token.HashForTest(plain), ExpiresAt: "2000-01-01T00:00:00Z",
			}); err != nil {
				t.Errorf("consume: %v", err)
			}
			panic("boom")
		})
	}()
	if got := rowByPlain(t, sqlDB, plain); got.Used != 0 {
		t.Fatal("konsumet skulle vært rullet tilbake ved panikk")
	}
	// Skrivelåsen må være frigitt.
	if _, err := svc.Rotate(ctx, plain, "ip", "ua"); err != nil {
		t.Fatalf("Rotate etter panikk: %v", err)
	}
}

// Med én tilkobling gir et kall mot s.db inne i transaksjonen vranglås; testen
// feiler da på timeout i stedet for å henge.
func TestRotate_NoDeadlockWithSingleConn(t *testing.T) {
	sqlDB, q, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	sqlDB.SetMaxOpenConns(1)
	seedService(t, q)
	ctx := context.Background()
	svc := token.NewRefreshService(sqlDB, audit.NewNoop())
	plain, _ := svc.Issue(ctx, testUser(), testService(), "ip", "ua")

	done := make(chan error, 1)
	go func() { _, err := svc.Rotate(ctx, plain, "ip", "ua"); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Rotate: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("vranglås: Rotate brukte tilkobling utenfor transaksjonen")
	}
}

type lookupFails struct{ token.RefreshQuerier }

func (lookupFails) GetRefreshTokenByHash(context.Context, string) (gen.RefreshToken, error) {
	return gen.RefreshToken{}, errors.New("simulert DB-feil")
}

func TestRotate_LookupDBError_NotMaskedAsRevoked(t *testing.T) {
	sqlDB := openTxDB(t)
	ctx := context.Background()
	real := token.NewRefreshService(sqlDB, audit.NewNoop())
	plain, _ := real.Issue(ctx, testUser(), testService(), "ip", "ua")
	if _, err := real.Rotate(ctx, plain, "ip", "ua"); err != nil {
		t.Fatal(err)
	}
	svc := token.NewRefreshServiceWithRunner(lookupFails{gen.New(sqlDB)}, token.SQLTxRunner(sqlDB), audit.NewNoop())
	_, err := svc.Rotate(ctx, plain, "ip", "ua")
	if err == nil || errors.Is(err, token.ErrTokenRevoked) || errors.Is(err, token.ErrTokenReuse) {
		t.Fatalf("forventet intern feil, fikk %v", err)
	}
}

func TestRotate_CancelledCtxOnReuse_StillRevokesAndAudits(t *testing.T) {
	sqlDB, q, err := db.OpenMemory()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sqlDB.Close() })
	sqlDB.SetMaxOpenConns(1)
	seedService(t, q)
	ctx := context.Background()
	svc := token.NewRefreshService(sqlDB, audit.NewService(q))
	a, _ := svc.Issue(ctx, testUser(), testService(), "ip", "ua")
	res, err := svc.Rotate(ctx, a, "ip", "ua")
	if err != nil {
		t.Fatal(err)
	}
	// Konsum feiler med ErrNoRows også på kansellert ctx? Driveren avviser ctx
	// tidlig, så vi kaller reuse-stien via en ctx som kanselleres først etter konsum.
	cctx, cancel := context.WithCancel(ctx)
	runner := token.SQLTxRunner(sqlDB)
	svc2 := token.NewRefreshServiceWithRunner(q, func(c context.Context, fn func(token.RefreshQuerier) error) error {
		err := runner(c, fn)
		cancel()
		return err
	}, audit.NewService(q))
	if _, err := svc2.Rotate(cctx, a, "ip", "ua"); !errors.Is(err, token.ErrTokenReuse) {
		t.Fatalf("forventet ErrTokenReuse, fikk %v", err)
	}
	if got := rowByPlain(t, sqlDB, res.NewToken); got.Revoked != 1 {
		t.Fatal("familien skulle vært revokert til tross for kansellert ctx")
	}
	time.Sleep(200 * time.Millisecond) // audit er asynkron
	var n int
	if err := sqlDB.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE event_type='refresh_token_reuse'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("forventet 1 reuse-audit, fikk %d (err %v)", n, err)
	}
}

func TestRotate_UnknownToken_IsErrTokenRevoked(t *testing.T) {
	svc := token.NewRefreshService(openTxDB(t), audit.NewNoop())
	if _, err := svc.Rotate(context.Background(), "aldri-utstedt", "ip", "ua"); !errors.Is(err, token.ErrTokenRevoked) {
		t.Fatalf("forventet ErrTokenRevoked, fikk %v", err)
	}
}
