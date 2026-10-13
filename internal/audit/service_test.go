package audit

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

// warnCapture teller Warn-poster med meldingen fra drop().
type warnCapture struct {
	mu    sync.Mutex
	total []uint64
}

func (w *warnCapture) Enabled(context.Context, slog.Level) bool { return true }
func (w *warnCapture) WithAttrs([]slog.Attr) slog.Handler       { return w }
func (w *warnCapture) WithGroup(string) slog.Handler            { return w }
func (w *warnCapture) Handle(_ context.Context, r slog.Record) error {
	if r.Level != slog.LevelWarn || r.Message != "audit: hendelse droppet" {
		return nil
	}
	r.Attrs(func(a slog.Attr) bool {
		if a.Key == "dropped_total" {
			w.mu.Lock()
			w.total = append(w.total, a.Value.Uint64())
			w.mu.Unlock()
		}
		return true
	})
	return nil
}

func (w *warnCapture) snapshot() []uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]uint64(nil), w.total...)
}

func captureWarns(t *testing.T) *warnCapture {
	t.Helper()
	prev := slog.Default()
	wc := &warnCapture{}
	slog.SetDefault(slog.New(wc))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return wc
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// blockingService har en skriver som står fast i insert til gate lukkes.
func blockingService(t *testing.T, capacity int, clock func() time.Time) (*Service, chan struct{}, chan struct{}) {
	t.Helper()
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	s := newService(func(ctx context.Context, _ gen.InsertAuditEventParams) error {
		select {
		case started <- struct{}{}:
		default:
		}
		<-gate
		return nil
	}, capacity, clock)
	return s, gate, started
}

func withinMs(t *testing.T, ms int, what string, f func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { f(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Duration(ms) * time.Millisecond):
		t.Fatalf("%s tok over %d ms", what, ms)
	}
}

func TestLog_NeverBlocks_QueueFullDrops(t *testing.T) {
	captureWarns(t)
	s, gate, started := blockingService(t, 2, time.Now)
	defer close(gate)

	s.Log(context.Background(), Event{Type: "a"})
	<-started // skriveren holder nå én hendelse; køen er tom
	withinMs(t, 10, "Log", func() {
		s.Log(context.Background(), Event{Type: "b"})
		s.Log(context.Background(), Event{Type: "c"})
		s.Log(context.Background(), Event{Type: "d"}) // køen full: droppes
	})
	if got := s.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, vil ha 1", got)
	}
}

func TestLog_DropWarnRateLimited(t *testing.T) {
	wc := captureWarns(t)
	clk := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	s, gate, started := blockingService(t, 1, clk.Now)
	defer close(gate)

	s.Log(context.Background(), Event{Type: "a"})
	<-started
	s.Log(context.Background(), Event{Type: "b"}) // fyller køen
	for i := 0; i < 5; i++ {
		s.Log(context.Background(), Event{Type: "x"})
	}
	if got := wc.snapshot(); len(got) != 1 || got[0] != 1 {
		t.Fatalf("Warn innen 10 s = %v, vil ha ett kall med total 1", got)
	}
	clk.Advance(warnInterval)
	s.Log(context.Background(), Event{Type: "x"})
	got := wc.snapshot()
	if len(got) != 2 || got[1] != 6 {
		t.Fatalf("Warn etter 10 s = %v, vil ha ny med kumulativ total 6", got)
	}
}

func TestLog_AfterClose_NoPanicNoBlock(t *testing.T) {
	captureWarns(t)
	s := newService(func(context.Context, gen.InsertAuditEventParams) error { return nil }, 4, time.Now)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	withinMs(t, 10, "Log etter Close", func() {
		s.Log(context.Background(), Event{Type: "late"})
	})
	if got := s.dropped.Load(); got != 1 {
		t.Fatalf("dropped = %d, vil ha 1", got)
	}
}

func openFileDB(t *testing.T) (*gen.Queries, func()) {
	t.Helper()
	sqlDB, q, err := db.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	return q, func() { sqlDB.Close() }
}

func countRows(t *testing.T, q *gen.Queries) int {
	t.Helper()
	rows, err := q.ListAuditEvents(context.Background(), gen.ListAuditEventsParams{Limit: 1000})
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func TestClose_DrainsQueueBeforeReturn(t *testing.T) {
	q, closeDB := openFileDB(t)
	defer closeDB()
	s := NewService(q)
	for i := 0; i < 100; i++ {
		s.Log(context.Background(), Event{Type: "bulk", Success: true})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, q); n != 100 {
		t.Fatalf("rader = %d, vil ha 100", n)
	}
}

func TestClose_TimeoutReturnsError(t *testing.T) {
	s, gate, started := blockingService(t, 4, time.Now)
	defer close(gate)
	s.Log(context.Background(), Event{Type: "a"})
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	var err error
	withinMs(t, 200, "Close", func() { err = s.Close(ctx) })
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, vil ha DeadlineExceeded", err)
	}
}

func TestLogSync_WritesBeforeReturn(t *testing.T) {
	q, closeDB := openFileDB(t)
	defer closeDB()
	s := NewService(q)
	defer s.Close(context.Background())
	if err := s.LogSync(context.Background(), Event{Type: "sync", Success: true}); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, q); n != 1 {
		t.Fatalf("rader rett etter LogSync = %d, vil ha 1", n)
	}
}

func TestLogSync_ReturnsInsertError(t *testing.T) {
	sqlDB, q, err := db.Open(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	s := NewService(q)
	defer s.Close(context.Background())
	sqlDB.Close()
	if err := s.LogSync(context.Background(), Event{Type: "sync"}); err == nil {
		t.Fatal("forventet feil mot lukket DB")
	}
}

func TestNoop_LogSyncAndClose(t *testing.T) {
	s := NewNoop()
	s.Log(context.Background(), Event{Type: "x"})
	if err := s.LogSync(context.Background(), Event{Type: "x"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// recorder samler alle slog-poster (melding og nivå).
type recorder struct {
	mu   sync.Mutex
	msgs []string
	lvls []slog.Level
}

func (r *recorder) Enabled(context.Context, slog.Level) bool { return true }
func (r *recorder) WithAttrs([]slog.Attr) slog.Handler       { return r }
func (r *recorder) WithGroup(string) slog.Handler            { return r }
func (r *recorder) Handle(_ context.Context, rec slog.Record) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, rec.Message)
	r.lvls = append(r.lvls, rec.Level)
	r.mu.Unlock()
	return nil
}

func (r *recorder) count(msg string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, m := range r.msgs {
		if m == msg {
			n++
		}
	}
	return n
}

func captureAll(t *testing.T) *recorder {
	t.Helper()
	prev := slog.Default()
	r := &recorder{}
	slog.SetDefault(slog.New(r))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return r
}

func TestClose_LogsDrainedCountIncludingInFlight(t *testing.T) {
	rec := captureAll(t)
	s, gate, started := blockingService(t, 4, time.Now)
	s.Log(context.Background(), Event{Type: "a"})
	<-started // én i flight
	s.Log(context.Background(), Event{Type: "b"})
	s.Log(context.Background(), Event{Type: "c"})

	closed := make(chan error, 1)
	go func() { closed <- s.Close(context.Background()) }()
	// Close har satt closed-flagget når Log droppes.
	for {
		s.mu.RLock()
		c := s.closed
		s.mu.RUnlock()
		if c {
			break
		}
		runtime.Gosched()
	}
	close(gate)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if rec.count("audit: tømt 3 hendelser") != 1 {
		t.Fatalf("meldinger: %v", rec.msgs)
	}
}

func TestClose_LogsEvenWhenEmpty(t *testing.T) {
	rec := captureAll(t)
	s := newService(func(context.Context, gen.InsertAuditEventParams) error { return nil }, 4, time.Now)
	if err := s.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rec.count("audit: tømt 0 hendelser") != 1 {
		t.Fatalf("meldinger: %v", rec.msgs)
	}
}

func TestClose_TimeoutStopsWriterWithSingleLog(t *testing.T) {
	rec := captureAll(t)
	var inserts atomic.Int32
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	s := newService(func(context.Context, gen.InsertAuditEventParams) error {
		inserts.Add(1)
		select {
		case started <- struct{}{}:
		default:
		}
		<-gate
		return errors.New("db lukket")
	}, 8, time.Now)
	s.Log(context.Background(), Event{Type: "a"})
	<-started
	for i := 0; i < 5; i++ {
		s.Log(context.Background(), Event{Type: "q"})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := s.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if rec.count("audit: Close ga opp før køen var tømt") != 1 {
		t.Fatalf("meldinger: %v", rec.msgs)
	}
	close(gate)
	<-s.done
	if n := inserts.Load(); n != 1 {
		t.Fatalf("inserts = %d, vil ha 1 (resten forkastes)", n)
	}
	if rec.count("audit: feil ved logging") != 1 || rec.count("audit: hendelser forkastet etter Close-timeout") != 1 {
		t.Fatalf("meldinger: %v", rec.msgs)
	}
}

func TestWriter_InsertHasDeadlineUpToFiveSeconds(t *testing.T) {
	type res struct {
		ok  bool
		rem time.Duration
	}
	got := make(chan res, 1)
	s := newService(func(ctx context.Context, _ gen.InsertAuditEventParams) error {
		d, ok := ctx.Deadline()
		got <- res{ok, time.Until(d)}
		return nil
	}, 2, time.Now)
	defer s.Close(context.Background())
	s.Log(context.Background(), Event{Type: "a"})
	r := <-got
	if !r.ok || r.rem > insertTimeout {
		t.Fatalf("deadline ok=%v rem=%v", r.ok, r.rem)
	}
}
