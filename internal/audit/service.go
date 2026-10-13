package audit

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zral/kauth-go/internal/db/gen"
)

type Event struct {
	Type       string
	AuthMethod string
	Email      string
	ServiceID  string
	IP         string
	UA         string
	Success    bool
	Details    string
}

const (
	queueCapacity = 1024
	insertTimeout = 5 * time.Second
	warnInterval  = 10 * time.Second
)

type insertFunc func(ctx context.Context, p gen.InsertAuditEventParams) error

// Service tar imot hendelser i en begrenset kø som én goroutine skriver til
// databasen. Køen gir bakgrunnsskriving uten én goroutine per hendelse, og
// Close kan tømme den før databasen lukkes ved shutdown.
type Service struct {
	insert insertFunc // nil = no-op (NewNoop)
	now    func() time.Time

	mu     sync.RWMutex // Log holder RLock under send, Close tar Lock før close(ch)
	closed bool
	ch     chan Event
	done   chan struct{}

	dropped  atomic.Uint64
	written  atomic.Uint64 // skrevne hendelser; Close rapporterer differansen fra lukkestart
	base     uint64        // written ved første Close
	stop     chan struct{} // lukkes når Close gir opp, så skriveren slutter å skrive mot DB
	stopOnce sync.Once
	warnMu   sync.Mutex
	lastWarn time.Time
}

func NewService(queries *gen.Queries) *Service {
	return newService(func(ctx context.Context, p gen.InsertAuditEventParams) error {
		return queries.InsertAuditEvent(ctx, p)
	}, queueCapacity, time.Now)
}

func newService(insert insertFunc, capacity int, now func() time.Time) *Service {
	s := &Service{
		insert: insert,
		now:    now,
		ch:     make(chan Event, capacity),
		done:   make(chan struct{}),
		stop:   make(chan struct{}),
	}
	go s.run()
	return s
}

// NewNoop returnerer en audit.Service som ikke gjør noe — kun for tester.
func NewNoop() *Service { return &Service{} }

func (s *Service) run() {
	defer close(s.done)
	discarded := 0
	for e := range s.ch {
		select {
		case <-s.stop:
			// Close ga opp (DB kan snart lukkes): forkast resten uten én feillogg per hendelse.
			discarded++
			continue
		default:
		}
		// Egen kontekst: forespørselen er ofte ferdig når skriveren når hendelsen.
		ctx, cancel := context.WithTimeout(context.Background(), insertTimeout)
		if err := s.write(ctx, e); err != nil {
			slog.Error("audit: feil ved logging", "type", e.Type, "error", err)
		}
		s.written.Add(1)
		cancel()
	}
	if discarded > 0 {
		slog.Error("audit: hendelser forkastet etter Close-timeout", "discarded", discarded)
	}
}

func (s *Service) write(ctx context.Context, e Event) error {
	success := int64(0)
	if e.Success {
		success = 1
	}
	return s.insert(ctx, gen.InsertAuditEventParams{
		EventType:  e.Type,
		AuthMethod: nullStr(e.AuthMethod),
		Email:      nullStr(e.Email),
		ServiceID:  nullStr(e.ServiceID),
		IpAddress:  nullStr(e.IP),
		UserAgent:  nullStr(e.UA),
		Success:    success,
		Details:    nullStr(e.Details),
		CreatedAt:  s.now().UTC().Format("2006-01-02T15:04:05Z"),
	})
}

// Log legger hendelsen i køen og blokkerer aldri auth-flyten. Full kø eller
// lukket tjeneste gir en droppet hendelse (telt og logget), ikke ventetid.
// ctx brukes ikke: skriveren har sin egen kontekst.
func (s *Service) Log(_ context.Context, e Event) {
	if s.insert == nil {
		return
	}
	s.mu.RLock()
	if !s.closed {
		select {
		case s.ch <- e:
			s.mu.RUnlock()
			return
		default:
		}
	}
	s.mu.RUnlock()
	s.drop(e.Type)
}

func (s *Service) drop(typ string) {
	n := s.dropped.Add(1)
	s.warnMu.Lock()
	now := s.now()
	warn := s.lastWarn.IsZero() || now.Sub(s.lastWarn) >= warnInterval
	if warn {
		s.lastWarn = now
	}
	s.warnMu.Unlock()
	if warn {
		slog.Warn("audit: hendelse droppet", "type", typ, "dropped_total", n)
	}
}

// LogSync skriver direkte (uten kø) og returnerer feilen, for hendelser som
// kallestedet må vite er lagret.
func (s *Service) LogSync(ctx context.Context, e Event) error {
	if s.insert == nil {
		return nil
	}
	return s.write(ctx, e)
}

// Close slutter å ta imot, tømmer køen og venter på skriveren eller ctx.
// Kanalen lukkes under skrivelås, så ingen Log kan sende på en lukket kanal.
func (s *Service) Close(ctx context.Context) error {
	if s.insert == nil {
		return nil
	}
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		s.base = s.written.Load()
		close(s.ch)
	}
	s.mu.Unlock()

	select {
	case <-s.done:
		slog.Info(fmt.Sprintf("audit: tømt %d hendelser", s.written.Load()-s.base))
		return nil
	case <-ctx.Done():
		s.stopOnce.Do(func() { close(s.stop) })
		slog.Warn("audit: Close ga opp før køen var tømt", "remaining", len(s.ch), "dropped_total", s.dropped.Load())
		return ctx.Err()
	}
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ClientIP er den eneste funksjonen som avgjør klient-IP. cloudflared kobler til
// fra loopback, så CF-Connecting-IP stoles på bare da; fra andre kilder kan
// headeren forfalskes av klienten. X-Forwarded-For, X-Real-IP og
// True-Client-IP leses aldri, siden de er trivielle å spoofe.
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	if rip := net.ParseIP(host); rip != nil && rip.IsLoopback() {
		if cf := r.Header.Get("CF-Connecting-IP"); cf != "" {
			if ip := net.ParseIP(cf); ip != nil {
				return ip.String()
			}
		}
	}
	return host
}
