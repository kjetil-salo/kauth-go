package audit

import (
	"context"
	"log"
	"net"
	"strings"
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

type Service struct {
	queries *gen.Queries
}

func NewService(queries *gen.Queries) *Service {
	return &Service{queries: queries}
}

// NewNoop returnerer en audit.Service som ikke gjør noe — kun for tester.
func NewNoop() *Service { return &Service{queries: nil} }

// Log skriver hendelse asynkront — blokkerer aldri auth-flyten.
func (s *Service) Log(ctx context.Context, e Event) {
	if s.queries == nil {
		return
	} // no-op i tester
	go func() {
		success := int64(0)
		if e.Success {
			success = 1
		}
		now := time.Now().UTC().Format("2006-01-02T15:04:05Z")
		err := s.queries.InsertAuditEvent(context.Background(), gen.InsertAuditEventParams{
			EventType:  e.Type,
			AuthMethod: nullStr(e.AuthMethod),
			Email:      nullStr(e.Email),
			ServiceID:  nullStr(e.ServiceID),
			IpAddress:  nullStr(e.IP),
			UserAgent:  nullStr(e.UA),
			Success:    success,
			Details:    nullStr(e.Details),
			CreatedAt:  now,
		})
		if err != nil {
			log.Printf("audit: feil ved logging av %s: %v", e.Type, err)
		}
	}()
}

func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// ExtractIP henter klient-IP fra Cloudflare → X-Forwarded-For → RemoteAddr.
// Kalles fra middleware og legges i context.
func ExtractIP(cfIP, xff, remote string) string {
	if cfIP != "" {
		return cfIP
	}
	if xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return remote
	}
	return host
}
