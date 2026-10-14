package admin

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zral/kauth-go/internal/audit"
)

const auditWriteTimeout = 5 * time.Second

// auditLogger lar admin-handlerne bruke synkron audit (LogSync) og lar tester
// simulere audit-feil.
type auditLogger interface {
	Log(ctx context.Context, e audit.Event)
	LogSync(ctx context.Context, e audit.Event) error
}

// logAdminWrite skriver admin-audit synkront etter at endringen er lagret, med
// aktøren i Details. Returnerer false når audit feilet; endringen står da, og
// kalleren varsler admin med warn=audit.
func logAdminWrite(ctx context.Context, a auditLogger, e audit.Event) bool {
	// WithoutCancel: auditraden skal skrives selv om admin kobler fra etter lagring.
	// Fristen hindrer at en hengende SQLite-skriving holder requesten til WriteTimeout.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditWriteTimeout)
	defer cancel()
	if actor := ActorFromContext(ctx); actor != "" {
		e.Details = strings.TrimSpace(e.Details + " actor=" + actor)
	}
	if err := a.LogSync(ctx, e); err != nil {
		slog.Error("admin: audit-skriving feilet etter lagring", "type", e.Type, "error", err)
		return false
	}
	return true
}

// redirectWithWarns bygger listeadressen med faste advarselskoder (PD10).
func redirectWithWarns(base string, warns ...string) string {
	if len(warns) == 0 {
		return base
	}
	q := url.Values{"warn": warns}
	return base + "?" + q.Encode()
}

// warnFlags filtrerer warn fra query mot kjente koder; verdier fra URL-en når aldri malen.
func warnFlags(r *http.Request, known ...string) map[string]bool {
	out := map[string]bool{}
	for _, v := range r.URL.Query()["warn"] {
		for _, k := range known {
			if v == k {
				out[k] = true
			}
		}
	}
	return out
}

// savedRedirect samler advarsler etter lagring: cache først, deretter audit (PD10).
func savedRedirect(cacheOK, auditOK bool) string {
	var warns []string
	if !cacheOK {
		warns = append(warns, "cache")
	}
	if !auditOK {
		warns = append(warns, "audit")
	}
	return redirectWithWarns("/admin/services", warns...)
}
