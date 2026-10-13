package db

import (
	"database/sql"
	"embed"
	"fmt"
	"log/slog"
	"sync"

	"github.com/pressly/goose/v3"
	"github.com/zral/kauth-go/internal/db/gen"
	_ "modernc.org/sqlite"
)

//go:embed migrations/*.sql
var migrations embed.FS

var setupGoose sync.Once

func Open(path string) (*sql.DB, *gen.Queries, error) {
	// busy_timeout er ikke valgfritt: SQLite sin default er 0, som betyr at en
	// skriver som møter en låst database gir opp umiddelbart med SQLITE_BUSY.
	// WAL hjelper ikke her — den skiller lesere fra skrivere, mens skriverne
	// fortsatt serialiseres mot én lås. Ved innlogging skjer flere skriv nesten
	// samtidig (refresh-token, to audit-hendelser, last_login), og uten timeout
	// forsvant taperen i stillhet siden audit.Log kun logger feilen sin.
	dsn := fmt.Sprintf(
		"file:%s?_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)",
		path)
	sqldb, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, nil, fmt.Errorf("åpne database: %w", err)
	}
	if err := sqldb.Ping(); err != nil {
		return nil, nil, fmt.Errorf("ping database: %w", err)
	}

	setupGoose.Do(func() {
		goose.SetBaseFS(migrations)
		goose.SetDialect("sqlite3") //nolint:errcheck
		goose.SetLogger(goose.NopLogger())
	})
	if err := goose.Up(sqldb, "migrations"); err != nil {
		return nil, nil, fmt.Errorf("migrasjoner: %w", err)
	}

	logPragmas(sqldb)
	return sqldb, gen.New(sqldb), nil
}

// logPragmas rapporterer de effektive innstillingene ved oppstart. busy_timeout
// er per tilkobling og ikke lagret i databasefilen, så det er ingen måte å
// verifisere den utenfra prosessen — derfor sier vi det selv.
func logPragmas(sqldb *sql.DB) {
	var journal string
	var busy int
	if err := sqldb.QueryRow("PRAGMA journal_mode").Scan(&journal); err != nil {
		return
	}
	if err := sqldb.QueryRow("PRAGMA busy_timeout").Scan(&busy); err != nil {
		return
	}
	slog.Info("database: åpnet", "journal_mode", journal, "busy_timeout_ms", busy)
}

// OpenMemory brukes bare i tester. Én tilkobling: hver tilkobling til :memory:
// får sin egen tomme database, så flere ville mistet skjemaet.
func OpenMemory() (*sql.DB, *gen.Queries, error) {
	sqldb, q, err := Open(":memory:")
	if err != nil {
		return nil, nil, err
	}
	sqldb.SetMaxOpenConns(1)
	return sqldb, q, nil
}
