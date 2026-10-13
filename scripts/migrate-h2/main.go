// migrate-h2 migrates a H2 SQL dump (from Java kauth) to a fresh SQLite file
// for kauth-go. Run with: CGO_ENABLED=0 go run ./scripts/migrate-h2/
package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/zral/kauth-go/internal/db"
	"github.com/zral/kauth-go/internal/db/gen"
)

const (
	dumpPath   = "/tmp/kauth-migrate/dump.sql"
	targetPath = "/tmp/kauth-migrate/kauth.db"
)

// ---- value parsing helpers ----

// decodeH2String decodes an H2 string value token into a Go string.
// Handles three forms:
//   - NULL              → returns ("", true [null])
//   - 'plain string'   → unescapes ” → '
//   - U&'unicode str'  → additionally decodes \NNNN hex escapes
func decodeH2String(tok string) (val string, isNull bool) {
	tok = strings.TrimSpace(tok)
	if strings.EqualFold(tok, "NULL") {
		return "", true
	}

	isUnicode := false
	if strings.HasPrefix(tok, "U&'") {
		isUnicode = true
		tok = tok[2:] // strip U& prefix, leaving 'string'
	}

	if len(tok) >= 2 && tok[0] == '\'' && tok[len(tok)-1] == '\'' {
		tok = tok[1 : len(tok)-1]
	}

	// unescape '' → '
	tok = strings.ReplaceAll(tok, "''", "'")

	if isUnicode {
		tok = decodeUnicodeEscapes(tok)
	}
	return tok, false
}

var unicodeEscapeRe = regexp.MustCompile(`\\([0-9a-fA-F]{4})`)

func decodeUnicodeEscapes(s string) string {
	return unicodeEscapeRe.ReplaceAllStringFunc(s, func(m string) string {
		hex := m[1:]
		cp, err := strconv.ParseInt(hex, 16, 32)
		if err != nil {
			return m
		}
		var buf [utf8.UTFMax]byte
		n := utf8.EncodeRune(buf[:], rune(cp))
		return string(buf[:n])
	})
}

// parseH2Bool parses TRUE/FALSE tokens → int64 (1/0).
func parseH2Bool(tok string) int64 {
	tok = strings.TrimSpace(tok)
	if strings.EqualFold(tok, "TRUE") {
		return 1
	}
	return 0
}

// parseH2Int parses an integer token.
func parseH2Int(tok string) int64 {
	tok = strings.TrimSpace(tok)
	v, err := strconv.ParseInt(tok, 10, 64)
	if err != nil {
		log.Fatalf("parseH2Int: %q → %v", tok, err)
	}
	return v
}

// parseH2IntNullable returns nil if tok == "NULL", else *int64.
func parseH2IntNullable(tok string) *int64 {
	tok = strings.TrimSpace(tok)
	if strings.EqualFold(tok, "NULL") {
		return nil
	}
	v := parseH2Int(tok)
	return &v
}

// parseH2Timestamp parses "TIMESTAMP WITH TIME ZONE 'YYYY-MM-DD HH:MM:SS.ffffff+HH'"
// or "TIMESTAMP WITH TIME ZONE 'YYYY-MM-DD HH:MM:SS.ffffff+HH:MM'" and returns
// a UTC timestamp formatted as "2006-01-02T15:04:05Z".
func parseH2Timestamp(tok string) string {
	tok = strings.TrimSpace(tok)
	// Extract the quoted part
	start := strings.Index(tok, "'")
	end := strings.LastIndex(tok, "'")
	if start == -1 || end == start {
		log.Fatalf("parseH2Timestamp: no quotes in %q", tok)
	}
	ts := tok[start+1 : end]

	// Try multiple formats
	formats := []string{
		"2006-01-02 15:04:05.999999999-07:00",
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05-07:00",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05.999999999+00",
		"2006-01-02 15:04:05+00",
	}

	// Normalise offset: "+00" → "+00:00" and similar
	ts = normaliseOffset(ts)

	var t time.Time
	var err error
	for _, f := range formats {
		t, err = time.Parse(f, ts)
		if err == nil {
			break
		}
	}
	if err != nil {
		log.Fatalf("parseH2Timestamp: cannot parse %q: %v", ts, err)
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

func normaliseOffset(ts string) string {
	// Already has colon in offset? leave it.
	// Offsets look like +00, +02, -05, +00:00, +02:00
	// Find last + or -
	for i := len(ts) - 1; i >= 0; i-- {
		if ts[i] == '+' || ts[i] == '-' {
			offset := ts[i+1:]
			if !strings.Contains(offset, ":") {
				// Add :00
				ts = ts[:i+1] + offset + ":00"
			}
			break
		}
	}
	return ts
}

// parseNullableTimestamp returns nil for NULL, else *string pointer to UTC ISO timestamp.
func parseNullableTimestamp(tok string) *string {
	tok = strings.TrimSpace(tok)
	if strings.EqualFold(tok, "NULL") {
		return nil
	}
	s := parseH2Timestamp(tok)
	return &s
}

// nowUTC returns current UTC time formatted as kauth-go's timestamp format.
func nowUTC() string {
	return time.Now().UTC().Format("2006-01-02T15:04:05Z")
}

// ---- tuple parser ----

// splitTuple splits a "(v1, v2, ...)" string into individual value tokens,
// respecting quoted strings (single-quoted, with ” escapes) and nested parens
// (for TIMESTAMP WITH TIME ZONE '...').
func splitTuple(line string) []string {
	line = strings.TrimSpace(line)
	// Strip trailing semicolons and commas first, then closing paren
	line = strings.TrimRight(line, ";")
	line = strings.TrimRight(line, ",")
	line = strings.TrimRight(line, " \t")
	// Strip surrounding parens
	if len(line) > 0 && line[0] == '(' {
		line = line[1:]
	}
	if len(line) > 0 && line[len(line)-1] == ')' {
		line = line[:len(line)-1]
	}

	var tokens []string
	var cur strings.Builder
	inQuote := false
	i := 0
	for i < len(line) {
		ch := line[i]
		if inQuote {
			if ch == '\'' {
				// Peek next: '' is escaped apostrophe
				if i+1 < len(line) && line[i+1] == '\'' {
					cur.WriteByte('\'')
					cur.WriteByte('\'')
					i += 2
					continue
				}
				// End of quoted string
				cur.WriteByte(ch)
				inQuote = false
				i++
				continue
			}
			cur.WriteByte(ch)
			i++
			continue
		}
		// Not in quote
		if ch == '\'' {
			inQuote = true
			cur.WriteByte(ch)
			i++
			continue
		}
		if ch == ',' {
			tokens = append(tokens, strings.TrimSpace(cur.String()))
			cur.Reset()
			i++
			continue
		}
		cur.WriteByte(ch)
		i++
	}
	if cur.Len() > 0 {
		tokens = append(tokens, strings.TrimSpace(cur.String()))
	}
	return tokens
}

// ---- dump reader ----

// tableBlock holds the raw tuple lines for a parsed table.
type tableBlock struct {
	name   string
	tuples []string
}

// parseDump reads the dump file and extracts INSERT rows per table.
func parseDump(path string) map[string][]string {
	data, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("read dump: %v", err)
	}
	content := string(data)
	lines := strings.Split(content, "\n")

	result := make(map[string][]string)

	var currentTable string
	var inInsert bool

	for _, rawLine := range lines {
		line := strings.TrimRight(rawLine, " \t\r")

		// Detect INSERT INTO "PUBLIC"."TABLE_NAME" VALUES
		if strings.HasPrefix(line, `INSERT INTO "PUBLIC"."`) {
			// Extract table name from: INSERT INTO "PUBLIC"."TABLE_NAME" VALUES
			inner := line[len(`INSERT INTO "PUBLIC"."`):] // starts at table name (after opening quote)
			endQ := strings.Index(inner, `"`)
			if endQ >= 0 {
				currentTable = inner[:endQ]
			}
			inInsert = true
			continue
		}

		if !inInsert {
			continue
		}

		trimmed := strings.TrimSpace(line)

		// End of insert block (semicolon-terminated line or empty or CREATE)
		if strings.HasPrefix(trimmed, "CREATE") ||
			strings.HasPrefix(trimmed, "ALTER") ||
			strings.HasPrefix(trimmed, "--") {
			inInsert = false
			currentTable = ""
			continue
		}

		if trimmed == "" {
			continue
		}

		// Lines starting with ( are tuple data
		if strings.HasPrefix(trimmed, "(") {
			// Strip trailing comma+semicolon
			clean := strings.TrimRight(trimmed, ";")
			result[currentTable] = append(result[currentTable], clean)
		}
	}

	return result
}

// ---- nullable string helper ----

func strPtr(s string, null bool) *string {
	if null {
		return nil
	}
	return &s
}

// ---- migration functions ----

func migrateServices(ctx context.Context, q *gen.Queries, rows []string) int {
	for _, row := range rows {
		// H2 SERVICE_CONFIG column order (from CREATE TABLE):
		// ID, ACCENT_COLOR, ACTIVE, AUTH_GOOGLE, AUTH_MAGIC_LINK, AUTH_MICROSOFT,
		// AUTO_REGISTER, BG_CSS, BG_IMAGE, CALLBACK_URL, DEFAULT_ORG, DEFAULT_ROLE,
		// DISPLAY_NAME, DOMAIN, EMAIL_FROM_NAME, JWT_COOKIE_NAME, LOGO_HTML,
		// REQUIRE_ROLE, TAGLINE, THEME, ENFORCE_ORG, ACCESS_TOKEN_TTL,
		// REFRESH_TOKEN_MAX_AGE, GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET,
		// MICROSOFT_CLIENT_ID, MICROSOFT_CLIENT_SECRET, AUTH_HOST
		toks := splitTuple(row)
		if len(toks) < 28 {
			log.Printf("services: short row (%d cols), skipping: %s", len(toks), row[:min(80, len(row))])
			continue
		}

		id, _ := decodeH2String(toks[0])
		accentColor, accentNull := decodeH2String(toks[1])
		active := parseH2Bool(toks[2])
		authGoogle := parseH2Bool(toks[3])
		authMagicLink := parseH2Bool(toks[4])
		authMicrosoft := parseH2Bool(toks[5])
		autoRegister := parseH2Bool(toks[6])
		bgCSS, bgCSSNull := decodeH2String(toks[7])
		bgImage, bgImageNull := decodeH2String(toks[8])
		callbackURL, _ := decodeH2String(toks[9])
		defaultOrg, defaultOrgNull := decodeH2String(toks[10])
		defaultRole, defaultRoleNull := decodeH2String(toks[11])
		displayName, _ := decodeH2String(toks[12])
		domain, _ := decodeH2String(toks[13])
		emailFromName, _ := decodeH2String(toks[14])
		jwtCookieName, jwtNull := decodeH2String(toks[15])
		logoHTML, logoNull := decodeH2String(toks[16])
		requireRole, requireNull := decodeH2String(toks[17])
		tagline, taglineNull := decodeH2String(toks[18])
		theme, themeNull := decodeH2String(toks[19])
		enforceOrg := parseH2Bool(toks[20])
		accessTokenTTL, attlNull := decodeH2String(toks[21])
		refreshTokenMaxAge, rtmaNull := decodeH2String(toks[22])
		googleClientID, gcidNull := decodeH2String(toks[23])
		googleClientSecret, gcsNull := decodeH2String(toks[24])
		msClientID, msidNull := decodeH2String(toks[25])
		msClientSecret, mssNull := decodeH2String(toks[26])
		authHost, ahNull := decodeH2String(toks[27])

		// Apply defaults for missing optional fields
		if accentNull {
			accentColor = "#2563EB"
		}
		if jwtNull {
			jwtCookieName = "auth_token"
		}
		if themeNull {
			theme = "light"
		}
		if attlNull {
			accessTokenTTL = "PT15M"
		}

		// The only service that should be default is "klarsyn" (first/only prod service)
		// Actually we migrate all services — set is_default=1 only for "klarsyn"
		isDefault := int64(0)
		if id == "klarsyn" {
			isDefault = 1
		}

		p := gen.CreateServiceParams{
			ID:                    id,
			DisplayName:           displayName,
			Tagline:               strPtr(tagline, taglineNull),
			Domain:                domain,
			AuthHost:              strPtr(authHost, ahNull),
			CallbackUrl:           callbackURL,
			LogoHtml:              strPtr(logoHTML, logoNull),
			BgImage:               strPtr(bgImage, bgImageNull),
			BgCss:                 strPtr(bgCSS, bgCSSNull),
			Theme:                 theme,
			AccentColor:           accentColor,
			EmailFromName:         emailFromName,
			AutoRegister:          autoRegister,
			DefaultRole:           strPtr(defaultRole, defaultRoleNull),
			DefaultOrg:            strPtr(defaultOrg, defaultOrgNull),
			RequireRole:           strPtr(requireRole, requireNull),
			EnforceOrg:            enforceOrg,
			IsDefault:             isDefault,
			AuthGoogle:            authGoogle,
			AuthMicrosoft:         authMicrosoft,
			AuthMagicLink:         authMagicLink,
			AuthPassword:          0,
			GoogleClientID:        strPtr(googleClientID, gcidNull),
			GoogleClientSecret:    strPtr(googleClientSecret, gcsNull),
			MicrosoftClientID:     strPtr(msClientID, msidNull),
			MicrosoftClientSecret: strPtr(msClientSecret, mssNull),
			JwtCookieName:         jwtCookieName,
			AccessTokenTtl:        accessTokenTTL,
			RefreshTokenMaxAge:    strPtr(refreshTokenMaxAge, rtmaNull),
			Active:                active,
			UpdatedAt:             nowUTC(),
		}

		if err := q.CreateService(ctx, p); err != nil {
			log.Fatalf("insert service %q: %v", id, err)
		}
	}
	return len(rows)
}

func migrateUsers(ctx context.Context, sqlDB *sql.DB, rows []string) int {
	// H2 APP_USER column order:
	// ID, EMAIL, NAME, ORG, PASSWORD, ROLE, USERNAME
	now := nowUTC()

	for _, row := range rows {
		toks := splitTuple(row)
		if len(toks) < 7 {
			log.Printf("users: short row (%d cols), skipping", len(toks))
			continue
		}

		id := parseH2Int(toks[0])
		email, _ := decodeH2String(toks[1])
		name, nameNull := decodeH2String(toks[2])
		orgs, _ := decodeH2String(toks[3])
		password, pwNull := decodeH2String(toks[4])
		roles, _ := decodeH2String(toks[5])
		// toks[6] is USERNAME — dropped

		var pwHash *string
		if !pwNull && password != "" {
			pwHash = &password
		}

		var namePtr *string
		if !nameNull {
			namePtr = &name
		}

		_, err := sqlDB.ExecContext(ctx,
			`INSERT INTO users (id, email, password_hash, name, roles, orgs, created_at) VALUES (?,?,?,?,?,?,?)`,
			id, email, pwHash, namePtr, roles, orgs, now,
		)
		if err != nil {
			log.Fatalf("insert user id=%d email=%s: %v", id, email, err)
		}
	}
	return len(rows)
}

func migrateAuditEvents(ctx context.Context, sqlDB *sql.DB, rows []string) int {
	// H2 AUDIT_EVENTS column order:
	// ID, AUTHMETHOD, DETAILS, EMAIL, EVENTTYPE, IPADDRESS, SUCCESS, TENANT, TIMESTAMP
	for _, row := range rows {
		toks := splitTuple(row)
		if len(toks) < 9 {
			log.Printf("audit_events: short row (%d cols), skipping", len(toks))
			continue
		}

		id := parseH2Int(toks[0])
		authMethod, amNull := decodeH2String(toks[1])
		details, detNull := decodeH2String(toks[2])
		email, emailNull := decodeH2String(toks[3])
		eventType, _ := decodeH2String(toks[4])
		ipAddress, ipNull := decodeH2String(toks[5])
		success := parseH2Bool(toks[6])
		serviceID, sidNull := decodeH2String(toks[7])
		createdAt := parseH2Timestamp(toks[8])

		_, err := sqlDB.ExecContext(ctx,
			`INSERT INTO audit_events (id, event_type, auth_method, email, service_id, ip_address, user_agent, success, details, created_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			id,
			eventType,
			strPtr(authMethod, amNull),
			strPtr(email, emailNull),
			strPtr(serviceID, sidNull),
			strPtr(ipAddress, ipNull),
			nil, // user_agent not in H2
			success,
			strPtr(details, detNull),
			createdAt,
		)
		if err != nil {
			log.Fatalf("insert audit_event id=%d: %v", id, err)
		}
	}
	return len(rows)
}

func migrateRefreshTokens(ctx context.Context, sqlDB *sql.DB, rows []string) int {
	// H2 REFRESH_TOKENS column order (from CREATE TABLE):
	// ID, CREATEDAT, EMAIL, EXPIRESAT, FAMILYEXPIRESAT, FAMILYID, IPADDRESS,
	// PARENTID, REVOKED, REVOKEDREASON, TOKENHASH, USED, USERAGENT
	const serviceID = "klarsyn"

	for _, row := range rows {
		toks := splitTuple(row)
		if len(toks) < 13 {
			log.Printf("refresh_tokens: short row (%d cols), skipping", len(toks))
			continue
		}

		id := parseH2Int(toks[0])
		createdAt := parseH2Timestamp(toks[1])
		email, _ := decodeH2String(toks[2])
		expiresAt := parseH2Timestamp(toks[3])
		familyExpiresAt := parseH2Timestamp(toks[4])
		familyID, _ := decodeH2String(toks[5])
		ipAddress, ipNull := decodeH2String(toks[6])
		parentID := parseH2IntNullable(toks[7])
		revoked := parseH2Bool(toks[8])
		revokedReason, rrNull := decodeH2String(toks[9])
		tokenHash, _ := decodeH2String(toks[10])
		used := parseH2Bool(toks[11])
		userAgent, uaNull := decodeH2String(toks[12])

		_, err := sqlDB.ExecContext(ctx,
			`INSERT INTO refresh_tokens (id, token_hash, email, service_id, family_id, parent_id, created_at, expires_at, family_expires_at, used, revoked, revoked_reason, ip_address, user_agent) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			id,
			tokenHash,
			email,
			serviceID,
			familyID,
			parentID,
			createdAt,
			expiresAt,
			&familyExpiresAt, // always non-null in H2 (TIMESTAMP NOT NULL)
			used,
			revoked,
			strPtr(revokedReason, rrNull),
			strPtr(ipAddress, ipNull),
			strPtr(userAgent, uaNull),
		)
		if err != nil {
			log.Fatalf("insert refresh_token id=%d: %v", id, err)
		}
	}
	return len(rows)
}

// ---- sample row printers ----

func printSampleService(ctx context.Context, q *gen.Queries) {
	svcs, err := q.ListAllServices(ctx)
	if err != nil || len(svcs) == 0 {
		return
	}
	s := svcs[0]
	fmt.Printf("  sample service: id=%s domain=%s active=%d is_default=%d updated_at=%s\n",
		s.ID, s.Domain, s.Active, s.IsDefault, s.UpdatedAt)
}

func printSampleUser(ctx context.Context, sqlDB *sql.DB) {
	row := sqlDB.QueryRowContext(ctx, `SELECT id, email, name, roles, orgs, created_at FROM users LIMIT 1`)
	var id int64
	var email, roles, orgs, createdAt string
	var name sql.NullString
	if err := row.Scan(&id, &email, &name, &roles, &orgs, &createdAt); err != nil {
		return
	}
	fmt.Printf("  sample user: id=%d email=%s name=%v roles=%s\n", id, email, name.String, roles)
}

func printSampleAudit(ctx context.Context, sqlDB *sql.DB) {
	row := sqlDB.QueryRowContext(ctx, `SELECT id, event_type, email, created_at FROM audit_events LIMIT 1`)
	var id int64
	var eventType, createdAt string
	var email sql.NullString
	if err := row.Scan(&id, &eventType, &email, &createdAt); err != nil {
		return
	}
	fmt.Printf("  sample audit_event: id=%d event_type=%s email=%v created_at=%s\n",
		id, eventType, email.String, createdAt)
}

func printSampleRefreshToken(ctx context.Context, sqlDB *sql.DB) {
	row := sqlDB.QueryRowContext(ctx, `SELECT id, email, family_id, created_at, used, revoked FROM refresh_tokens LIMIT 1`)
	var id int64
	var email, familyID, createdAt string
	var used, revoked int64
	if err := row.Scan(&id, &email, &familyID, &createdAt, &used, &revoked); err != nil {
		return
	}
	fmt.Printf("  sample refresh_token: id=%d email=%s family_id=%s used=%d revoked=%d created_at=%s\n",
		id, email, familyID, used, revoked, createdAt)
}

// ---- row count verifier ----

func countTable(ctx context.Context, sqlDB *sql.DB, table string) int64 {
	var n int64
	_ = sqlDB.QueryRowContext(ctx, fmt.Sprintf("SELECT COUNT(*) FROM %s", table)).Scan(&n)
	return n
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ---- main ----

func main() {
	ctx := context.Background()

	// Remove existing target so we start fresh
	if err := os.Remove(targetPath); err != nil && !os.IsNotExist(err) {
		log.Fatalf("remove old db: %v", err)
	}

	// Open SQLite with migrations applied
	sqlDB, q, err := db.Open(targetPath)
	if err != nil {
		log.Fatalf("db.Open: %v", err)
	}
	defer sqlDB.Close()

	// Parse H2 dump
	fmt.Printf("parsing %s ...\n", dumpPath)
	tableRows := parseDump(dumpPath)
	for tbl, rows := range tableRows {
		fmt.Printf("  found %s: %d rows\n", tbl, len(rows))
	}

	// Migration: services first (FK references)
	nServices := migrateServices(ctx, q, tableRows["SERVICE_CONFIG"])
	fmt.Printf("inserted services: %d\n", nServices)

	// Users
	nUsers := migrateUsers(ctx, sqlDB, tableRows["APP_USER"])
	fmt.Printf("inserted users: %d\n", nUsers)

	// Audit events
	nAudit := migrateAuditEvents(ctx, sqlDB, tableRows["AUDIT_EVENTS"])
	fmt.Printf("inserted audit_events: %d\n", nAudit)

	// Disable FK enforcement for refresh_tokens — some parent_id references tokens
	// that were already cleaned up (not in the 90-day dump window).
	if _, err := sqlDB.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		log.Fatalf("PRAGMA foreign_keys OFF: %v", err)
	}
	// Refresh tokens (must be after services due to FK service_id)
	nRefresh := migrateRefreshTokens(ctx, sqlDB, tableRows["REFRESH_TOKENS"])
	if _, err := sqlDB.ExecContext(ctx, "PRAGMA foreign_keys = ON"); err != nil {
		log.Fatalf("PRAGMA foreign_keys ON: %v", err)
	}
	fmt.Printf("inserted refresh_tokens: %d\n", nRefresh)

	nMagic := 0 // MAGIC_LINK_TOKENS is empty in the dump

	// Verify row counts
	dbServices := countTable(ctx, sqlDB, "services")
	dbUsers := countTable(ctx, sqlDB, "users")
	dbAudit := countTable(ctx, sqlDB, "audit_events")
	dbRefresh := countTable(ctx, sqlDB, "refresh_tokens")
	dbMagic := countTable(ctx, sqlDB, "magic_tokens")

	fmt.Printf("\nmigrated: services=%d, users=%d, audit_events=%d, refresh_tokens=%d, magic_tokens=%d\n",
		dbServices, dbUsers, dbAudit, dbRefresh, dbMagic)

	// Sanity checks
	if dbServices != int64(nServices) || dbUsers != int64(nUsers) ||
		dbAudit != int64(nAudit) || dbRefresh != int64(nRefresh) || dbMagic != int64(nMagic) {
		log.Printf("WARNING: inserted vs DB count mismatch!")
	}

	// Print sample rows
	fmt.Println("\nsample rows:")
	printSampleService(ctx, q)
	printSampleUser(ctx, sqlDB)
	printSampleAudit(ctx, sqlDB)
	printSampleRefreshToken(ctx, sqlDB)

	fmt.Printf("\nSQLite database written to: %s\n", targetPath)
}
