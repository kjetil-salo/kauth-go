-- name: InsertAuthorizationCode :exec
INSERT INTO authorization_codes (code, service_id, email, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ConsumeAuthorizationCode :one
UPDATE authorization_codes
SET used = 1
WHERE code = ? AND used = 0 AND expires_at > ?
RETURNING *;

-- Codes live 60 seconds, so a single threshold is enough here, unlike
-- magic_tokens' longer grace period for unused tokens. See CHANGELOG for
-- the reasoning from the PR 1 code review.
--
-- NOTE (sqlc 1.31.1 bug, reported upstream): a bare "expires_at" column
-- reference in a single-condition DELETE like this one gets truncated by
-- sqlc's raw-query-text extraction whenever the preceding comment block
-- contains non-ASCII (UTF-8 multi-byte) characters -- looks like a
-- byte-vs-rune offset bug in how sqlc slices the source file to build the
-- embedded query string. Reproduced in isolation. Keeping this comment
-- ASCII-only, and the column qualified as authorization_codes.expires_at,
-- both worked around it; only the qualification is strictly required once
-- the comment is ASCII, but both are kept as belt-and-suspenders. Do not
-- reintroduce accented characters in this comment without re-checking the
-- generated internal/db/gen/authorization_codes.sql.go output.
-- name: DeleteExpiredAuthorizationCodes :exec
DELETE FROM authorization_codes WHERE authorization_codes.expires_at < ?;
