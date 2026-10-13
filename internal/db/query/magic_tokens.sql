-- name: InsertMagicTokenLimited :execrows
INSERT INTO magic_tokens (token, email, service_id, redirect_uri, purpose, created_at, expires_at)
SELECT CAST(sqlc.arg(token_hash) AS TEXT), CAST(sqlc.arg(email) AS TEXT), sqlc.narg(service_id), sqlc.narg(redirect_uri), CAST(sqlc.arg(purpose) AS TEXT), CAST(sqlc.arg(created_at) AS TEXT), CAST(sqlc.arg(expires_at) AS TEXT)
WHERE (
    SELECT COUNT(*) FROM magic_tokens
    WHERE magic_tokens.email = sqlc.arg(email) AND magic_tokens.purpose = sqlc.arg(purpose) AND magic_tokens.created_at > sqlc.arg(window_start)
) < 3;

-- name: GetValidMagicTokenByHash :one
SELECT * FROM magic_tokens
WHERE token = sqlc.arg(token_hash) AND purpose = sqlc.arg(purpose) AND used = 0 AND expires_at > sqlc.arg(now);

-- name: ConsumeMagicToken :one
UPDATE magic_tokens
SET used = 1
WHERE token = sqlc.arg(token_hash) AND purpose = sqlc.arg(purpose) AND used = 0 AND expires_at > sqlc.arg(now)
RETURNING *;

-- name: DeleteExpiredMagicTokens :exec
DELETE FROM magic_tokens
WHERE (used = 1 AND expires_at < ?)
   OR expires_at < ?;
