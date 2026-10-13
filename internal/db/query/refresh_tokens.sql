-- name: InsertRefreshToken :exec
INSERT INTO refresh_tokens
    (token_hash, email, service_id, family_id, parent_id,
     created_at, expires_at, family_expires_at, ip_address, user_agent)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ConsumeRefreshToken :one
UPDATE refresh_tokens
SET used = 1
WHERE token_hash = ? AND used = 0 AND revoked = 0 AND expires_at > ?
RETURNING *;

-- name: RevokeFamilyTokens :exec
UPDATE refresh_tokens
SET revoked = 1, revoked_reason = ?
WHERE family_id = ? AND revoked = 0;

-- name: RevokeUserRefreshTokens :execrows
UPDATE refresh_tokens
SET revoked = 1, revoked_reason = ?
WHERE email = ? AND revoked = 0;

-- name: GetRefreshChild :one
SELECT created_at FROM refresh_tokens
WHERE family_id = ? AND parent_id = ?
LIMIT 1;

-- name: DeleteExpiredRefreshTokens :exec
DELETE FROM refresh_tokens
WHERE expires_at < ?
  AND (family_expires_at IS NULL OR family_expires_at < ?);

-- name: CountRefreshTokens :one
SELECT COUNT(*) FROM refresh_tokens;

-- name: GetRefreshTokenByHash :one
SELECT * FROM refresh_tokens WHERE token_hash = ? LIMIT 1;
