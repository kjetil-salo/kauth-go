-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(trim(email)) = lower(trim(sqlc.arg(email))) LIMIT 1;

-- name: GetActiveUserByEmail :one
SELECT * FROM users WHERE lower(trim(email)) = lower(trim(sqlc.arg(email))) AND deactivated_at IS NULL LIMIT 1;

-- name: CreateUser :one
INSERT INTO users (email, password_hash, name, roles, orgs, created_at)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login = ? WHERE email = ?;

-- name: UpdateUser :exec
UPDATE users SET name = ?, roles = ?, orgs = ? WHERE id = ?;

-- name: DeactivateUser :one
UPDATE users SET deactivated_at = ? WHERE id = ? RETURNING email;

-- name: ListUsers :many
SELECT * FROM users ORDER BY email LIMIT ? OFFSET ?;

-- name: ListUsersByOrg :many
SELECT * FROM users WHERE orgs LIKE ? ORDER BY email LIMIT ? OFFSET ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;
