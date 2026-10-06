-- name: GetUserByEmail :one
SELECT * FROM users WHERE email = ? LIMIT 1;

-- name: GetActiveUserByEmail :one
SELECT * FROM users WHERE email = ? AND deactivated_at IS NULL LIMIT 1;

-- name: CreateUser :one
-- subject_id genereres i SQL, ikke i Go: det holder sub-genereringen paa ett
-- sted for alle fire innloggingsveiene (magic link, Google, Microsoft,
-- admin-opprettelse), og en femte vei kan ikke glemme den. Antall
-- plassholdere er uendret, saa CreateUserParams er urort.
--
-- NB: ASCII-only med vilje. sqlc 1.31.1 slicer den raa SQL-teksten paa
-- byte-offset og kutter spoerringen naar en kommentar rett foran den
-- inneholder flerbyte-tegn -- samme bug som er dokumentert i
-- authorization_codes.sql.
INSERT INTO users (email, password_hash, name, roles, orgs, created_at, subject_id)
VALUES (?, ?, ?, ?, ?, ?, lower(hex(randomblob(16))))
RETURNING *;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login = ? WHERE email = ?;

-- name: UpdateUser :exec
UPDATE users SET name = ?, roles = ?, orgs = ? WHERE id = ?;

-- name: DeactivateUser :exec
UPDATE users SET deactivated_at = ? WHERE id = ?;

-- name: ListUsers :many
SELECT * FROM users ORDER BY email LIMIT ? OFFSET ?;

-- name: ListUsersByOrg :many
SELECT * FROM users WHERE orgs LIKE ? ORDER BY email LIMIT ? OFFSET ?;

-- name: CountUsers :one
SELECT COUNT(*) FROM users;
