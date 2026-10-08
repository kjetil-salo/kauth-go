-- Oppslag paa e-post normaliserer BEGGE sider: parameteren fordi den kommer
-- raa fra et skjemafelt eller en email-claim, og kolonnen fordi rader lagret
-- foer migrasjon 009 kan ha stor forbokstav. Uten dette opprettet
-- innloggingsveiene en ny konto -- nytt subject_id, dermed ny sub -- for en
-- bruker som tastet adressen sin med annen bokstavstoerrelse enn sist.
--
-- Normaliseringen ligger i SQL og ikke i Go av samme grunn som subject_id i
-- CreateUser under: da kan ingen innloggingsvei (magic link, Google,
-- Microsoft, passord, admin) glemme den, og en sjette vei arver den gratis.
--
-- sqlc.arg(email) er noedvendig for at parameteren fortsatt heter Email i Go;
-- uten den navngir sqlc den etter den ytterste SQL-funksjonen ("TRIM").

-- name: GetUserByEmail :one
SELECT * FROM users WHERE lower(trim(email)) = lower(trim(sqlc.arg(email))) LIMIT 1;

-- name: GetActiveUserByEmail :one
SELECT * FROM users WHERE lower(trim(email)) = lower(trim(sqlc.arg(email))) AND deactivated_at IS NULL LIMIT 1;

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
VALUES (lower(trim(sqlc.arg(email))), sqlc.arg(password_hash), sqlc.arg(name), sqlc.arg(roles), sqlc.arg(orgs), sqlc.arg(created_at), lower(hex(randomblob(16))))
RETURNING *;

-- name: UpdateUserLastLogin :exec
UPDATE users SET last_login = sqlc.arg(last_login) WHERE lower(trim(email)) = lower(trim(sqlc.arg(email)));

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
