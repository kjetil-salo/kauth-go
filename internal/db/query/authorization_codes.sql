-- name: InsertAuthorizationCode :exec
INSERT INTO authorization_codes (code, service_id, email, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);

-- name: ConsumeAuthorizationCode :one
UPDATE authorization_codes
SET used = 1
WHERE code = ? AND used = 0 AND expires_at > ?
RETURNING *;

-- name: DeleteExpiredAuthorizationCodes :exec
-- Koder lever i 60 sekunder — i motsetning til magic_tokens trengs ingen
-- lengre nåde-periode for ubrukte koder, så én terskel er nok (påpekt i
-- kodegjennomgang: den opprinnelige (used=1 AND expires_at<?) OR expires_at<?
-- var alltid ekvivalent med bare expires_at<? når begge parametre er samme
-- tidspunkt).
DELETE FROM authorization_codes WHERE expires_at < ?;
