-- +goose Up
-- Unik på normalisert e-post, slik at "A@x.no" og "a@x.no " ikke kan bli to
-- brukere. Feiler bevisst hvis det allerede finnes slike duplikater: de må
-- løses manuelt, ikke slås sammen stille.
CREATE UNIQUE INDEX idx_users_email_norm ON users(lower(trim(email)));

-- +goose Down
DROP INDEX IF EXISTS idx_users_email_norm;
