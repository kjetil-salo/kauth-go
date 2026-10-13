-- +goose Up
-- magic_tokens.token og authorization_codes.code inneholder heretter SHA-256-hex
-- av klartekstverdien (som refresh_tokens.token_hash), ikke selve hemmeligheten.
-- Eksisterende rader er klartekst og kan ikke hashes bakover, og begge typene
-- lever i minutter (15 min / 60 s), så de slettes heller enn å bli liggende
-- som ubrukelige rader.
DELETE FROM magic_tokens;
DELETE FROM authorization_codes;

-- purpose binder tokenet til flyten det ble utstedt for, slik at et
-- admin-token aldri kan løses inn som tjenesteinnlogging og omvendt.
ALTER TABLE magic_tokens
    ADD COLUMN purpose TEXT NOT NULL DEFAULT 'service' CHECK (purpose IN ('service','admin'));

-- family_id settes ved innløsning, slik at gjenbruk av en kode kan revokere
-- refresh-familien den ga opphav til.
ALTER TABLE authorization_codes ADD COLUMN family_id TEXT;

-- +goose Down
-- Hashede rader kan ikke brukes av eldre kode, så tabellene tømmes.
DELETE FROM magic_tokens;
DELETE FROM authorization_codes;
ALTER TABLE magic_tokens DROP COLUMN purpose;
ALTER TABLE authorization_codes DROP COLUMN family_id;
