-- +goose Up

-- Public OIDC-klienter (f.eks. en ekstern partner-app uten server-side
-- hemmelighet) må bruke PKCE i stedet for et client secret. Flagget styrer
-- om /login (som authorization_endpoint) krever code_challenge før det
-- slipper brukeren videre inn i innloggingsflyten.
ALTER TABLE services ADD COLUMN requires_pkce INTEGER NOT NULL DEFAULT 0;

-- Kortlevde, engangsbrukte autorisasjonskoder for standard OIDC
-- authorization_code-flyt (RFC 6749 §4.1 + PKCE, RFC 7636). Samme mønster
-- som magic_tokens: opprettes ved vellykket innlogging via /login (når
-- forespørselen inneholder response_type=code), løses inn på /token.
CREATE TABLE authorization_codes (
    id                    INTEGER PRIMARY KEY,
    code                  TEXT NOT NULL UNIQUE,
    service_id            TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    email                 TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT,
    nonce                 TEXT,
    code_challenge        TEXT,
    code_challenge_method TEXT,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at            TEXT NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);

-- +goose Down
DROP TABLE IF EXISTS authorization_codes;
ALTER TABLE services DROP COLUMN requires_pkce;
