-- +goose Up

-- Kortlevde, engangsbrukte autorisasjonskoder for standard OIDC
-- authorization_code-flyt (RFC 6749 §4.1 + PKCE, RFC 7636). Samme mønster
-- som magic_tokens: opprettes ved vellykket innlogging via /login (når
-- forespørselen inneholder response_type=code), løses inn på /token.
--
-- PKCE er obligatorisk for enhver response_type=code-forespørsel, uansett
-- tjeneste — ingen per-tjeneste unntak. En kode uten PKCE kan løses inn av
-- hvem som helst som fanger den opp, siden client_id er offentlig
-- informasjon og ingen client secret finnes for en offentlig OIDC-klient
-- (OAuth 2.1 / BCP §2.1.1 krever nettopp dette).
CREATE TABLE authorization_codes (
    id                    INTEGER PRIMARY KEY,
    code                  TEXT NOT NULL UNIQUE,
    service_id            TEXT NOT NULL REFERENCES services(id) ON DELETE CASCADE,
    email                 TEXT NOT NULL,
    redirect_uri          TEXT NOT NULL,
    scope                 TEXT,
    nonce                 TEXT,
    code_challenge        TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    created_at            TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ','now')),
    expires_at            TEXT NOT NULL,
    used                  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX idx_authorization_codes_expires ON authorization_codes(expires_at);

-- +goose Down
DROP TABLE IF EXISTS authorization_codes;
