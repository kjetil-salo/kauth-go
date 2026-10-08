-- +goose Up

-- E-postadresser har til nå blitt lagret og slått opp eksakt slik brukeren
-- skrev dem. SQLite sammenligner TEXT med = byte for byte, så
-- GetActiveUserByEmail('Kari@eksempel.no') traff ikke raden
-- 'kari@eksempel.no'. Resultatet var at innloggingsveien opprettet en NY
-- konto for samme person: nytt subject_id, og dermed ny sub i OIDC-tokenene.
--
-- Det slo inn forskjellig i de to klassene av innloggingsveier:
--
--   * magic link og passord leser adressen brukeren selv taster inn, der
--     mobiltastatur gjerne stor-forbokstaverer første tegn.
--   * Google og Microsoft leverer email-claimen slik identitetsleverandøren
--     normaliserer den, som kan skille seg fra det brukeren tastet forrige
--     gang.
--
-- Admin-veiene lowercaset allerede (internal/admin/users.go,
-- internal/admin/auth.go), så en admin-opprettet konto og en innlogging på
-- samme adresse kunne ende som to rader.
--
-- Konsekvensen er alvorligere enn en dublett: en ressursserver som knytter
-- rader til sub ser to forskjellige personer, og brukeren mister
-- historikken sin ved å taste adressen med annen bokstavstørrelse enn sist.
-- Det er samme klasse feil som 008 rettet for e-post-som-sub.
--
-- Local-part er formelt case-sensitiv i RFC 5321 §2.4, men ingen
-- e-postleverandør i praktisk bruk behandler den slik, og adressen brukes her
-- utelukkende som identitetsnøkkel — ikke til ruting. Derfor normaliseres
-- hele adressen.
UPDATE users
SET email = lower(trim(email))
WHERE email <> lower(trim(email))
  AND lower(trim(email)) NOT IN (
      SELECT lower(trim(email)) FROM users u2 WHERE u2.id <> users.id
  );

-- Indeksen håndhever at normaliseringen holder framover. Den er bevisst
-- plassert ETTER UPDATE-en: finnes det allerede to rader som kun skiller seg
-- i bokstavstørrelse, lar UPDATE-en over dem stå urørt og denne indeksen
-- feiler migrasjonen. Det er med vilje. En slik kollisjon er to kontoer for
-- samme menneske, med hver sin historikk og hvert sitt subject_id, og hvilken
-- som skal overleve er ikke noe en migrasjon kan avgjøre uten å kaste data.
-- Da skal deployen stoppe og kollisjonen ryddes for hånd.
CREATE UNIQUE INDEX idx_users_email_lower ON users(lower(trim(email)));

-- +goose Down
DROP INDEX IF EXISTS idx_users_email_lower;
