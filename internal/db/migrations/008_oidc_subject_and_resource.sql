-- +goose Up

-- K6 (docs/ANALYSE_DELEGERT_BRUKERIDENTITET i drivstoffpriser): sub har til nå
-- vært brukerens e-postadresse. En ressursserver som knytter egne rader til
-- sub mister da koblingen i det øyeblikket noen bytter e-post, og en
-- gjenbrukt adresse arver den forrige eierens historikk. OIDC Core §2 krever
-- at sub er lokalt unik og ALDRI gjenbrukt — e-post er ingen av de to.
--
-- subject_id er derfor en opak, uforanderlig id per bruker. 16 byte fra
-- SQLites egen CSPRNG, hex — ingen betydning, ingen personopplysning, og
-- ikke rowid (som i prinsippet kan gjenbrukes etter en DELETE).
--
-- Kolonnen legges til nullable fordi SQLite ikke godtar et ikke-konstant
-- DEFAULT i ALTER TABLE ADD COLUMN. Backfillen under gir hver eksisterende
-- rad sin egen verdi (randomblob evalueres per rad), og CreateUser fyller
-- den for nye brukere. Koden faller tilbake til e-post hvis den likevel er
-- NULL, så en rad satt inn utenom CreateUser svekker ikke mer enn dagens
-- oppførsel.
ALTER TABLE users ADD COLUMN subject_id TEXT;

UPDATE users SET subject_id = lower(hex(randomblob(16))) WHERE subject_id IS NULL;

CREATE UNIQUE INDEX idx_users_subject_id ON users(subject_id);

-- K5: resource indicator (RFC 8707). Klienten oppgir hvilken ressursserver
-- tokenet skal brukes mot på /authorize, og aud settes til den i stedet for
-- client_id. Uten dette må en ressursserver godta et token med aud=<klienten
-- selv>, altså uten noe bevis på at tokenet var ment for NETTOPP den — og da
-- kan et token utstedt til klienten for tjeneste A spilles av mot tjeneste B.
--
-- Nullable: en klient som ikke ber om en resource får samme oppførsel som i
-- dag (aud = client_id). Verdien bæres fra /authorize til /token gjennom
-- koden, ikke gjennom en klient-oppgitt parameter alene, slik at den ikke kan
-- byttes ut i innløsningssteget.
ALTER TABLE authorization_codes ADD COLUMN resource TEXT;

-- +goose Down
DROP INDEX IF EXISTS idx_users_subject_id;
ALTER TABLE users DROP COLUMN subject_id;
ALTER TABLE authorization_codes DROP COLUMN resource;
