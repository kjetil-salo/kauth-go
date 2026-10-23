-- +goose Up

-- Et access-token utstedt gjennom refresh_token-grant har til nå mistet både
-- aud og scope: authorizationCodeGrant kaller IssueAccessForAudience() med
-- verdiene fra autorisasjonskoden, mens RefreshToken() kaller IssueAccess(),
-- som ikke setter noen av dem. Koden er for lengst konsumert på det
-- tidspunktet, så det fantes ingenting å gjenskape dem fra.
--
-- Virkningen er at en delegert fullmakt bare lever til første fornyelse.
-- Drivstoffprisene krever aud=ressursindikatoren og scope=priser:skriv på
-- delegerte skriv; Veivakt fullførte code-runden 20. oktober 2026, og alle
-- innsendinger etter at det første access-tokenet utløp (15 minutter) ble
-- avvist på «mangler aud». Fra klientens side er dette usynlig: token-byttet
-- svarer 200, og tokenet er gyldig — det har bare mistet fullmakten sin.
--
-- Begge kolonnene er nullable, og en rad uten resource gir uendret oppførsel
-- (IssueAccess, ingen aud) — slik at kauths egen bespoke-flyt, som aldri
-- setter aud, ikke påvirkes. Verdiene følger token-familien gjennom
-- rotasjonen, så et barn arver fullmakten til forelderen sin og ikke mer.
ALTER TABLE refresh_tokens ADD COLUMN resource TEXT;
ALTER TABLE refresh_tokens ADD COLUMN scope TEXT;

-- +goose Down
ALTER TABLE refresh_tokens DROP COLUMN resource;
ALTER TABLE refresh_tokens DROP COLUMN scope;
