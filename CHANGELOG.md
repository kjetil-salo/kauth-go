# Changelog

Alle merkbare endringer i prosjektet dokumenteres her. Format inspirert av [Keep a Changelog](https://keepachangelog.com/), kategorier: Added, Changed, Fixed, Security, Deprecated, Removed.

## [Unreleased]

### Added

- Spec-komplett OIDC `authorization_code`-flyt med obligatorisk PKCE (RFC 6749 §4.1 + RFC 7636 — ingen konfidensiell klient-type, `client_id` er offentlig informasjon og en kode uten PKCE kan løses inn av hvem som fanger den opp), i tillegg til den eksisterende bespoke login/dispatch-flyten. `/login` fungerer nå også som `authorization_endpoint` for standard OIDC-klienter: en forespørsel med `response_type=code&client_id=...` valideres (kjent client_id, registrert redirect_uri, code_challenge+S256 påkrevd — feil etter at redirect_uri er bekreftet rapporteres som `?error=invalid_request&state=` på redirect_uri, ikke en 400 fra kauth selv) og bæres videre gjennom innloggingsreisen i en ny, usignert `oidc_authz`-cookie. `/dispatch` utsteder deretter en kortlevd, engangsbrukt autorisasjonskode (ny `authorization_codes`-tabell, 60s levetid, `code_challenge`/`code_challenge_method` er `NOT NULL`) i stedet for et token i URL-en, og redirecter med `?code=&state=` (bygget med `url.Parse`+`Query().Set`, ikke strengkonkatenering — tåler en redirect_uri som allerede har query-parametre). To lag forsvar mot en gjenlevende `oidc_authz`-cookie fra en avbrutt OIDC-runde som ellers kunne kapre en påfølgende, urelatert innlogging: `/login` rydder cookien proaktivt i sin ikke-OIDC-gren, og `/dispatch` krever i tillegg at `?service=` (satt av alle fire login-handlerne) er identisk med cookiens `client_id`, og verifiserer `redirect_uri` mot allowlisten på nytt der koden faktisk utstedes. `/token` støtter en ny `grant_type=authorization_code`: `code_verifier` sin lengde valideres (43-128 tegn) før bruk, koden løses inn (redirect_uri og client_id må matche eksakt hva koden ble utstedt for), PKCE verifiseres alltid (`code_verifier` → SHA-256 → base64url mot lagret `code_challenge`), access-tokenet utstedes med `aud`=client_id (`Issuer.IssueAccessForAudience` — det vanlige access-tokenet har ingen `aud`), og et ekte `id_token` (`aud`=client_id, `nonce` fra requesten) utstedes kun hvis scope inneholder `openid`. Discovery-dokumentet lister nå `grant_types_supported`, `code_challenge_methods_supported`, `scopes_supported` og `token_endpoint_auth_methods_supported: ["none"]`. Motivert av et konkret behov: en ekstern tredjepart skal kunne implementere "Logg inn med [tjeneste]" med et standard OIDC-klientbibliotek, noe den eksisterende flyten (token direkte i URL, ingen `aud`/`nonce`) ikke støtter trygt utenfor tjenester vi selv kontrollerer klientkoden til. Herdet gjennom en runde kodegjennomgang før merge — se PR-diskusjonen for detaljer, inkludert et par ting vurdert og bevisst utsatt (server-side revokering av tokens ved kode-gjenbruk).
- Ny nullable `services.email_from_address`-kolonne (samme mønster som `auth_host`) og Brevo-transport i `internal/mail`. En tjeneste med satt adresse sender magic-link via Brevo med den adressen som avsender; tomt felt gir uendret oppførsel (global `KAUTH_SMTP_FROM` via rå SMTP). `spekto`-tjenesten er satt til `noreply@spekto.live` (bekreftet DNS-verifisert i den delte Brevo-kontoen) — de fire andre tjenestene er uendret, siden deres domener ikke er Brevo-verifiserte. Retter et tillitssignal der en Spekto-bruker mottok magic-link-e-post fra `noreply@klarsyn.net`, som ikke matcher hverken merkevaren eller lenken den peker til.
- `SECURITY.md` med rapporteringsguide og threat model.
- `CHANGELOG.md`.
- `CONTRIBUTING.md` med lokal utvikling, struktur og PR-prosess.
- `.env.example` med alle konfig-variabler.
- Login-sidene (`/login`, `/magic-login`) og magic-link-e-posten finnes på norsk, engelsk og tysk. Språk velges fra `?lang=` eller nettleserens `Accept-Language`, med engelsk som fallback. Diskret språkvelger nederst på sidene. Admin-panelet er fortsatt norsk-only.
- Tjenestenes taglines er oversatt per tjeneste i `internal/i18n/taglines.go`. `services.tagline` brukes som fallback for tjenester som ennå ikke er oversatt.
- Feilmeldingene i magic-link-verifiseringen er lokalisert: utløpt/brukt lenke og manglende konto redirecter til `/magic-login?error=<kode>&lang=<locale>` i stedet for å svare med norsk plaintext. Magic-lenken i e-posten bærer `&lang=` så et eksplisitt språkvalg overlever turen via e-postklienten.

### Changed

- Serverfeil i magic-link-verifiseringen logges nå med `slog.Error` og spesifikk årsak, mens brukeren får én generisk oversatt melding. Tidligere ble tekniske detaljer vist på skjermen uten at noe ble logget.

- Admin Google-login bruker nå samme `/callback`-URL som vanlig brukerflyt, via intern `redirect_uri`-cookie til `/admin/google-callback`. Matcher Java-originalens mønster og krever ikke separat redirect-URI hvitlistet hos Google.
- `doc/FEATURES.md` oppdatert med admin Google-flyt-detaljer og intern-dispatch-seksjon.

### Fixed

- `/dispatch` gjettet hvilken tjeneste brukeren hadde logget inn på. Login-handlerne kjenner tjenesten presist — Google og Microsoft har den HMAC-verifisert gjennom `VerifyState` — men kastet den bort i redirecten og sendte bare token og refresh videre. Dispatcheren måtte derfor lete gjennom tjenestene i `ListActiveServices`-rekkefølge (`ORDER BY display_name`) og ta den første med en `default_org` som fantes blant brukerens orgs, slik at utfallet ble avgjort av alfabetisk rekkefølge framfor av hvor brukeren skulle. En bruker med orgs `playground, vinkjeller`, og ingen org som noen klarsyn-tjeneste eier, falt gjennom til Vinkjeller ved innlogging på Klarsyn og havnet på `kjeller.lilleklo.work`. Feilen traff alle klarsyn-brukere uten `lars` i orgs, men var usynlig for kongebrukeren: han treffer Analyse først, og Analyse deler `callback_url` med Klarsyn — riktig landing av et sammentreff, ikke av routing. Service-IDen sendes nå som `?service=` fra alle fire login-veiene og brukes som nytt nivå 2, validert mot registryet. Redirect går fortsatt bare til `callback_url` fra basen, så en ukjent eller påfunnet ID kan ikke styre hvor brukeren havner. Org-matchen er beholdt som nivå 4 for forespørsler uten `?service=`, men ingen av våre egne flyter er avhengig av den lenger; heuristikken er feilbarlig i seg selv og bør på sikt ut. Samme feilfamilie som magic-link-oppføringen under: en tjeneste-identitet som går tapt underveis i en multi-tenant-flyt.

- `services.auth_host` var ikke satt for `klarsyn`, mens `KAUTH_ISSUER` er `auth.klarsyn.net`. Host-matchen i både `service.Registry.Resolve` og dispatcheren kunne dermed ikke treffe for klarsyn-innlogginger, som falt videre til org-gjettingen over. Satt i prod-basen; ingen kodeendring.

- Magic-link-e-posten sendte alltid brukeren til den globale, statiske `KAUTH_BASE_URL` (`auth.klarsyn.net`) uansett hvilken tjeneste innloggingen gjaldt — en Spekto-bruker havnet dermed på Klarsyn sin side. Lenken bygges nå fra den allerede resolvet tjenestens `auth_host` når den er satt, med samme fallback-oppførsel som før for tjenester uten eget `auth_host` (Klarsyn, uendret). Fjernet også en ubrukt `redirect_uri`-query-param-lesing i `/magic-login` (klienten sendte den aldri).

## [0.1.0] — 2026-06-18

Første portering av kauth fra Quarkus til Go er ferdig og kjører i prod.

### Added

#### Auth-flyter

- Google OIDC med HMAC-signert state og per-host redirect_uri
- Microsoft OIDC mot `/common`-endepunktet, kanonisk JWKS-URL
- Magic-link på e-post med 15-minutters TTL, atomisk konsumering, rate-limiting og anti-enumeration
- Passord-login (deaktivert som default; bcrypt-hashing når aktivert)
- Cross-host login-flyt: JWT som URL-query, refresh-token som URL-fragment til app-callback

#### Token-håndtering

- RS256-signerte JWT-er
- JWKS- og OpenID Discovery-endepunkter
- Refresh-token-rotasjon med opake tokens (SHA-256 hashet)
- Family-revocation ved gjenbruksdeteksjon (RFC OAuth-BCP §4.13) via `GetRefreshTokenByHash`
- Per-tjeneste TTL og refresh-token-max-age

#### Multi-tenant

- Datadrevet service-config-tabell
- Tjeneste-resolver med fire-nivå prioritet (eksakt redirect_uri-match, auth_host, service-ID, suffix-match)
- Per-tjeneste branding (theme, accent_color, logo_html, bg_image, bg_css)
- Per-tjeneste OIDC client_id/secret-overstyring
- Cache-invalidering ved service-mutasjon
- Host-match i dispatcher for auth_host → service-routing

#### Admin-panel

- Innlogging via magic-link og Google OIDC
- Konge-rolle som autorisasjonsbase
- Bruker-CRUD med paginering, søk og org-filter
- Audit-logg med eksport som CSV
- Tjeneste-CRUD med cache-invalidering
- Bakgrunnsbilde-upload med MIME-validering og 1 MB-grense

#### Sikkerhet

- HMAC-state for OIDC med konstant-tids sammenligning
- HttpOnly + Secure cookies (overstyrbart med `KAUTH_INSECURE_COOKIES` for lokal HTTP)
- Anti-enumeration med 200ms minimum-respons-tid og identiske svar
- Rate-limiting på magic-link (3 per 15 min per e-post)
- Audit-isolering i goroutine — audit-feil blokkerer aldri auth-flyt
- IP-tracking via Cloudflare-header (`CF-Connecting-IP`)
- CSV-injection-prefiks-håndtering (`'`-prefiks på `=`, `+`, `-`, `@`, `\t`, `\r`)
- Open-redirect-beskyttelse i dispatch (avviser `//evil.com`-mønstre)

#### Drift

- Statisk Go-binær (~14 MB) uten CGO
- Cross-compile til ARM64-linux via `make build-arm64`
- Graceful shutdown via `signal.NotifyContext`
- Cleanup-jobber for magic-tokens, refresh-tokens og audit-events (90 dagers retensjon)
- WAL-modus SQLite med `foreign_keys = ON`
- Daglig backup via `scripts/backup-kauth-go.sh` (cron 03:00, 30 dagers retensjon)
- systemd-unit med `GOMEMLIMIT` og cgroup-minnegrenser
- Strukturerte logger via `log/slog`

#### Verktøy

- `scripts/migrate-h2/` — engangsverktøy for H2 → SQLite-migrering fra Java-versjonen
- `scripts/backup-kauth-go.sh` — daglig SQLite-backup

#### Dokumentasjon

- README.md med onboarding, OIDC-oppsett og det passordløse valget
- `doc/FEATURES.md` med detaljert funksjonsoversikt
- MIT-lisens

### Migrasjon fra Java-versjonen

Data fra `quarkus-simple-auth` (H2-database) ble migrert via `scripts/migrate-h2/`. Reverse-migrering (SQLite → H2) for kald fallback ligger i `quarkus-simple-auth/scripts/migrate-to-h2/`. Cloudflare Tunnel ble pekt om fra Java-container på port 8082 til kauth-go på port 8083.

[Unreleased]: https://github.com/zral/kauth-go/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/zral/kauth-go/releases/tag/v0.1.0
