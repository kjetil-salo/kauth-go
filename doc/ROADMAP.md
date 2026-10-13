# kauth-go — sikkerhetsavklaring og overordnet plan

**Status:** Utkast til godkjenning (2026-10-13)
**Eier:** Lars
**Gjelder:** prod (`master` lokalt, 17d818e — kjører på lilleklo) og `origin/master` (5363c34, 9 commits foran, inkl. authorization_code + PKCE fra kjetil-salo)

Dette dokumentet er paraplyen over de neste featurene. Hver fase under blir én eller flere DSF-features. Hver av dem går gjennom analyse- og plan-gate før kode røres, og analyse og plan holdes lokalt. *Hvorfor*-beslutninger føres i [ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md); *hva som gjenstår* i [BACKLOG.md](BACKLOG.md).

**Grunnlag:**

1. ChatGPT-vurdering «Vurder kauth go» (dokumentbasert, ikke kode) — risikopunkt A–E og en 12-ukers utviklingsplan.
2. Ekstern revisjon (ChatGPT, kodebasert gap-analyse av utvalgte filer) — samme dato.
3. Egen verifisering mot faktisk kode i begge versjoner, med fil:linje-bevis. De kritiske funnene er reprodusert mot en lokal, isolert eval-instans, ikke mot prod.

---

## 1. Sammendrag

Retningen fra begge ChatGPT-rundene holder: kauth-go skal være en passordløs **identity broker** — autentisering delegeres, identitet og autorisasjon eies (se ADN 7). Den eksterne revisjonens rekkefølge — stabil identitet *før* generisk OIDC — er riktig, og den er tatt inn her.

Men verifiseringen fant tre ting ingen av gjennomgangene så, og som endrer prioriteringen: **det finnes en ett-klikks kjede fra en lenke til full admin-overtakelse i prod i dag.**

1. **Open redirect** i `/dispatch` (`/\evil.com` passerer intern-sti-sjekken) sender access-tokenet til en ekstern vert. Reprodusert: `Location: /\evil.example?token=eyJ…`.
2. **`/admin/google-callback`** bytter *ethvert* kauth-signert JWT for en `konge`-bruker til en 8-timers admin-sesjon — ingen sjekk av `token_use` eller `aud`.
3. Kombinert: en lenke til `https://auth…/social-login?redirect_uri=/%5Cevil.com` som en admin klikker på, gir angriperen et access-token, som veksles til admin-sesjon.

I tillegg: admin-skjemaet for tjenester **nuller `require_role`/`enforce_org`** (og per-tjeneste OAuth-credentials) hver gang en tjeneste lagres, og **refresh-grant lar klienten velge tjeneste fritt** uten policy-sjekk. Begge undergraver tilgangskontrollen stille.

Derfor en ny **Fase 0 (akutt herding)** før alt annet. Den er liten (S-tiltak, anslag 3–5 utviklerdager) og kan gå som én DSF-feature.

---

## 2. Risikoregister

Alvorlighet: **K** kritisk · **H** høy · **M** middels · **L** lav. «Prod» = finnes i prod i dag. Str. = S/M/L innsats.

### 2.1 Kritisk

| ID | Funn | Prod | Bevis | Tiltak | Str. | Fase |
|---|---|---|---|---|---|---|
| K1 | **Open redirect lekker access-token.** Intern-sti-sjekken er `HasPrefix("/") && !HasPrefix("//")`; `/\evil.com` slipper gjennom, nettlesere tolker `/\` som `//`. Cookien settes fra query (`/social-login?redirect_uri=`, `google.go:42` og JS i `login.html:207`) | Ja | `dispatch.go:152` (origin), `:86` (prod). Reprodusert lokalt | Eksakt allowlist av interne stier (i dag kun `/admin/google-callback`); avvis `\` og kontrolltegn; krev tom scheme/host etter `url.Parse` | S | 0 |
| K2 | **Token confusion inn i admin.** `HandleGoogleCallback` godtar ethvert gyldig kauth-JWT (access/id/admin, enhver tjeneste) fra `?token=` og utsteder admin-cookie hvis e-posten har `konge` | Ja | `admin/auth.go:276-331`; `Verify` sjekker kun signatur/iss/exp (`token/issuer.go:206-221`) | Erstatt med kortlivet engangs-handoff (`token_use=admin_handoff`, `aud=kauth-admin`, ≤60 s, engangs) eller direkte Google-callback for admin; `Verify` skal ta forventet `token_use`/`aud` | S | 0 |
| K3 | **Tokens i journald.** chi `Logger` logger full `RequestURI`: `/dispatch?token=<AT>&rt=<RT>`, `/admin/google-callback?token=<AT>`, `/magic-login/<token>`. Verifisert i prod-journald (11 + 1 linjer siste uke). Med K2: lokal lesetilgang til logg ⇒ admin | Ja | `cmd/kauth/main.go:101` | Redigerende request-logger (stripp `token`, `rt`, `code`, magic-sti); rydd eksisterende journald etter fiks | S | 0 |

### 2.2 Høy

| ID | Funn | Prod | Bevis | Tiltak | Str. | Fase |
|---|---|---|---|---|---|---|
| H1 | **Admin-lagring nuller tjenestefelt.** Skjemaet mangler `require_role`, `enforce_org`, `google/microsoft_client_id/secret`, `logo_html`, `bg_css`, men `UpdateService` skriver alle → NULL/0. Tilgangskrav slås av stille; per-tjeneste OAuth-klient faller til global | Ja | `admin/services.go:296-332`, `templates/admin/service-edit.html`, `query/services.sql:25-36` | Felt som ikke er i skjemaet beholdes (egen query eller «behold ved tomt»); legg `require_role`/`enforce_org` inn i skjemaet; regresjonstest. **Sjekk prod-DB for tjenester der kravene allerede er nullet** | S | 0 |
| H2 | **Refresh-grant uten tjenestebinding og policy.** `/token` tar `service_id` fra skjemaet, ikke fra refresh-raden, og kjører ikke `checkPolicy`. RT fra åpen tjeneste B ⇒ access-token for A uten A sine krav. Refreshede code-flow-tokens mister `aud` | Ja | `password.go:259-275` (origin), `:115` (prod); `refresh.go:107,170` lagrer `service_id` men returnerer det ikke | Bruk lagret `service_id`, avvis avvik, kjør `checkPolicy`, behold `aud` | S | 0 |
| H3 | **Prod mangler policy-fikser fra origin.** `checkPolicy` kun i Google/MS (ikke magic/passord), og `strings.Contains`-match (`sysadmin` oppfyller `admin`) | Ja | prod `google.go:190-193`; fikset i origin 3801891 | Merge origin → prod (lokale malendringer må håndteres først) | S | 0 |
| H4 | **nOAuth-klassen i Microsoft-flyten.** `/common` + `SkipIssuerCheck`, ingen `tid`-allowlist, ingen `nonce`, ingen `xms_edov`; mapping på `email` → `preferred_username`. En fremmed tenant kan sette `mail` til en eksisterende brukers adresse. Faktisk utnyttbarhet avhenger av app-registreringen «Klarsyn» (`removeUnverifiedEmailClaim`) | Ja | `microsoft.go:108-134,167` | Kort sikt: krev `xms_edov==true` (eller personlig MSA), valgfri `tid`-allowlist per tjeneste, send+verifiser nonce. Varig: identitet på `(tid, oid)` (Fase 2) | S→M | 1 |
| H5 | **Ingen `aud` på vanlige access-tokens** (kun code-flow har det). Et token for tjeneste B er gyldig mot A for enhver ressursserver som sjekker signatur+iss | Ja | `issuer.go:153-159` | `aud=svc.ID` på alle access-tokens, `aud=kauth-admin` på admin, `jti`; klientene (vinkjeller, pov, klarsyn) begynner å kreve `aud` | M | 1 |
| H6 | **Refresh-race og manglende revokering.** Konsumering, innsetting av barn og family-revoke er tre separate operasjoner; revoke treffer kun `used=0`, så barnet til den som vant racet overlever reuse-deteksjon. Revoked token trigger ikke family-revoke. Logout og deaktivering revokerer ikke | Ja | `refresh.go:125-179`, `query/refresh_tokens.sql:16`, `dispatch.go:228-268` | Én transaksjon; revoke på `family_id` uten `used`-filter; revoke ved logout/deaktivering | S–M | 1 |
| H7 | **CORS `*` med credentials.** `*` i `KAUTH_CORS_ORIGINS` speiler enhver Origin og setter `Allow-Credentials: true` ⇒ ethvert nettsted kan rotere og lese refresh via `fetch(credentials:'include')`. README sier «ikke wildcard». `/token` har heller ingen Origin-sjekk (RT-cookie er `SameSite=None`) | Konfig-avhengig | `auth/middleware.go:47-49` | Avvis `*` ved oppstart; krev Origin i allowlist på cookie-basert `/token` | S | 0 |

### 2.3 Middels

| ID | Funn | Bevis | Tiltak | Str. | Fase |
|---|---|---|---|---|---|
| M1 | **Token-i-URL (legacy-flyten).** Alle login-flyter sender AT+RT i query til `/dispatch`; legacy-callback får `?token=` + `#rt=`. Kan ikke slås av per tjeneste. Ingen `Referrer-Policy` | `dispatch.go:43-53`, `google.go:161`, `magic.go:279` m.fl. | `Referrer-Policy: no-referrer` (Fase 0); internt bytte til engangs-handle i stedet for tokens i URL; per-tjeneste `legacy_token_redirect`; migrer klientene til code+PKCE | M | 0 (header) / 1 |
| M2 | **Magic link konsumeres på GET** — e-postskannere brenner eller *fullfører* innloggingen (gjelder også `/admin/verify`) | `main.go:135`, `magic.go:212`, `admin/auth.go:172` | Bekreftelsesside på GET, konsumering på POST | M | 1 |
| M3 | **Magic link: klartekst i DB, svak rate limit, URL-styrt tjeneste.** Token lagres ukryptert; limiter er prosesslokal, ryddes aldri, nøkkel er rå e-post (case-varianter omgår den); admin-magic har ingen limit; `VerifyToken` bruker `?service=` fra URL i stedet for tokenets `ServiceID`; service-ID uescapet i lenken | `magic.go:25-55,135,150,160,181,205`; `admin/auth.go:83-169` | SHA-256 som for refresh; normalisert e-post; TTL-limiter med opprydding; limit på admin; bind til lagret tjeneste; `QueryEscape` | S–M | 1 |
| M4 | **Klient-IP kan forfalskes, og kauth lytter på alle interfaces.** `chimiddleware.RealIP` (deprecated, spoofbar) + egen kjede stoler på True-Client-IP/X-Real-IP/XFF/CF-Connecting-IP. Prod lytter på `*:8083` — nåbar fra LAN og docker0 forbi tunnelen. Påvirker audit, ikke authz | `main.go:100,199`; `audit/service.go:70-83` | Fjern RealIP; stol på `CF-Connecting-IP` kun fra loopback, valider med `net.ParseIP`; `KAUTH_HTTP_ADDR` default `127.0.0.1` | S | 0 |
| M5 | **Ingen sikkerhetsheadere.** Ingen CSP, `frame-ancestors`/XFO, `nosniff`, HSTS. Login/admin kan rammes inn; `logo_html` rendres rått uten CSP | grep: 0 treff; `magic.go:86` | Header-middleware | S | 0 |
| M6 | **Admin-CSRF.** Kun `SameSite=Lax`; søster-apper under samme registrerbare domene er same-site | `admin/*.go` | `Origin`/`Sec-Fetch-Site`-sjekk på alle POST under `/admin` | S | 1 |
| M7 | **Google-flyten:** ingen `email_verified`, ingen nonce til Google, ingen `hd`-støtte, ingen upstream PKCE; `err.Error()` lekkes til bruker (også i MS) | `google.go:61,105-115`; `microsoft.go:116,137` | Krev `email_verified`; nonce + PKCE; valgfri `hd`-allowlist per tjeneste; generiske feilmeldinger | S | 1 |
| M8 | **Signeringsnøkler:** én nøkkel, ingen `kid` i JWT-header (JWKS har hardkodet `kauth-1`), rotasjon = restart og alle tokens ugyldige. `FEATURES.md` påstår feilaktig at rotasjon oppdages automatisk | `issuer.go:32-38,142-149,224-237` | Nøkkelring med `kid`, current/next/previous i JWKS, dokumentert prosedyre | M | 5 |
| M9 | **Audit er asynkron** (fire-and-forget goroutine; tapes ved feil og SIGTERM). **Admin-JWT kan ikke trekkes tilbake** (middleware slår ikke opp rolle i DB; 8 t) | `audit/service.go:36-58`; `admin/middleware.go:23-35` | Bufret kø med flush ved shutdown (synkront for admin-skriv); rolle-sjekk mot DB i admin-middleware | S–M | 1 |
| M10 | **Passordinnlogging uten rate limit/lockout**, timing-enumerering, kun av/på per tjeneste | `password.go:34-87` | Global kill-switch `KAUTH_PASSWORD_LOGIN_ENABLED` (default av); se beslutning B4 | S | 0 |
| M11 | **E-post er case-sensitiv** i Google/MS/magic/passord (admin normaliserer) ⇒ duplikatkontoer, omgått limiter | `query/users.sql:5`, `001_init.sql:40` | `lower(trim())` ved inngang + migrering/kollisjonssjekk av eksisterende data | S–M | 2 |
| M12 | **Klienthemmeligheter i klartekst i SQLite.** Vises ikke i UI, audit eller eksport; DB/backup er 0600 og backup bruker `umask 077` (ok) | `001_init.sql:26,28` | Kryptering i hvile med nøkkel fra env, eller flytt til env/fil per tjeneste | M | 5 |

### 2.4 Lav / hygiene

| ID | Funn | Tiltak | Fase |
|---|---|---|---|
| L1 | Magic-link-e-post sendes selv om lagring av tokenet feiler (sett ved reproduksjon: FK-feil, mail sendt likevel) | Returner før sending ved lagringsfeil | 1 |
| L2 | Autorisasjonskode brennes før `client_id`/`redirect_uri`/PKCE sjekkes; gjenbruk revokerer ikke tokens fra første innløsning; koder i klartekst | Sjekk først; revoker ved gjenbruk | 1 |
| L3 | `enforce_org=1` med tom `default_org` håndhever ingenting, uten varsel; admin validerer ikke `callback_url` | Admin-validering | 1 |
| L4 | Legacy nivå 1 godtar `redirect_uri` fra *hvilken som helst* tjenestes allowlist, ikke tjenesten man logget inn mot | Begrens til innloggingstjenesten | 0 |
| L5 | Prods discovery annonserer `response_types: code` og `authorization_endpoint: /login`, men prod har ikke code-flyten (løses av merge, H3) | — | 0 |
| L6 | Ingen CI; `gofmt -l` ikke rent (6 filer); `govulncheck` ikke installert; én tag (`v0.1.0`) | GitHub Actions: fmt, vet, test, `-race`, govulncheck | 6 |
| L7 | bcrypt cost 10; `rand.Read`-feil ignoreres i `magic.go:150`; `Invalidate`-feil ignoreres i admin | Opprydding | 1 |

---

## 3. ChatGPTs påstander mot koden

| Påstand | Verdikt | Kommentar |
|---|---|---|
| A — tokens i URL via `/dispatch` | **Bekreftet, verre** | Også RT i query til `/dispatch`, også i code-flyten, og logget til journald. Åpnet K1 og K2 |
| B — refresh-cookie `SameSite=None` | **Bekreftet** | Pluss CORS-`*` med credentials (H7) og ingen Origin-sjekk |
| C — ingen automatisk nøkkelrotasjon | **Bekreftet** | I tillegg ingen `kid` i header og ingen `aud` på access/admin (H5, K2) |
| D — secrets i klartekst | **Bekreftet** / filrettigheter **ok** | Fant H1 i samme kode |
| E — trust boundary mot Cloudflare | **Bekreftet** | Prod lytter på `*:8083`, og RealIP gjør alle headere spoofbare |
| Autorisasjonsfeil «allerede funnet» | **Fikset i origin, ikke i prod** | Refresh-grant (H2) er fortsatt åpen |
| Roller/org som CSV | **Bekreftet** | Eksakt match i origin, substring i prod. CSV beholdes |
| Asynkron audit | **Bekreftet** | `CLAUDE.md` sa «synkront» — rettet |
| «OIDC Code + PKCE finnes» (planens premiss) | **Kun i origin** | Prod må oppgraderes først |

**Ekstern revisjon:** funnene stemmer (e-post som identitet, ingen upstream nonce/PKCE, `SkipIssuerCheck`, refresh uten transaksjon, token-i-URL, `sub=email`). Den overså K1, K2, K3, H1 og H2, og tok derfor ikke med akuttfasen. Den var også uklar på nOAuth-risikoen: problemet er ikke at issuer mangler, men at e-post fra en fremmed tenant brukes som identitet. Begrensningen den selv oppgir (leste bare utvalgte filer) forklarer avviket.

---

## 4. Beslutninger som trengs fra Lars

| # | Spørsmål | Anbefaling |
|---|---|---|
| B1 | **Kontokobling:** skal samme e-post fra to leverandører automatisk bli samme bruker? | **Nei.** Hver ekstern identitet `(iss, sub)` er sin egen kobling; ny kobling bare etter fersk innlogging med en eksisterende. Overgang: eksisterende e-postbrukere får identiteten koblet *ved første innlogging etter migreringen*, kun fra Google med `email_verified` / MS med `xms_edov` / magic link. Deretter låses koblingen |
| B2 | **`sub`-semantikk:** e-post → stabil ID | Per tjeneste-flagg `sub_format` (`email` default, `id` opt-in). Klientene (vinkjeller, pov, klarsyn, spekto) migreres én og én; `email`-claim beholdes |
| B3 | **Legacy token-i-URL:** når skal den slutte? | Fase 0 gjør den trygg (K1, L4, Referrer-Policy, loggredigering). Per-tjeneste av-bryter i Fase 1; av som default for nye tjenester; fjernes når alle klienter er på code+PKCE |
| B4 | **Passord:** fjerne helt eller beholde av? | Global kill-switch nå (default av). Fjern koden når ingen tjeneste har `auth_password=1` |
| B5 | **Microsoft-tenants:** alle eller allowlist? | `xms_edov` påkrevd for alle; valgfri `tid`-allowlist per tjeneste |
| B6 | **Merge av origin:** kjetil-salos 9 commits inn i prod | Ja, som første steg i Fase 0. Lokale endringer i `templates/login.html` og `magic-login.html` committes eller stashes først |

---

## 5. Faseplan

Én erfaren utvikler (DSF-pipeline). Estimater i utviklerdager, eksklusive ekstern revisjon.

| Fase | Innhold | Risikoer | Est. | DSF-feature |
|---|---|---|---|---|
| **0 — Akutt herding** | Merge origin → prod; K1 intern-sti-allowlist; K2 admin-handoff + `Verify` med forventet `token_use`/`aud`; K3 redigerende logger + rydd journald; H1 skjemabug + sjekk av prod-data; H2 refresh-binding + policy; H7 avvis CORS-`*` + Origin-sjekk på `/token`; M4 bind 127.0.0.1 + fjern RealIP; M5 sikkerhetsheadere inkl. `Referrer-Policy`; M10 passord-kill-switch; L4 | K1–K3, H1–H3, H7, M4, M5, M10, L4, L5 | 3–5 | 007 |
| **1 — Herd eksisterende flyter** | Utløpstid (`iat`) i signert OIDC-state; full formålsbinding magic-token ↔ tjeneste med eksplisitt `purpose`-kolonne i stedet for `service_id IS NULL` (fra 007-review); Upstream nonce + PKCE (Google/MS); `email_verified`/`xms_edov`/`tid`; refresh i én transaksjon + revoke ved logout/deaktivering; `aud`+`jti` på alle tokens; magic link: bekreftelsesside, hashing, limiter, tjenestebinding; admin-CSRF; audit-kø; admin-middleware mot DB; legacy-av-bryter per tjeneste | H4–H6, M1–M3, M6, M7, M9, L1–L3, L7 | 7–11 | 008–010 |
| **2 — Stabil identitet** | `user_identities(user_id, provider, issuer, subject)` unik på `(issuer, subject)`; stabil intern ID; e-postnormalisering; migrering med kollisjonsrapport; `sub_format` per tjeneste; eksplisitt kobling/frakobling og recovery (B1, B2) | P-funnene, M11 | 6–9 | 011–012 |
| **3 — Felles føderert innlogging** | `FederatedLoginService` + provider-grensesnitt; Google/MS refaktorert inn (gamle handlere kjører side om side til de er verifisert); `checkPolicy` og utstedelse ett sted | — | 4–6 | 013 |
| **4 — Generisk OIDC** | `identity_providers` + `service_identity_providers`; discovery med eksplisitt issuer-allowlist (SSRF-vern); JWKS-cache; lokal OIDC-testleverandør for negativtester | — | 5–8 | 014 |
| **5 — Policy, admin-UX, nøkler og hemmeligheter** | Provider-admin og tilordning per tjeneste; `allow_magic_link` / `allowed_providers` / `require_federated_login`; nøkkelring med `kid`; secrets kryptert i hvile | M8, M12 | 5–8 | 015–016 |
| **6 — Test, drift og release** | CI (fmt, vet, test, `-race`, govulncheck); E2E mot testleverandør; restore-test av backup; fuzzing av redirect/callback; oppdatert SECURITY.md/FEATURES.md; ekstern revisjon; `v1.0.0` | L6 | 5–8 | 017 |
| | **Totalt** | | **35–55** | |

Fase 0 er en forutsetning for alt annet og bør gå før noen klient endres. Fase 1 og 2 kan delvis overlappe; Fase 3 forutsetter Fase 2.

### Utenfor scope (bekreftet)

Egen WebAuthn/passkeys, TOTP/HOTP, passord som fremtidig metode, LDAP/AD, SAML, Postgres/Redis, horisontal skalering. **Apple Sign In** ligger i backlog (årsavgift 99 USD for Apple Developer Program; arkitekturen i Fase 3–4 skal gjøre den til en adapter senere).

### Dokumentasjon som må rettes underveis

- `doc/FEATURES.md`: påstand om automatisk nøkkelrotasjon (:59), `aud` som standard-claim (:51), `token_use`-verdier (:50), «rt sendes ikke til serveren» (:339), family-revoke ved `revoked=1` (:71).
- `README.md:119` / `SECURITY.md`: CORS «ikke wildcard» og IP-tillitsmodell stemmer ikke med koden før Fase 0.

---

## 6. Hvordan planen kjøres

Hver fase startes med `/feature-lifecycle` og får eget løpenummer (fra 007; 001–006 brukt i Quarkus-kauth, se ADN-loggen). Holdout-scenariene for Fase 0 skrives *før* fiksene og skal minst dekke:

- `/\` og `/%5C` i `redirect_uri` gir aldri `Location` utenfor kauth
- et vanlig access-token mot `/admin/google-callback` gir ikke admin-cookie
- refresh med `service_id` ulik tokenets tjeneste avvises
- lagring av en tjeneste i admin beholder `require_role`/`enforce_org`
- `KAUTH_CORS_ORIGINS=*` stopper oppstart

Kauth-endringer er sikkerhetskritiske, så security-review (opus) kjøres for alle diffs under `internal/auth/`, `internal/token/`, `internal/admin/`, `internal/service/` og `cmd/kauth/`.
