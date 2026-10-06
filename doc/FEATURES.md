# Funksjonalitet i kauth

En komplett oversikt over hva kauth gjør og hvordan. README-en gir overordnet motivasjon; dette dokumentet gir detaljen.

## Innholdsfortegnelse

- [Innloggingsmetoder](#innloggingsmetoder)
- [Token-håndtering](#token-håndtering)
- [OIDC authorization_code + PKCE](#oidc-authorization_code--pkce)
- [Multi-tenant arkitektur](#multi-tenant-arkitektur)
- [Admin-panel](#admin-panel)
- [Sikkerhetsmekanismer](#sikkerhetsmekanismer)
- [Cross-host login-flyt](#cross-host-login-flyt)
- [Audit-logg](#audit-logg)
- [Bakgrunnsjobber](#bakgrunnsjobber)
- [Endepunkter](#endepunkter)
- [Datamodell](#datamodell)
- [Drift og kjøremiljø](#drift-og-kjøremiljø)

## Innloggingsmetoder

Fire metoder, alle valgbare per tjeneste via boolean-felter i `services`-tabellen (`auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`).

### Google OIDC

Standard OAuth2-flyt med PKCE og signert state. Nonce sendes til Google og sjekkes mot `id_token.nonce`. `email_verified == true` kreves i både vanlig og admin-gren; ellers avvises innloggingen og `google_oidc_rejected` logges i audit. Per-tjeneste OAuth-klient hvis `google_client_id` er satt på service-raden, ellers global klient fra miljøvariabler. Redirect-URI bygges per request fra `Host`-headeren, slik at ulike auth-hostnames kan registreres mot ulike Google-klienter med presise whitelists.

### Microsoft OIDC

Bruker `/common/oauth2/v2.0`-endepunktet for å akseptere både personlige Microsoft-kontoer og bedriftskontoer. Signaturen valideres mot kanonisk JWKS-URL: `https://login.microsoftonline.com/common/discovery/v2.0/keys`. Biblioteket kjører med `SkipIssuerCheck`, fordi `iss` er per tenant. kauth sjekker i stedet selv at `iss` er `https://login.microsoftonline.com/{tid}/v2.0` (ADN 10).

- Personlig konto (MSA) gjenkjennes bare på `tid == 9188040d-6c67-4c5b-b112-36a304b66dad`. Et manglende claim tolkes aldri som personlig konto.
- Organisasjonskonto krever `xms_edov == true`. `xms_edov` er optional claim i app-registreringen, og er konfigurert i begge Entra-appene (Klarsyn og spekto).
- Tom `email` avvises. Det er ingen fallback til `preferred_username`.
- Nonce sendes til Microsoft og sjekkes mot `id_token.nonce`.
- Avvisning logges som `microsoft_oidc_rejected` med `reason=<årsak>` og `tid` i details.

### Magic-link på e-post

256-bit kryptografisk tilfeldig token i en lenke, 15 minutters levetid, engangsbruk via atomisk `UPDATE WHERE used = 0`. Tokenet lagres som SHA-256-hex (`HashOpaque`), aldri i klartekst. Klartekst finnes bare i e-posten.

- **Bestilling (`POST /magic-login`):** e-posten normaliseres (`NormalizeEmail`: trim + små bokstaver) før alt annet. Kvoten er 3 bestillinger per normalisert e-post og formål (`service`/`admin`) per 15 minutter. Den telles i databasen i samme `INSERT`, så den overlever restart og holder under parallelle forespørsler. Er kvoten brukt opp eller lagringen feiler, sendes ingen e-post. Svaret er likevel det samme (se Anti-enumeration). Sending skjer asynkront, slik at responstiden ikke skiller kjente fra ukjente adresser
- **Tjenestebinding:** raden lagrer tjenesten som ble resolvet ved bestilling, ikke skjemaverdien. Er `auth_magic_link` av for tjenesten, settes ingen rad inn. Ved innløsning brukes bare den lagrede tjenesten, uansett `?service=` eller host. Er tjenesten inaktiv eller har magic link av da, gir det `error=expired`, og tokenet brennes
- **Bekreftelsesside:** lenken i e-posten åpner `GET /magic-login/{token}`, som bare viser en side med én knapp. Siden har tjenestens tema, nb/en/de, ingen e-postadresse og ingen JavaScript. GET endrer ingenting og teller ikke i kvoten, så lenkeskannere og forhåndsvisning i e-postklienter bruker ikke opp tokenet. Knappen sender `POST /magic-login/{token}`, som bruker opp tokenet og logger inn. Ukjent, utløpt eller brukt token gir `error=expired`
- **Samme origin:** POST krever samme origin (se Sec-Fetch under Sikkerhetsmekanismer). Et kryss-origin-forsøk gir `403` med en forklaring («åpne lenken i nettleseren»), og tokenet står urørt
- **Formål:** `magic_tokens.purpose` skiller tjenestelenker (`service`, med `service_id`) fra admin-lenker (`admin`, uten `service_id`). Et token kan ikke brukes på feil side

### Passord

Deaktivert som standard. bcrypt-hashet, lagres i `password_hash`. OIDC-only-brukere får sentinel-verdien `"n/a"` i feltet. Se argumentet for passordfri-default i hoved-README.

## Token-håndtering

### JWT (access token)

RS256-signerte. Claims:
- `sub` — brukerens e-post
- `email`
- `org` — array av tenant-slugs fra `users.orgs` (CSV-felt i DB, splittes ved utstedelse)
- `groups` — array fra `users.roles`
- `name` — valgfri
- `token_use` — `access` eller `admin`
- standard `iss`, `aud`, `iat`, `exp`, `nbf`

TTL settes per tjeneste via `services.access_token_ttl` (ISO 8601-varighet, f.eks. `PT15M`, `PT8H`, `P1D`).

### JWKS + OpenID Discovery

- `GET /.well-known/jwks.json` — eksponerer den offentlige RSA-nøkkelen med `kty=RSA, use=sig, alg=RS256, kid`
- `GET /.well-known/openid-configuration` — standard discovery-dokument med `authorization_endpoint`, `token_endpoint`, `jwks_uri`, `response_types_supported`, etc.
- Resource-servere validerer JWT mot JWKS-URL — kauth-roterte nøkler oppdages automatisk

### Refresh-token-rotasjon

256-bit opake tokens, lagret SHA-256-hashet (`refresh_tokens.token_hash`, 64 hex-char CHECK-constraint). Hver utstedelse skaper en ny familie eller arver eksisterende `family_id`. `POST /token?grant_type=refresh_token` roterer i én transaksjon:

1. Token konsumeres atomisk (`used = 1`) og barnet settes inn i samme transaksjon. Feiler en av delene, er ingenting endret
2. Ny access-JWT + ny refresh-token utstedes med samme `family_id`
3. Eksisterende refresh-cookie overskrives

Feil gir ulik status: klientfeil (ukjent, utløpt, revokert eller gjenbrukt token) gir 401, mens interne feil (DB, tilfeldighetskilde, cache) gir 500 `server_error`. Ved 500 beholder klienten cookien og kan prøve igjen.

### Revokering av refresh-familier

Familien er enheten for tilbaketrekking (ADN 10). Hele familien revokeres (`RevokeFamilyTokens`) når:

- **Reuse:** et konsumert token presenteres igjen. Sjekken er uavhengig av `used`-flagget og av klientens request-context, slik at revokeringen fullføres selv om klienten kobler fra. Audit `refresh_token_reuse` får `service_id` og `gap_s=<sekunder>` fra barnets opprettelse til gjenbruket (`gap_s=unknown` hvis barnet mangler). Lite gap tyder på klient-race, stort gap på stjålet token. Gapet er grunnlaget hvis et idempotensvindu noen gang skal vurderes
- **Revokert token presenteres:** familien tas ned på nytt (revoked_reason `revoked_token_presented`) og audit `refresh_token_revoked_presented` logges. Utløpt-men-ikke-revokert token gir bare avvisning
- **Logout:** `GET /logout` revokerer familien til `refresh_token`-cookien (`user_logout`) før cookien slettes, men bare når forespørselen er en bevisst handling (se Logout og Sec-Fetch under Sikkerhetsmekanismer)
- **Verifisert gjenbruk av autorisasjonskode:** familien koden ga opphav til revokeres (`authorization_code_reuse`) bare når klient, `redirect_uri` og PKCE matcher, se OIDC-delen
- **Deaktivering:** admin-deaktivering av en bruker revokerer alle brukerens refresh-tokens (`user_deactivated`)

Klienten får generisk avvisning, og hele kjeden er død for både angriper og legitim klient. Et ekte refresh-race logger derfor ut begge parter. Matcher OAuth Security BCP (RFC 9700 §4.14.2).

**Akseptert begrensning:** allerede utstedte access-tokens lever til TTL utløper etter logout eller deaktivering. `/api/me` validerer bare JWT-en og sjekker ikke databasen. Kortvarig TTL er den eneste avgrensningen.

### Per-tjeneste TTL og max-age

- `services.access_token_ttl` — JWT-levetid
- `services.refresh_token_max_age` — hardt tak på familielevetid (NULL = ubegrenset)
- `family_expires_at` settes ved første utstedelse fra `max_age`, arves uendret ved hver rotasjon; klempes på `min(now+30d, family_expires_at)` ved utstedelse

## OIDC authorization_code + PKCE

Løser inn en klar mangel i den ellers OIDC-flavored bespoke flyten over:
et standard OIDC-klientbibliotek (`oidc-client-ts`, `authlib` osv.) kan ikke
brukes mot `/login`+`/dispatch` slik de fungerte alene — token kom tilbake
direkte i URL-en, uten `aud`/`nonce`, uten en `code`-runde å bytte inn. Dette
er nødvendig for en klient kauth ikke selv kontrollerer kildekoden til.

### Forespørselen (`/login` som authorization_endpoint)

En standard OIDC-forespørsel gjenkjennes på `response_type=code&client_id=...`.
`client_id` er samme verdi som tjenestens `services.id` — det finnes ingen
egen klient-tabell, en OIDC-klient ER en tjeneste. Ved en slik forespørsel:

1. Tjenesten resolves på `client_id` (ikke `?service=` eller host-header).
   Ukjent `client_id` → 400 direkte fra kauth, ikke en redirect (det ville
   vært en open redirect via en påfunnet client_id — kauth har ingen
   betrodd redirect_uri å sende brukeren til før client_id er slått opp)
2. `redirect_uri` må matche tjenestens `callback_url`-allowlist eksakt
   (samme `Registry.IsAllowedCallback` som Google-flyten bruker). Ikke
   registrert → 400, av samme grunn som over
3. **PKCE er obligatorisk for enhver `response_type=code`-forespørsel —
   ingen per-tjeneste unntak.** `code_challenge` og
   `code_challenge_method=S256` må begge være til stede, ellers redirectes
   brukeren til `redirect_uri?error=invalid_request&state=` (RFC 6749
   §4.1.2.1 — redirect_uri er jo allerede bekreftet trygg i steg 2, så feilen
   rapporteres dit, ikke som en 400 kauth selv viser fram). Det finnes ingen
   konfidensiell klient-type i det hele tatt: `client_id` er offentlig
   informasjon, og en kode uten PKCE ville kunnet løses inn av hvem som
   helst som fanget den opp underveis
4. Hele forespørselen (client_id, redirect_uri, state, nonce, scope,
   code_challenge, code_challenge_method) lagres i en **usignert**
   `oidc_authz`-cookie og bæres videre gjennom resten av innloggingsreisen —
   magic link, Google, Microsoft eller passord er alle uendret og ser
   ingenting av dette

En vanlig (ikke-OIDC) `/login`-forespørsel rydder proaktivt en eventuell
gjenværende `oidc_authz`-cookie fra en tidligere avbrutt OIDC-runde — se
"To lag forsvar" under.

### Autorisasjonskoder

`authorization_codes`-tabellen speiler `magic_tokens` (koden lagres som SHA-256-hex, klartekst går bare i redirecten): kortlevd (60 sekunder
— vesentlig kortere enn magic-link sine 15 minutter, siden koden kun skal
leve fra `/dispatch`-redirect til klientens umiddelbare innløsning) og
engangsbrukt (`used`-flagg, samme "konsumer atomisk"-mønster som
`ConsumeMagicToken`). `code_challenge`/`code_challenge_method` er `NOT NULL`
i skjemaet — reflekterer at PKCE aldri er valgfritt.

`/dispatch` genererer koden idet en `oidc_authz`-cookie er til stede (etter
at brukeren har fullført innlogging via en av de vanlige metodene), og
redirecter til `redirect_uri?code=&state=` (bygget med `url.Parse` +
`Query().Set`, ikke strengkonkatenering — en registrert redirect_uri kan
allerede ha egne query-parametre) — aldri med et token i klartekst i URL-en,
i motsetning til den eksisterende bespoke flyten.

#### Hvorfor tilgangsreglene håndheves i `/token`, ikke i `/dispatch`

Første forsøk på denne herdingen la en `?service=`-sjekk i `/dispatch`: krev
at URL-ens `?service=`-parameter er identisk med `oidcReq.ClientID` før en
kode utstedes. Det viste seg utilstrekkelig, og verdt å forklare hvorfor,
siden feilen er lett å gjenta.

`?service=` er en vanlig URL-parameter — ikke en verdi bundet til tokenet.
Et vanlig access-token har ingen `aud`, så `/dispatch` kan ikke vite hvilken
tjeneste et gitt token faktisk ble utstedt for; den kan bare lese hva URL-en
*påstår*. En bruker med et helt legitimt token for tjeneste B (som de har
lovlig tilgang til) kan derfor, mens en `oidc_authz`-cookie for tjeneste A
ligger fra tidligere (fra å ha klikket "logg inn" i partner-app A, uten å
fullføre den runden), gå rett til `/dispatch?token=<B-token>&service=A` —
uten noensinne å ha gått via A sin egen login-handler, der A sine
`require_role`/`enforce_org`-regler normalt håndheves. `?service=`-sjekken
passerer (URL-en er internt konsistent), og en A-kode utstedes til en
bruker som aldri har blitt vurdert mot A sine regler.

Løsningen: `/token` er det ENESTE stedet i hele flyten som kan vite sikkert
hvilken tjeneste som skal autorisere brukeren, fordi det er der `svc` slås
opp fra koden selv (`row.ServiceID`), ikke fra en URL-parameter klienten
kontrollerer. `authorizationCodeGrant` kaller derfor `checkPolicy(user, svc)`
— samme funksjon Google-flyten allerede bruker (`google.go`) — rett etter
`GetActiveUserByEmail`, og avviser med `invalid_grant` hvis brukeren mangler
`RequireRole` eller ikke er i `EnforceOrg`-organisasjonen. Dette gjelder
uansett hvor gyldig koden og PKCE-verifiseringen er.

`/login` rydder fortsatt en gjenlevende `oidc_authz`-cookie proaktivt i sin
ikke-OIDC-gren, og `/dispatch` beholder `?service=`-sjekken — begge er
fortsatt fornuftig hygiene og feiler trygt (retur til `/login` er aldri
skadelig), men ingen av dem er nå det som faktisk beskytter mot
tilgangsomgåelse. Det er `checkPolicy` i `/token` som gjør den jobben.

### Innløsning (`POST /token`, `grant_type=authorization_code`)

`/token` dispatcher nå på `grant_type` (tidligere behandlet enhver
forespørsel som refresh). For `authorization_code`:

1. `code_verifier` sin lengde valideres (43-128 tegn, RFC 7636 §4.1) før den
   i det hele tatt brukes til noe
2. Koden slås opp på hash. Manglende `code` gir `invalid_request`, ukjent tjeneste `invalid_client`, ukjent kode generisk `invalid_grant` (audit `authorization_code_invalid`)
3. En kode som allerede er brukt, er gjenbruk (sjekkes før utløp og mismatch). Matcher klient, `redirect_uri` og
   PKCE, revokeres refresh-familien koden ga opphav til (`authorization_code_reuse`,
   OAuth BCP). Matcher de ikke, revokeres ingenting (`authorization_code_reuse` med `reason=unverified`),
   så en lekket kode alene ikke kan logge ut brukeren. Utløpt kode gir `authorization_code_invalid`
4. `client_id` og `redirect_uri` fra requesten må matche eksakt det koden
   ble utstedt for (RFC 6749 §4.1.3), og `code_verifier` hashes
   (SHA-256 → base64url) og sammenlignes mot lagret `code_challenge`. Kun
   `S256` støttes, `plain` tilbys bevisst ikke. Alltid håndhevet, ikke
   betinget av noe tjenesteflagg. Avvik gir `invalid_grant` og audit
   `authorization_code_mismatch` med `reason=client|redirect_uri|pkce`, og
   koden røres ikke: en angriper som bare gjetter, kan ikke brenne offerets kode
5. `checkPolicy(user, svc)` — samme funksjon Google-flyten bruker — kjøres
   på nytt mot tjenesten koden faktisk tilhører (`row.ServiceID`, ikke noen
   URL-parameter). Dette er den reelle beskyttelsen mot tilgangsomgåelse,
   se forklaringen over
6. Konsum og første refresh-rad skjer i én transaksjon (`ConsumeAuthorizationCodeChecked`, med alle predikater i `WHERE`). Koden får `family_id` fra den nye familien. Ved parallelle forsøk vinner høyst ett, og taperen klassifiseres som gjenbruk. Øvrige kodefeil gir `400 invalid_grant`, interne feil `500 server_error`
7. Ved suksess utstedes access- og refresh-token, med access-tokenet utstedt
   via `Issuer.IssueAccessForAudience` — `aud` = ressursen klienten ba om
   (se Resource indicators under), ellers client_id, i motsetning til det
   vanlige access-tokenet fra `IssueAccess` (utstedt til tjenester vi selv
   kontrollerer, uten `aud`). Riktig for et token som nå kan havne hos en
   ressursserver på en ekstern parts side. Tokenet bærer også `scope` fra
   koden og merkes `typ: at+jwt` i JWT-headeren (RFC 9068 §2.1), slik at en
   ressursserver kan avvise et `id_token` som forsøkes brukt som adgangstoken
8. `id_token` (`Issuer.IssueIDToken`, `aud`=client_id, `nonce` speilet fra
   requesten) utstedes KUN hvis scope inneholder `openid` (OIDC Core
   §3.1.3.3) — en ren OAuth2-klient som aldri ba om `openid` skal ikke få et
   identitetstoken den ikke forventer

### Resource indicators (RFC 8707)

En klient kan oppgi `resource=<absolutt URI>` på `/login` for å si hvilken
ressursserver access-tokenet skal brukes mot. Verdien lagres på
autorisasjonskoden (`authorization_codes.resource`) og settes som `aud` på
access-tokenet i stedet for client_id. `id_token` beholder alltid
`aud`=client_id — de to tokenene har ulike mottakere, og OIDC Core §2 er
tydelig på at identitetstokenet tilhører klienten.

Hvorfor det er verdt en egen parameter: uten den må en ressursserver godta et
token med `aud`=<klienten selv>, altså uten noe bevis på at tokenet var ment
for nettopp den. Da kan et token klienten fikk for tjeneste A spilles av mot
tjeneste B, og `aud`-sjekken blir en formalitet.

Reglene:

- Ugyldig verdi (relativ URI, eller fragment — RFC 8707 §2) gir
  `?error=invalid_target` på klientens redirect_uri. En URN er gyldig.
- Flere `resource`-parametre avvises med samme feil. kauth utsteder ett token
  med én `aud`; å godta to og droppe den ene i stillhet ville gitt klienten et
  token den tror dekker mer enn det gjør.
- Sender klienten `resource` også til `/token`, må den være identisk med
  kodens (RFC 8707 §2.2), ellers `invalid_target`. Det er alltid KODENS verdi
  som styrer `aud` — ellers kunne den som fanget opp en kode selv valgt
  hvilken ressursserver tokenet skulle gjelde for.
- Ingen `resource` gir uendret oppførsel: `aud`=client_id.

`scope` returneres også i `/token`-svaret (RFC 6749 §5.1) når det er satt, så
en klient kan lese hva den fikk uten å dekode access-tokenet.

`resource` og `scope` bæres i den usignerte `oidc_authz`-cookien og
revalideres i `/dispatch` der koden utstedes, slik client_id og redirect_uri
gjør — en håndlaget cookie kan derfor ikke plassere en vilkårlig streng i
`aud`.

**Kjent begrensning, verdt å kjenne før man stoler på `scope`:** kauth har
ingen samtykkesteg og ingen per-klient liste over tillatte scopes, så en
klient får det scopet den ber om. `scope` er dermed et uttrykk for hva
klienten ba om, ikke en beslutning kauth har tatt — nyttig som
minste-privilegium-markør og for logging, men ikke et bevis på at noen har
godkjent nettopp den tilgangen. Det tokenet faktisk beviser, er at *denne*
brukeren autentiserte seg og at koden ble utstedt til *denne* klienten; en
klient kan ikke skaffe seg et token for en annen bruker. En ressursserver som
vil ha samtykke som premiss må kreve det selv, eller kauth må få en
per-klient scope-allowlist først.

### sub er opak og uforanderlig

`sub` er brukerens `users.subject_id` — 16 tilfeldige byte som hex, satt av
`CreateUser` (migrasjon 010 backfyller eksisterende brukere). E-postadressen
ligger fortsatt i sin egen `email`-claim.

Tidligere var `sub` selve e-postadressen. OIDC Core §2 krever at `sub` er
lokalt unik og aldri gjenbrukt, og e-post er ingen av de to: en konsument som
knytter egne rader til `sub` mister koblingen når noen bytter adresse, og en
gjenbrukt adresse arver forrige eiers historikk. En bruker uten `subject_id`
(rad satt inn utenom `CreateUser`) faller tilbake til e-post, altså samme
oppførsel som før migrasjonen.

**Ressursserveres eget ansvar:** kauth setter nå `aud` på tokens utstedt via
denne flyten, men om en intern ressursserver (minliste, bildegalleri,
spekto, ...) faktisk validerer `aud` er opp til den serveren selv. Sjekk
dette før en tjeneste faktisk åpnes for en ekstern OIDC-klient — hvis
ressursserveren kun validerer signaturen, kan et token utstedt til
partneren i prinsippet brukes mot den også.

### Cleanup

Utløpte autorisasjonskoder ryddes av samme bakgrunnsjobb-mønster som magic
tokens og refresh tokens — se [Bakgrunnsjobber](#bakgrunnsjobber).

## Multi-tenant arkitektur

### Tjeneste-resolver

`internal/service.Registry` cacher alle aktive tjenester i minnet og resolver request → tjeneste via fire-nivå prioritet:

1. **Eksakt redirect_uri-host == service.domain** — vinner over auth_host. Wire/sub-tjenester deler auth-host med foreldretjenesten men har eget domain.
2. **Host-header == service.auth_host** — for tjenester med dedikert auth-hostname (auth.spekto.live, auth.lilleklo.work)
3. **Eksplisitt service-ID** via `?service=`-query
4. **Suffix-match redirect_uri mot service.domain** — for sub-domener uten egen service-rad

Cache invalideres ved Create/Update i admin-panelet.

### Per-tjeneste branding

- `display_name`, `tagline`, `accent_color`, `theme` (light/dark)
- `logo_html` — rå SVG/HTML, embeddes via `template.HTML` cast
- `bg_image` — sti relativ til `/static/`, rendres som `url('/static/<sti>') center/cover no-repeat fixed`
- `bg_css` — alternativ ren CSS-bakgrunn

### Per-tjeneste OAuth-klienter

`google_client_id`/`google_client_secret`/`microsoft_client_id`/`microsoft_client_secret` overstyrer globale miljøvariabler. Lar ulike tjenester ha separate Google Cloud-prosjekter med presise redirect-URI-whitelists.

### Per-tjeneste auth-flagg

`auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`, `auto_register`, `enforce_org`, `is_default`, `active`. Login-templaten viser kun knapper for aktive metoder.

### Default-org og krav-rolle

- `default_org` — CSV-streng som blir `users.orgs` for auto-registrerte brukere
- `default_role` — tilsvarende for `users.roles`
- `require_role` — tjenesten krever at brukeren har denne rollen i `roles` for å logge inn
- `enforce_org` — krever at brukeren har `default_org` i `orgs`

Håndheves av `checkPolicy` (`internal/auth/google.go`), kalt fra alle fire
login-veiene (Google, Microsoft, magic-link, passord) samt fra
`authorization_code`-grant i `/token`. Matcher CSV-feltet nøyaktig per felt
(splittet på komma, ikke substring) — `require_role="admin"` godtar ikke en
bruker med kun `sysadmin` i `roles`
([issues/2](https://github.com/zral/kauth-go/issues/2)). Magic-link og
passord kalte den ikke i det hele tatt før dette ble rettet
([issues/3](https://github.com/zral/kauth-go/issues/3)) — funnet i
kodegjennomgangen av PR #1, siden `require_role`/`enforce_org` inntil da kun
var reelt håndhevet for Google/Microsoft-innlogging.

## Admin-panel

Beskyttede ruter under `/admin/*` med separat `admin_token`-cookie (egen JWT med `token_use=admin`). Krever rollen `konge` i `users.roles`. Middlewaren verifiserer JWT-en og slår deretter opp brukeren i databasen på hver request. Ukjent eller deaktivert bruker, manglende `konge` i DB-rollene og DB-feil gir avvisning (`303 /admin/login` eller `401`), aldri tilgang. En deaktivert admin mister dermed tilgangen umiddelbart, ikke først når JWT-en utløper. Alle ikke-sikre metoder under `/admin` krever samme origin.

Skrivehandlingene (`user_created`, `user_edited`, `user_deactivated`, `service_created`, `service_edited`) auditeres synkront etter at endringen er lagret, med `actor=<admin-e-post>` i `details`. Feiler audit-skrivingen, står endringen, og redirecten får `?warn=audit` slik at listen viser «Lagret, men ikke auditert». Skjemafelt leses bare fra POST-body (`PostFormValue`), aldri fra query.

### Innlogging

- `GET /admin/login` — viking-door bakgrunn, primær Google-knapp + sekundær e-postlenke
- `GET /admin/google-init` — starter vanlig Google-flyt mot samme `/callback` (samme URL som er hvitlistet hos Google), men med admin-formål i den HMAC-signerte state-parameteren. Formålet hentes aldri fra query, cookie eller `redirect_uri`, og flyten går ikke innom `/dispatch`
- `GET /admin/google-callback` — utgått inngang som ikke setter cookie og bare redirecter til `/admin/login`. Admin-sesjonen settes i OIDC-callbacken (`/callback`) når signert state har admin-formål: aktiv bruker, eksakt rolle `konge` og e-post bekreftet av Google
- `POST /admin/login` — magic-link-flyt for admin (samme origin kreves, anti-enumeration, 200ms floor, samme kvote som tjenestene: 3 per 15 min, formål `admin`)
- `GET /admin/verify?token=<X>` — viser bekreftelsesside (norsk, ingen e-post, ingen JavaScript). Endrer ikke tokenet
- `POST /admin/verify` — samme origin kreves. Konsumerer magic-token, sjekker konge-rolle og setter `admin_token`

### Brukeradministrasjon

- `GET /admin/users` — pagineret liste med søk på e-post og org-filter
- `GET /admin/users/new` + `POST /admin/users` — opprett bruker (valgfritt bcrypt-passord eller `n/a`)
- `GET /admin/users/{id}/edit` + `POST /admin/users/{id}` — rediger navn, roller, organisasjoner
- `POST /admin/users/{id}/deactivate` — settes `deactivated_at = now()`
- `GET /admin/users/export` — CSV-eksport (formula-injection-beskyttet)

### Audit-logg

- `GET /admin/audit` — paginert visning, filter på e-post og service-ID
- `GET /admin/audit/export` — CSV-eksport

### Tjenestehåndtering

- `GET /admin/services` — liste alle tjenester
- `GET /admin/services/new` + `POST /admin/services` — opprett ny
- `GET /admin/services/{id}/edit` + `POST /admin/services/{id}` — full redigering inkludert fil-upload for bakgrunnsbilde
- Cache-invalidering trigger automatisk etter mutasjon

### Bakgrunnsbilde-upload

Multipart-form med fil-validering: kun jpg/jpeg/webp/png, ≤1 MB. Filnavn genereres som `<service-id>-bg-<8 hex>.<ext>` for å unngå kollisjoner. Lagres i `static/`-katalogen og `bg_image`-feltet settes automatisk.

## Sikkerhetsmekanismer

### HMAC-signert OIDC-state

State som sendes til OIDC-providere inneholder serviceID, 128-bit nonce, utstedelsestid og eventuelt admin-formål, signert med HMAC-SHA256. Nonce er bundet til `id_token.nonce` i både Google- og Microsoft-flyten. State er gyldig i 10 minutter (+60 s klokkeskjevhet); eldre eller fremtidig state avvises. Sammenligningen ved callback bruker `hmac.Equal` (konstant-tid mot timing-angrep).

### Generiske innloggingsfeil

Feil i OIDC-flyten redirecter til `/login?error=<kode>` med en lukket mengde koder: `login_failed` (tekniske feil) og `access_denied` (ingen konto eller policybrudd, ikke til å skille utenfra). Ukjente `?error=`-verdier vises som generisk tekst i malen, aldri som gitt. Admin sendes til `/admin/login?err=ingen_tilgang`. Årsaken går til audit og logg, og flyten starter aldri leverandøren på nytt automatisk.

### Cookie-hygiene

Alle cookies har `HttpOnly: true` og `Secure: true` i prod (over Cloudflare HTTPS). `KAUTH_INSECURE_COOKIES=true` slår av Secure for lokal HTTP-utvikling. SameSite settes per kontekst:
- `auth_token` (per-service navn): `Lax`
- `refresh_token`: `None` (cross-origin SPA-støtte for `POST /token`)
- `admin_token`: `Lax`, path `/admin`
- `oidc_state` / `redirect_uri`: `Lax`

### Anti-enumeration

`POST /magic-login` og `POST /admin/login` returnerer alltid samme respons uavhengig av om e-postadressen finnes, om kvoten er brukt opp, om tjenesten har magic link av og om lagringen feilet — samme melding, samme status (200), og minst 200 ms responstid (defer-sleep om saksflyten gikk for raskt). E-post sendes asynkront, så sendetiden ikke avslører noe.

### Rate-limiting

Magic-link: 3 bestillinger per normalisert e-post og formål per 15-minutters vindu, telt i databasen (`magic_tokens`) og derfor uavhengig av restart. Det finnes ingen limit per IP ennå (BACKLOG).

### Samme origin (Sec-Fetch)

`internal/fetchmeta` avgjør om en skrivende request kommer fra kauth selv. `Sec-Fetch-Site: same-origin` godtas. Mangler headeren, må `Origin` være lik egen origin (`https://` + `Host`, `http://` bare med `KAUTH_INSECURE_COOKIES=true`). `same-site`, `cross-site`, `none`, `Origin: null` og fravær av begge gir avvisning (fail-closed). Brukes på `POST /magic-login/{token}`, `POST /admin/verify` og som middleware på alle ikke-sikre metoder under `/admin`. Avvisning gir `403`, ingen databaseskriving og ingen audit. Loggen har rutemønster og header-verdier, aldri token.

### Logout og Sec-Fetch

`/logout` er fortsatt GET, fordi klientapper navigerer dit fra egen vert. Revokering og sletting av cookies skjer bare etter denne tabellen:

| `Sec-Fetch-Site` | `Sec-Fetch-Mode` / `-Dest` | Utfall |
|---|---|---|
| mangler (eldre klient, curl) | – | Revokerer |
| `same-origin`, `same-site`, `none` | uansett | Revokerer |
| `cross-site` | `navigate` og `Dest` er `document` eller mangler | Revokerer |
| `cross-site` | alt annet (`img`/`no-cors`, `cors`, `navigate` med `iframe`) | Ingen revokering og ingen endring av cookies. Samme redirect som før |

En skjult `<img>` eller `<iframe>` på en cross-site side kan altså ikke logge brukeren ut stille. Same-site-forespørsler kan fortsatt, og synlig toppnivå-navigasjon fra en annen side revokerer. Restrisiko: `same-site` revokerer, så en kompromittert søster-app kan logge ut stille.

### E-postnormalisering

E-post normaliseres (`NormalizeEmail`: trim + små bokstaver) ved bestilling av magic link og i Google- og Microsoft-flyten, og nye brukere lagres normalisert. Oppslag på brukere sammenligner `lower(trim(email))` på begge sider, og en unik indeks (`idx_users_email_norm`) hindrer duplikater som bare skiller seg i store/små bokstaver. Kolliderer en auto-registrering med en eksisterende (f.eks. deaktivert) bruker, avvises innloggingen med `reason=user_conflict`, uten ny rad.

**Merknad:** Go `ToLower` bretter Unicode, mens SQLite `lower()` bare bretter ASCII. En eldre rad med ikke-ASCII store bokstaver (f.eks. `Ø@x.no`) finnes derfor ikke ved oppslag med `ø@x.no`, og gir en duplikatkonto (ikke kontoovertakelse). Prod har ingen slike rader. Løses med varig identitet (Fase 2).

### Audit-isolering

Vanlig audit (`Log`) går via en begrenset kø (1 024 hendelser) med én skriver-goroutine, adskilt fra auth-flyten. Hvis databasen er treig eller utilgjengelig, fortsetter auth uten å blokkere. Er køen full, droppes hendelsen. Det telles, og `audit: hendelse droppet` logges med kumulativ teller høyst hvert 10. sekund. Skriveren bruker egen kontekst med 5 s timeout per innsetting.

Admin-skrivehandlinger bruker `LogSync` (skriver direkte og returnerer feilen). `/token` og refresh bruker aldri `LogSync`.

Ved shutdown venter kauth på pågående e-postsendinger (5 s), tømmer audit-køen (`audit: tømt N hendelser`, 5 s) og lukker så databasen. Hendelser kan fortsatt gå tapt ved full kø, timeout på flush eller hard kill.

### IP-tracking via Cloudflare

`ClientIPMiddleware` ekstraherer klient-IP fra `CF-Connecting-IP` → `X-Forwarded-For` (første element) → `RemoteAddr`. Verdien legges i request-context og logges i audit-events.

### CSV-injection-beskyttelse

`csvEsc` legger til `'`-prefiks på felter som starter med `=`, `+`, `-`, `@`, `\t` eller `\r` for å nøytralisere formel-evaluering i Excel/Sheets. CSV-quoting håndteres av `encoding/csv` selv.

### Constant-time admin-rolle-sjekk

Admin-middleware verifiserer JWT, sjekker `token_use == "admin"` og `groups`-claim for `konge`, og bekrefter så mot databasen at brukeren er aktiv og har `konge` — alle kontroller før requesten slipper inn.

## Cross-host login-flyt

Brukeren går til en app (f.eks. `analyse.klarsyn.net`), blir redirected til auth-domain (`auth.klarsyn.net`). Etter vellykket login MÅ JWT komme tilbake til app-domenet — cookies funker ikke cross-host. Flyt:

1. App: `→ https://auth.<svc>/login?redirect_uri=<app-callback>`
2. Login-siden setter `redirect_uri`-cookie via JS og redirecter til valgt auth-provider
3. Provider-callback (`/callback`, `/ms-callback`, `/magic-login/{token}`, eller `POST /do-login`) utsteder JWT + refresh-token
4. Callback redirecter til `GET /dispatch?token=<jwt>&rt=<refresh>&service=<id>` (URL-param, ikke cookie)
5. Dispatcher leser tokenet, verifiserer signaturen og finner riktig tjeneste (se routing-nivåene under)
6. Redirect til app-callback med `?token=<jwt>#rt=<refresh>` — JWT som query-param, refresh-token som URL-fragment (fragmentet sendes ikke til serveren, og ikke til Referer)
7. App leser `?token=` fra URL, validerer mot JWKS

Refresh-token-cookien settes parallelt på auth-domenet med `SameSite=None` slik at `POST /token` fungerer cross-origin.

### Dispatcher-routing

`/dispatch` avgjør hvor brukeren skal lande, og prøver kildene i tur — mest presise først. Første treff vinner:

| Nivå | Kilde | Brukes av |
|------|-------|-----------|
| 1 | `redirect_uri`-cookie, sjekket mot tjenestenes allowlist | Apper som sender `?redirect_uri=` inn til `/login` |
| 2 | `?service=<id>` — service-IDen login-flyten allerede har verifisert | Alle fire login-veiene |
| 3 | Host-header mot `services.auth_host` | Tjenester med eget auth-domene |
| 4 | `org`-claim mot `services.default_org` | Bakoverkompatibilitet |
| 5 | Default-tjenestens `callback_url` | Siste utvei |

Nivå 2 er den pålitelige: for Google og Microsoft kommer IDen fra den HMAC-signerte state-parameteren (`SignState`/`VerifyState`), som round-trippes gjennom provideren og ikke kan forfalskes. Magic-link og passord sender den resolvet tjenesten direkte.

IDen valideres alltid mot registryet, og redirect går kun til `callback_url` slik den står i databasen — aldri til en URL fra requesten. En ukjent eller påfunnet `?service=` kan derfor ikke styre hvor brukeren havner; den faller bare gjennom til neste nivå.

Nivå 4 er en heuristikk og bør ikke stoles på: den itererer over tjenestene i `display_name`-rekkefølge og tar den første med en `default_org` brukeren har. En bruker som ikke har tjenestens `default_org` blant sine orgs vil havne feil. Den står igjen kun for forespørsler uten `?service=`, og bør fjernes når ingenting eksternt bruker den (se `CHANGELOG.md`, Unreleased/Fixed).

### Admin Google-flyten og `/dispatch`

Intern-sti-grenen i `/dispatch` er fjernet: på nivå 1 godtas bare en `redirect_uri` som er eksakt lik en registrert `callback_url`. Admin Google-flyten går ikke lenger via `/dispatch`. `/admin/google-init` legger admin-formål i den signerte state-parameteren, og `/callback` setter `admin_token`-cookien direkte (ingen JWT i URL-en) og redirecter til `/admin/users`. Peker nivå 1 til en callback hos en annen tjeneste enn den verifiserte, logges `redirect_service_mismatch` (007 F9).

## Audit-logg

Lagret i `audit_events`-tabellen med felter:
- `event_type` — `login_success`, `login_failed`, `magic_link_login`, `google_oidc_login`, `microsoft_oidc_login`, `google_oidc_rejected`, `microsoft_oidc_rejected`, `admin_login`, `admin_logout`, `admin_google_login`, `refresh_token_issued`, `refresh_token_rotated`, `refresh_token_reuse`, `refresh_token_revoked_presented`, `user_logout`, `user_deactivated`, `service_created`, `service_edited`, ...
- `auth_method` — `google`, `microsoft`, `magic_link`, `password`, `refresh`
- `email`, `service_id`, `ip_address`, `user_agent`
- `success` — bool, alltid eksplisitt satt av applikasjonen
- `details` — fritekst, brukes for grunn på feilet login. `refresh_token_reuse` har `gap_s=<n>`, `user_deactivated` har `id=<n> revoked=<antall>` eller `id=<n> revoke_failed` (deaktiveringen står selv om revokeringen feiler; refresh for deaktivert bruker avvises uansett)
- `created_at` — ISO 8601 UTC

Nye event-typer fra 009: `authorization_code_invalid`, `authorization_code_mismatch`, `authorization_code_reuse`, `authorization_code_exchanged`. Admin-skriv har `actor=<e-post>` i `details`. Skrivingen er asynkron via kø, bortsett fra admin-skriv (se Audit-isolering).

90 dagers retensjon (cleanup-jobb sletter eldre). Eksporteres via admin GUI som CSV.

## Bakgrunnsjobber

Tre goroutiner, alle med 1 times tick, kjører umiddelbart ved oppstart:

- **`cleanMagicTokens`** — sletter brukte magic-tokens som er utløpt, og ubrukte som er eldre enn 24 timer
- **`cleanRefreshTokens`** — sletter refresh-tokens der `expires_at` er passert OG `family_expires_at` enten er null eller passert
- **`cleanAuditEvents`** — sletter audit-events eldre enn 90 dager

Alle stopper rent på `ctx.Done()` ved SIGTERM/SIGINT.

## Endepunkter

### Offentlige

`/login` og `/magic-login` støtter begge `?lang=<nb|en|de>` for å velge visningsspråk. Parameteren overstyrer `Accept-Language`-headeren; en ukjent verdi faller tilbake til `Accept-Language` i stedet for å tvinge engelsk, og total fallback (ingen match noe sted) er engelsk. Nyttig for en relying party som vet at brukeren foretrekker et gitt språk — f.eks. `?lang=de` på redirect til login.

| Metode | Sti | Beskrivelse |
|---|---|---|
| GET | `/login` | Login-side, valgfri `?service=<id>`, `?redirect_uri=<url>` og `?lang=<nb\|en\|de>` — fungerer også som `authorization_endpoint` for standard OIDC (`?response_type=code&client_id=...&code_challenge=...`) |
| GET | `/login.html`, `/login-pov.html` | Legacy 301 → `/login` |
| GET | `/oidc-login`, `/social-login` | Initier Google OAuth |
| GET | `/callback` | Google OAuth callback |
| GET | `/ms-oidc-login`, `/ms-social-login` | Initier Microsoft OAuth |
| GET | `/ms-callback` | Microsoft OAuth callback |
| GET | `/magic-login` | Magic-link-skjema, valgfri `?service=<id>` og `?lang=<nb\|en\|de>` |
| POST | `/magic-login` | Send magic-link |
| GET | `/magic-login/{token}` | Bekreftelsesside (endrer ingenting) |
| POST | `/magic-login/{token}` | Konsumer magic-token (samme origin kreves) |
| POST | `/do-login` | Passord-login (hvis aktivert) |
| POST | `/token` | `grant_type=refresh_token` eller `grant_type=authorization_code` (+ PKCE) — CORS-aktivert |
| GET | `/dispatch` | Post-login dispatcher |
| GET | `/logout` | Revokerer refresh-familien, sletter cookies, redirect (se tabellen under Sikkerhetsmekanismer) |
| GET | `/api/me` | JWT-introspection (returnerer claims som JSON) |
| GET | `/.well-known/jwks.json` | JWKS — CORS-aktivert |
| GET | `/.well-known/openid-configuration` | Discovery — CORS-aktivert |
| GET | `/static/*` | Statiske filer |

### Admin

| Metode | Sti | Beskyttelse |
|---|---|---|
| GET | `/admin/login` | Åpen |
| POST | `/admin/login` | Åpen — samme origin, anti-enumeration |
| GET | `/admin/verify` | Åpen — bekreftelsesside, krever magic-token |
| POST | `/admin/verify` | Åpen — samme origin, konsumerer magic-token |
| GET | `/admin/logout` | Åpen |
| GET | `/admin/google-init` | Åpen — starter Google-flyt med admin-formål i signert state |
| GET | `/admin/google-callback` | Åpen — utgått, redirecter til `/admin/login` uten å sette cookie |
| GET | `/admin/users[/new/{id}/edit/export]` | konge-rolle |
| POST | `/admin/users[/{id}[/deactivate]]` | konge-rolle, samme origin |
| GET | `/admin/audit[/export]` | konge-rolle |
| GET, POST | `/admin/services[/new/{id}/edit]` | konge-rolle, POST med samme origin |

## Datamodell

Seks SQLite-tabeller med WAL og foreign keys på:

### `services`

Tjeneste-konfigurasjon. 30+ kolonner inkludert id, display_name, domain, auth_host, callback_url, branding (theme, accent_color, logo_html, bg_image, bg_css), auth-flagg (auth_google/microsoft/magic_link/password), OAuth-creds (per-service), TTL-er, default_role/org, is_default, active, updated_at. `id` er også `client_id` for en tjeneste som bruker OIDC `authorization_code`-flyten — ingen egen klient-tabell.

### `users`

Brukerkontoer: id, email (unik på `lower(trim(email))`), password_hash, name, roles (CSV), orgs (CSV), created_at, last_login, deactivated_at.

### `magic_tokens`

Engangs-innloggingstokens: id, token (SHA-256-hex), email (normalisert), service_id (NULL for admin), purpose (`service`/`admin`), redirect_uri, created_at, expires_at, used.

### `refresh_tokens`

Opake refresh-tokens med family-tracking: id, token_hash (sha256 hex, CHECK length=64), email, service_id, family_id, parent_id, created_at, expires_at, family_expires_at, used, revoked, revoked_reason, ip_address, user_agent.

### `audit_events`

Hendelseslogg: id, event_type, auth_method, email, service_id, ip_address, user_agent, success, details, created_at.

### `authorization_codes`

Engangs-autorisasjonskoder for OIDC `authorization_code`-flyten: id, code (SHA-256-hex), family_id (settes ved innløsning), service_id, email, redirect_uri, scope, nonce, code_challenge, code_challenge_method, created_at, expires_at, used.

## Drift og kjøremiljø

- **Single static binær** — ingen CGO, ingen runtime-avhengigheter (modernc.org/sqlite)
- **Cross-compile** — `make build-arm64` for ARM64-linux
- **Graceful shutdown** — `signal.NotifyContext` + `srv.Shutdown(15s)`, så pågående e-postsendinger (5 s), `auditSvc.Close` (5 s) og til slutt `sqlDB.Close()`. Cleanup-goroutiner stopper rent på `ctx.Done()`
- **Minne** — `GOMEMLIMIT=96MiB` + cgroup `MemoryHigh=112M` / `MemoryMax=128M` via systemd
- **Strukturerte logger** — `log/slog`, JSON-format, til journald via systemd
- **WAL-modus** — SQLite med `journal_mode=WAL` og `foreign_keys=ON` ved oppstart
- **Daglig backup** — `scripts/backup-kauth-go.sh` via cron 03:00, `sqlite3 .backup` for atomisk konsistent kopi (trygt mens kauth kjører), 30 dagers retensjon
- **Cloudflare Tunnel** — TLS-terminering og DDoS-beskyttelse, klient-IP via `CF-Connecting-IP`
- **systemd-tjeneste** — kjører som `lars`, `ProtectSystem=strict`, `NoNewPrivileges`, `Restart=on-failure`
