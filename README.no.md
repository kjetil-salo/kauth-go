<div align="center">
    <h1>kauth</h1>
    <p>OIDC-identitetsprovider i Go for små organisasjoner.</p>
    <p><a href="README.md">English</a> · <strong>Norsk</strong></p>
</div>

![Login-side](doc/login-hero.png)

OIDC-identitetsprovider i Go. Tanken er at små organisasjoner skal slippe å sette opp en Keycloak eller Zitadel for å få sentral innlogging på et par tjenester.

En statisk binær på ~14 MB. ~25 MB RAM i drift. SQLite under panseret, RS256-signerte JWT-er, og Cloudflare Tunnel foran for TLS og DDoS-beskyttelse.

Kjører i prod på et knippe tjenester.

## Hva kauth gjør

- Utsteder JWT-er (RS256)
- Roterer refresh-tokens med reuse-deteksjon (RFC OAuth-BCP §4.13)
- Eksponerer JWKS og OpenID Discovery på `/.well-known/`
- Snakker standard OIDC `authorization_code` + PKCE (RFC 6749 §4.1, RFC 7636) for tjenester merket `requires_pkce` — et ekte `id_token` med `aud`/`nonce`, slik at en ekstern klient du ikke kontrollerer koden til kan bruke et vanlig OIDC-bibliotek i stedet for den bespoke token-i-URL-flyten. Se [doc/FEATURES.md](doc/FEATURES.md#oidc-authorization_code--pkce).
- Tilbyr fire innloggingsveier per tjeneste: Google OIDC, Microsoft OIDC, magic-link på e-post, og passord (sistnevnte av som default — se *Det passordløse valget* nedenfor)
- Sentral brukeradministrasjon: ett admin-panel for alle tjenestene
- Auditlogg med 90 dagers retensjon, filtrerbar på alle kolonner og eksporterbar til CSV

Hver tjeneste konfigureres datadrevet i `services`-tabellen. Onboarding er én INSERT.

## Komme i gang lokalt

```bash
git clone git@github.com:zral/kauth-go.git
cd kauth-go
make build           # bygger bin/kauth
```

Minimum konfig via miljøvariabler:

```bash
export KAUTH_DB_PATH=./data/kauth.db
export KAUTH_ISSUER=http://localhost:8080
export KAUTH_BASE_URL=http://localhost:8080
export KAUTH_PRIVATE_KEY_PATH=./secrets/privateKey.pem
export KAUTH_PUBLIC_KEY_PATH=./secrets/publicKey.pem
export KAUTH_OIDC_STATE_SECRET=$(openssl rand -base64 48)
export KAUTH_SMTP_MOCK=true
export KAUTH_INSECURE_COOKIES=true   # bare for lokal HTTP-utvikling

./bin/kauth
```

Generer RSA-nøkler hvis du ikke har dem fra før:

```bash
openssl genpkey -algorithm RSA -out secrets/privateKey.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in secrets/privateKey.pem -out secrets/publicKey.pem
```

Migrasjoner kjører automatisk ved oppstart.

## Onboarde en ny tjeneste

En tjeneste = én rad i `services`-tabellen. Her er en oppdiktet app "polaris" som logger inn med Google:

```sql
INSERT INTO services (
    id, display_name, tagline, domain, callback_url,
    email_from_name, email_from_address,
    auth_google, auth_magic_link, auth_microsoft, auth_password,
    auth_host,
    google_client_id, google_client_secret,
    default_role, default_org, auto_register,
    theme, accent_color, jwt_cookie_name,
    access_token_ttl, refresh_token_max_age,
    active, updated_at
) VALUES (
    'polaris', 'Polaris', 'Navigasjon for små team',
    'polaris.example.com', 'https://polaris.example.com/auth/callback',
    'Polaris', 'noreply@polaris.example.com',
    1, 1, 0, 0,
    'auth.polaris.example.com',
    '812403915077-eksempel-klient-id.apps.googleusercontent.com',
    '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',
    'user', 'polaris', 1,                  -- auto-registrer som user/polaris
    'light', '#2563EB', 'auth_token',
    'PT30M', 'P30D',
    1, datetime('now')
);
```

Felter du nesten alltid setter. Eksempelverdiene er fra Polaris over — en oppdiktet tjeneste med Google som eneste innloggingsvei, men med formater som ligger tett opp til ekte:

| Felt | Eksempel | Forklaring |
|---|---|---|
| `id` | `polaris` | Kort slug uten mellomrom. Brukes i URLer og JWT-claims, så den bør være stabil — å endre den senere bryter eksisterende tokens. |
| `display_name` | `Polaris` | Vises på login-siden og i admin-panelet. |
| `tagline` | `Navigasjon for små team` | Undertekst på login-siden. Kan overstyres per språk i `internal/i18n`; feltet er fallback. |
| `domain` | `polaris.example.com` | App-domenet. Brukes til å rute callbacks tilbake til riktig sted. |
| `callback_url` | `https://polaris.example.com/auth/callback` | Hvor brukeren sendes etter vellykket login. Må eksakt matche app-ens callback-endepunkt. |
| `auth_host` | `auth.polaris.example.com` | Hostnavnet auth-siden serveres på for denne tjenesten. Gir branded URL per tjeneste. Må peke på kauth via Cloudflare Tunnel, og `https://<auth_host>/callback` må være hvitlistet hos Google. |
| `google_client_id` | `812403915077-eksempel-klient-id.apps.googleusercontent.com` | Fra Google Cloud Console. Ekte format er 12-sifret prosjektnummer, bindestrek, 32 tegn, så `.apps.googleusercontent.com`. La stå `NULL` hvis tjenesten skal bruke den globale klienten fra `.env`. |
| `google_client_secret` | `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` | Samme sted, med prefikset `GOCSPX-` og 28 tegn etter. Lagres i klartekst i databasen — filrettighetene på `kauth.db` er beskyttelsen. |
| `auth_google` | `1` | Én kolonne per innloggingsvei: `auth_google`, `auth_microsoft`, `auth_magic_link`, `auth_password`. Bare de som er `1` vises på login-siden. |
| `default_role` | `user` | Hva nye brukere får i `role`-claim. |
| `default_org` | `polaris` | Hva nye brukere får i `org`-claim. App-en bruker dette til tilgangskontroll. |
| `auto_register` | `1` | `1` oppretter nye brukere ved første login. `0` betyr at admin må opprette dem først. |
| `access_token_ttl` | `PT30M` | ISO 8601-varighet. Kort access-TTL og lang refresh holder sikkerhet og UX i balanse. |
| `refresh_token_max_age` | `P30D` | Hvor lenge en refresh-familie kan leve før brukeren må logge inn på nytt. |
| `email_from_address` | `noreply@polaris.example.com` | Avsender for magic-link fra denne tjenesten. `NULL` bruker global SMTP — se *Sette opp magic-link*. |
| `jwt_cookie_name` | `auth_token` | Cookie-navnet tokenet settes i. Ulike navn per tjeneste hindrer kollisjon på delt toppdomene. |
| `theme` / `accent_color` | `light` / `#2563EB` | Utseende på login-siden. |

Når raden er på plass, peker du tjenestens login-flyt mot `https://<auth_host>/login?redirect_uri=https://<din-app>/auth/callback`. Resten ordner kauth.

### CORS-origin for refresh-flyten

SPA-klienter som kaller `POST /token` for refresh (eller leser `/.well-known/*` fra browser) må hvitlistes i `KAUTH_CORS_ORIGINS`. Komma-separert, eksakt origin-match — ikke wildcard-domene:

```bash
KAUTH_CORS_ORIGINS=https://app1.example.com,https://app2.example.com
```

Mangler app-en på listen får browseren `No 'Access-Control-Allow-Origin' header is present` og refresh-runden feiler stille — klienten beholder gammelt refresh-token, neste forsøk trigger reuse-deteksjon og brukeren kastes til login. Symptomet ser ut som "logges ut etter 15 min" men ligger i nettverket, ikke i token-laget.

Endre `.env` og restart kauth når du onboarder en ny SPA.

### Bakgrunnsbilde

Legg bildet i `static/`-katalogen og deploy:

```bash
cp polaris-hero.jpg static/
git add static/polaris-hero.jpg
git commit -m "feat(static): bakgrunnsbilde for polaris"
make deploy
```

Sett deretter `bg_image` på service-raden:

```sql
UPDATE services SET bg_image = '/polaris-hero.jpg' WHERE id = 'polaris';
```

Login-templaten setter automatisk `background: url('/static/polaris-hero.jpg') center/cover no-repeat fixed`. Innholdet i `static/` serves på `/static/`-prefiks. Bilder bør være under 1 MB — webp eller komprimert jpeg gir best vekt-til-kvalitet.

### Cloudflare Tunnel: auth_host må være ett nivå under wildcard-domenet

`auth_host` må peke på et hostnavn Cloudflares wildcard-sertifikat faktisk dekker. Et Universal SSL-sertifikat for `eksempel.work` dekker `*.eksempel.work` — **ett** nivå, ikke to. `auth.polaris.eksempel.work` feiler derfor med `SSL routines::ssl/tls alert handshake failure`, mens `auth-polaris.eksempel.work` fungerer. Samme grunn til at dette repoet har `auth-dev.spekto.live` og ikke `auth.dev.spekto.live` for `spekto-dev`.

Sjekkliste for en ny `auth_host` bak samme tunnel som resten av flåten:

1. `cloudflared tunnel route dns --overwrite-dns <tunnel-id> <auth_host>`
2. Legg til en ingress-rad i `/etc/cloudflared/config.yml` som peker `<auth_host>` mot `http://localhost:<KAUTH_HTTP_PORT>` — samme port som de andre auth-hostene.
3. `cloudflared --config /etc/cloudflared/config.yml tunnel ingress validate` før restart.
4. `systemctl restart kauth` (henter ny service-rad inn i registry-cachen) og `systemctl restart cloudflared` (deler tunnel med alle andre tjenester — kort avbrudd for alle, ikke bare den nye).

### Beskytte en side uten egen backend

En ren statisk side (ingen server-side kode) kan ikke selv gjennomføre en OIDC-flyt — den har ingen plass å ta imot `?token=...` på og ingen måte å sette en cookie fra. Løsningen er en tynn auth-gate foran `http.FileServer`, ikke å bygge OIDC inn i kauth for statiske filer:

- Requester uten gyldig cookie → 302 til `https://<auth_host>/login?redirect_uri=<callback_url>`.
- `callback_url` er et endepunkt på selve gate-prosessen (f.eks. `/auth/callback`), som leser `?token=...`, verifiserer det mot kauths JWKS, og setter cookien selv før den slipper videre til filserveren.
- **kauth signerer i praksis uten `kid` i selve JWT-headeren** — kun JWKS-oppslaget publiserer en fast `kid` (`kauth-1`). En gate som insisterer på eksakt `kid`-match mot tokenets header vil derfor avvise ellers gyldige tokens. Prøv i stedet alle nøklene JWKS returnerer når `kid` mangler eller ikke finnes i cachen.
- Refresh-token (`rt`) sendes tilbake fra `/dispatch` som URL-**fragment** (`#rt=...`), ikke query-param — det når aldri en server. En gate uten JS-lag kan ikke fange det opp, og bør derfor la være å prøve. Sett heller `access_token_ttl` på tjenesten til noe lengre enn kauths default (f.eks. `PT12H`) og la brukeren logge inn på nytt sjeldnere, i stedet for å bygge refresh-rotasjon i gaten.

Referanseimplementasjon: `authgate/` i univers-repoet (samme maskin) — ren Go, ingen eksterne avhengigheter, ~300 linjer.

Siden access-tokens er statsløse, kan verken kauth eller en slik gate stoppe et allerede utstedt, ikke-utløpt token — deaktivering av en bruker i kauth virker først ved neste innlogging/refresh. Skal én bestemt bruker kunne tvinges ut umiddelbart uten å røre andre tjenester bak samme kauth-instans, må det løses lokalt i gaten (se "Tving ut en bruker" i `authgate/README.md`) — en liten fil med e-post → tidsstempel, sjekket mot tokenets `iat` på hver request.

## Sette opp Google OIDC

Per tjeneste, eller globalt for alle. Per tjeneste anbefales hvis tjenestene tilhører ulike domener — Google krever at redirect-URI-en er hvitlistet på OAuth-klienten.

1. I [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials → Create OAuth Client ID → Web application.
2. Authorized redirect URI: `https://<auth_host>/callback` for hver auth-host tjenesten din skal støtte.
3. Sett `google_client_id` og `google_client_secret` på service-raden — eller `KAUTH_GOOGLE_CLIENT_ID` / `KAUTH_GOOGLE_CLIENT_SECRET` globalt hvis alle tjenestene deler én klient.
4. Sett `auth_google = 1` på tjenesten.

## Sette opp Microsoft OIDC

Samme oppskrift, men i [Microsoft Entra Admin Center](https://entra.microsoft.com/) → App registrations → New registration.

1. Account types: Accounts in any organizational directory and personal Microsoft accounts (gir bredeste dekning via `/common`-endepunktet).
2. Redirect URI (Web): `https://<auth_host>/ms-callback`.
3. Certificates & secrets → New client secret.
4. Lagre `MicrosoftClientID` og `MicrosoftClientSecret` på service-raden eller globalt.
5. Sett `auth_microsoft = 1`.

Microsoft-flyten bruker `/common`-endepunktet og verifiserer ID-tokenet med `SkipIssuerCheck`, siden personlige kontoer og bedriftskontoer har ulike `iss`-claims. Signaturverifikasjon er fortsatt streng.

### Finne app-registreringen igjen i Entra

Skal en ny tjeneste dele Microsoft-klient med en eksisterende (samme `microsoft_client_id` globalt), må du finne *App registration*-objektet i riktig tenant — ikke *Enterprise application*-objektet, som ser nesten likt ut men mangler redirect-URI-er. Tre fellefaktorer i praksis:

- **Feil tenant**: kontoen din kan ha tilgang til flere Entra-directories. "Default Directory" med 0 apper er nesten aldri riktig sted. Bruk katalogbytteren øverst til høyre, eller prøv den klassiske Azure-portalen (`portal.azure.com`) om entra.microsoft.com ikke lister nok kataloger.
- **Enterprise Application ≠ App registration**: søker du opp appen fra Enterprise Applications-lista, havner du på en side uten Authentication-blad i det hele tatt. Gå til **Identity → Applications → App registrations** i stedet, og søk på Application (client) ID.
- **Authentication-siden viser bare én plattform om gangen**: Overview-siden for app-registreringen har en lenke som teller opp redirect-URI-er (f.eks. "1 web") — klikk direkte på det tallet for å hoppe til riktig plattformseksjon, i stedet for å lete gjennom Authentication-fanen manuelt.

## Sette opp magic-link (e-postinnlogging)

Hvilken som helst SMTP-server går. Vi bruker [Resend](https://resend.com) i prod.

```bash
export KAUTH_SMTP_HOST=smtp.resend.com
export KAUTH_SMTP_PORT=587
export KAUTH_SMTP_USER=resend
export KAUTH_SMTP_PASSWORD=re_xxxxxxxxx
export KAUTH_SMTP_FROM=noreply@yourdomain.com
export KAUTH_SMTP_STARTTLS=true
```

Sett `auth_magic_link = 1` på tjenesten. Brukeren får en lenke med 15 minutters levetid, engangsbruk, atomisk konsumert i databasen. Tre forsøk per e-postadresse per 15 minutter — alt over blir stille slipt vekk (anti-enumeration: alle responser ser like ut).

### Egen avsenderadresse per tjeneste

Som default sendes alt fra `KAUTH_SMTP_FROM` over rå SMTP, uansett hvilken tjeneste brukeren logger inn på. Vil du at Polaris-brukere skal få e-post fra `noreply@polaris.example.com`, setter du `email_from_address` på service-raden. Da går sendingen via [Brevo](https://brevo.com) sitt transaksjons-API i stedet:

```bash
export KAUTH_BREVO_API_KEY=xkeysib-xxxxxxxx
```

Domenet må være verifisert hos Brevo først — ellers avvises sendingen. Feltet er nullable nettopp fordi det bare skal settes for domener som faktisk er verifisert; `NULL` betyr uendret oppførsel via global SMTP.

## Det passordløse valget

> Passord er — eh — upassende.

kauth støtter passord — feltet finnes, koden er der — men det er av som default, og vi anbefaler å la det stå sånn.

Argumentet er ikke at passord er teknisk umulig, eller at magic-link er sterkere kryptografi enn et godt passord. Magic-link og "send reset-link" har samme grunnleggende risikomodell: hvis e-postkontoen kompromitteres, er begge tapt. Phishing fungerer like godt mot begge.

Forskjellen er hvor mange uavhengige credentials vi forvalter per bruker. Passord pluss e-post-recovery er to credentials, to lekkasje-veier, to phishing-scenarier. Bare e-post er én credential — samme angrepsflate, men uten passord-laget på toppen. Vi slipper alt det laget bærer med seg: gjenbruk på tvers av tjenester, dårlige hash-algoritmer hos andre, lekkede passordbaser som rammer oss om e-posten matcher, reset-flyter som glipper.

Og det er et skalerings-poeng her. Jo flere tjenester en bruker må holde styr på, jo mer sannsynlig er det at samme passord brukes på alle. Hvor godt vi hasher betyr mindre når brukeren har samme passord på en tjeneste som lagrer i klartekst. Hver gang vi krever et nytt passord, bidrar vi marginalt til det problemet. Den belastningen ønsker vi ikke å legge på brukerne våre.

Når all autentisering går via Google, Microsoft eller en engangslenke på e-post, slipper vi unna det som er vanskeligst å gjøre selv. Identitetsleverandørene har et sikkerhetsbudsjett vi aldri kan matche — FIDO2, anomali-deteksjon, device-binding, phishing-resistans, alt sammen vedlikeholdt uten at vi løfter en finger.

Friksjonen blir lavere også. Magic-link tar et titalls sekunder, Google-knappen er to klikk. Ingen glemte passord, ingen utløpsmeldinger om at passordet må byttes innen fjorten dager.

Det er også en posisjon vi liker å innta. Å droppe passord helt sier noe om hva vi mener autentisering bør være i 2026, både til brukerne og til oss selv. Det er enklere å holde linjen når den er trukket.

Det er fortsatt noen edge cases. En engangsbruker uten Google som ikke vil oppgi e-post er én. De løses som enkelttilfeller, ikke i arkitekturen.

## Auditloggen

Alle innlogginger, refresh-runder og admin-operasjoner havner i `audit_events`. Panelet ligger på `/admin/audit`.

Filteret dekker alle kolonnene i tabellen. Tidspunkt tar fra- og til-dato. E-post, IP og detaljer er substring-søk med en operator ved siden av, så du kan like gjerne be om *alt unntatt* en verdi — nyttig for å luke ut egen aktivitet. Hendelse, metode, tjeneste og OK er avkryssingsbokser, og valgene hentes fra dataene, så nye hendelsestyper dukker opp av seg selv uten kodeendring. Rader som mangler metode eller tjeneste har sin egen `(ingen)`-boks; uten den ville «huk av alt» skjult dem.

Filtrene kombineres fritt og bæres med i URL-en, så et filter kan bokmerkes eller deles. «Eksporter CSV» tar med nøyaktig det du ser.

Oppryddingsjobben sletter hendelser eldre enn 90 dager.

## Drift

Deploy: `make deploy` cross-compiler til arm64, scp-er binæren til target-hosten og restarter systemd-tjenesten. Target settes via `KAUTH_DEPLOY_HOST`-variabelen.

`kauth.service` kjører som vanlig bruker, med WAL-aktivert SQLite, graceful SIGTERM, og restart on-failure. Minne taes hånd om via GOMEMLIMIT og cgroup-tak satt i unit-filen.

Backup-en ligger i `scripts/backup-kauth-go.sh` — daglig kopi via cron klokken 03:00, bruker `sqlite3 .backup` som er trygt mens kauth kjører. 30 dagers retensjon.

Logger går til journald via `log/slog` i strukturert format. Cleanup-jobber (magic-tokens, refresh-tokens, audit-events) kjører hver time som bakgrunns-goroutiner.

Cloudflare Tunnel foran: kauth lytter på localhost, tunnelen terminerer TLS og setter klient-IP i `CF-Connecting-IP`-header. Null hull i brannmuren utover det.

## Arkitektur i grove trekk

- `cmd/kauth` — entry point. Konfig, DB-oppstart, router-wiring, graceful shutdown.
- `internal/auth` — innloggings-handlere (Google, Microsoft, magic-link, password), dispatch, login-side, middleware.
- `internal/token` — JWT-utstedelse, JWKS, refresh-rotasjon.
- `internal/admin` — admin-panel: brukeradministrasjon, audit-logg, service-konfig, magic-link- og Google-innlogging for admin.
- `internal/service` — tjeneste-resolver med cache. Bestemmer hvilken tjeneste en innkommende request tilhører basert på redirect-URI eller auth-host.
- `internal/i18n` — språkkatalog og -deteksjon (`nb`/`en`/`de`, fallback engelsk) for login-sidene og magic-link-e-posten.
- `internal/db` — sqlc-generert databaselag mot SQLite (modernc.org/sqlite, CGO-fri).
- `internal/jobs` — bakgrunnsjobber.

Mer detaljert funksjonsoversikt ligger i [doc/FEATURES.md](doc/FEATURES.md).

## Tribute

Denne porten bygger på [Kjetil Salo](https://github.com/kjetil-salo) sin originale kauth i Quarkus. JWT-utstederen, magic-link-flyten, Microsoft OIDC, første versjon av admin-panelet og H2-støtten er hans arbeid. Det datadrevne service-config-konseptet og refresh-token-rotasjonen med family-revocation kom til underveis.

Det viktigste han bidro med var likevel premisset og drivkraften — at vi skulle ha noe enkelt og sikkert som ikke var en Keycloak eller Zitadel-dinosaur. Hele eksistensen til kauth henger på den ideen, og at Kjetil tok initiativet til å bygge det. Go-versjonen er en port, ikke en ny idé.

## Lisens

[MIT](LICENSE). Bruk som du vil. Hvis du gjør noe lurt eller fanger en bug, send en PR.
