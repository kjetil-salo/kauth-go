# Architecture Design Notes — kauth-go

Sentral beslutningslogg for arkitektur- og designvalg i kauth-go. Hver ADN er en kort, datert oppføring som forklarer *hvorfor*, ikke bare *hva*.

**Nummerering:** ADN 1–6 og feature 001–006 ble ført i Quarkus-versjonen (`quarkus-simple-auth/doc/ARCHITECTURE_DESIGN_NOTES.md`). Beslutningene der gjelder fortsatt for kauth-go, som er en port av samme tjeneste. Nummereringen fortsetter derfor fra ADN 7 og feature 007.

| ADN | Tema (Quarkus-loggen) |
|---|---|
| 1 | `org`-claim som JSON-array i JWT |
| 2 | Refresh token med rotasjon og family-revokering |
| 3 | Per-tjeneste access-token TTL |
| 4 | Datadrevet refresh-token familygrense |
| 5 | `aud`-claim i JWT + `service_id` på refresh tokens |
| 6 | Per-tjeneste OAuth-klient for branding på consent-skjerm |

> ADN 5 sier at access-tokens skal ha `aud` og at refresh-tokens bindes til `service_id`. Kauth-go setter i dag `aud` bare i code-flyten, og refresh-grant bruker ikke det lagrede `service_id` (ROADMAP H2, H5). Porten har altså gått bort fra ADN 5. Fase 0–1 retter det.

---

## ADN 7 — kauth-go er en identity broker, ikke en autentiseringsplattform (2026-10-13)

**Status:** Besluttet

**Beslutning:** Kauth-go delegerer autentiseringen til etablerte leverandører (Google, Microsoft, magic link til brukerens e-post, senere generisk OIDC). Kauth eier identitet, kontokobling, autorisasjon (roller, org og policy per tjeneste), sesjoner og tokenutstedelse. Prinsippet er «Delegate authentication. Own identity and authorization.»

**Begrunnelse:** Google og Microsoft er bedre på passkeys, MFA, kontogjenoppretting og deteksjon av kontoovertakelse enn et lite prosjekt kan bli. Hver autentiseringsmekanisme kauth bygger selv, er sikkerhetskritisk kode som må eies for alltid. Konkurransefortrinnet mot Authelia, Keycloak og Zitadel er *mindre* sikkerhetskritisk kompleksitet, ikke flere funksjoner.

**Konsekvens:**
- Utenfor scope: egen WebAuthn/passkeys, TOTP/HOTP, passord som fremtidig metode, LDAP, SAML og Postgres/Redis.
- Apple Sign In ligger i backlog på grunn av løpende kostnad (Apple Developer Program). Provider-arkitekturen skal gjøre den til en adapter senere.
- At innloggingen er delegert, betyr ikke at MFA er brukt. Kauth må selv ha en policy for hvor mye det stoler på hver leverandør, og for magic link spesielt.
- Kontokobling blir den mest sikkerhetskritiske delen av kauth (se ROADMAP B1).

**Grunnlag:** Produktstrategi drøftet med ChatGPT og ekstern revisjon, [ROADMAP.md](ROADMAP.md).

---

## ADN 8 — Dark Software Factory-oppsett portert fra vinkjeller (2026-10-13)

**Status:** Besluttet

**Beslutning:** Kauth-go bruker DSF-pipelinen fra vinkjeller: approval gates, faset livssyklus, holdout-scenarier, lifecycle-telemetri og spesialiserte review-agenter. Stack-spesifikke deler er tilpasset Go: test-kommandoer, filsti-triggere og en eval-server som bygger binæren mot en isolert DB med ferske nøkler.

**Begrunnelse:** Kauth er sikkerhetskritisk infrastruktur for flere tjenester. Verifiseringen 2026-10-13 fant feil som ingen dokumentbasert gjennomgang så (ROADMAP K1–K3, H1, H2). Det krever en prosess der negative scenarier skrives før koden og security-review kjøres på alle auth-diffs.

**Konsekvens:** Selve oppsettet holdes lokalt og er ikke en del av det offentlige repoet. Det gjelder hooks, skills, driver- og eval-skript, analyse- og plandokumenter og holdout-scenarier. Bare beslutningsloggen, ROADMAP og BACKLOG er sporet. Holdout-scenariene beskriver dessuten sårbarheter i detalj før de er rettet.

---

## ADN 9 — Tokenformål og tjenestebinding håndheves av kauth, ikke av URL-en eller klienten (2026-10-13)

**Status:** Godkjent (analyse 2026-10-13)
→ Analyse: [doc/features/007_AN_AKUTT_HERDING.md](features/007_AN_AKUTT_HERDING.md)

**Beslutning:**
1. **`Verify` krever forventet formål.** Kallere oppgir hvilken `token_use` de forventer (og `aud` der den finnes). Ingen endepunkter godtar et «gyldig kauth-JWT» generelt. Admin-tokens får `aud=kauth-admin` med én gang. `aud` på access-tokens kommer i Fase 1 (H5, i tråd med ADN 5).
2. **En sesjon opprettes bare der autentiseringen skjedde.** Admin-sesjonen settes i OIDC-callbacken (formålet ligger i den HMAC-signerte staten) eller i magic link-verifiseringen. Den lages aldri ved å veksle et token fra en URL.
3. **Refresh-tokenets lagrede tjeneste er autoritativ.** `service_id` fra klienten er bare et hint. I Fase 0 blir avvik logget og ignorert, i Fase 1 avvist. Policy (`require_role`/`enforce_org`) kjøres ved hver refresh mot den lagrede tjenesten. Rader uten tjeneste avvises.
4. **Redirect-mål er eksakte registrerte URL-er.** Det finnes ingen unntak for interne stier.
5. **Tokens skal aldri i loggen.** Request-loggen hvitelister felt (sti, aldri query), slik at nye parametere ikke kan lekke.
6. **Innstramminger som kan bryte klienter, innføres med logging først** (L4 og H2-avvik i Fase 0) og håndheves når dataene viser at det er trygt.
7. **Nettverksgrensen er loopback.** Kauth lytter på 127.0.0.1, og klient-IP hentes fra `CF-Connecting-IP` bare når forbindelsen kommer fra loopback.

**Begrunnelse:** Verifiseringen 2026-10-13 (ROADMAP K1, K2, H2) viste at tre uavhengige feil hadde samme rot: kauth stolte på det URL-en eller klienten påsto (et vilkårlig JWT i `?token=`, en `service_id` i skjemaet, en intern sti i en usignert cookie) i stedet for på sin egen tilstand. ADN 5 fra Quarkus-versjonen sa allerede at refresh skal bindes til `service_id`. Porten mistet det. Å lukke hver feil for seg, uten et prinsipp, inviterer til neste variant.

**Konsekvens:**
- Aktive admin-sesjoner må logge inn på nytt én gang når `aud=kauth-admin` innføres.
- Ingen nye kolonner. Klientenes tokens er uendret i Fase 0.
- Fase 1 bygger videre med `aud` på alle tokens, avvisning av `service_id`-avvik, eventuelt håndheving av L4, og CSRF-vern som tar høyde for at `Referrer-Policy: no-referrer` gir `Origin: null` på skjema-POST.

**Tillegg (2026-10-13, fra 007 F5):** Kauth sender `Referrer-Policy: no-referrer`. Derfor sender nettleseren `Origin: null` på kauths egne skjema-POST-er. CSRF-vern for admin og andre skjemaer (Fase 1) skal bruke `Sec-Fetch-Site: same-origin` eller et CSRF-token, ikke Origin. `Origin: null` skal aldri godtas. Origin-sjekken på `/token` (007 F7) påvirkes ikke, fordi den kalles fra appenes egne sider.

---

## ADN 10 — Føderert identitet krever leverandørbekreftet e-post, og refresh-familier revokeres som helhet (2026-10-13)

**Status:** Vedtatt (2026-10-13)
→ Analyse: [doc/features/008_AN_HERD_FLYTER.md](features/008_AN_HERD_FLYTER.md)

**Beslutning:**
1. **E-post fra en leverandør brukes bare når leverandøren har bekreftet den.** Google: `email_verified == true`, i alle grener. Microsoft: en personlig konto gjenkjennes bare på `tid == 9188040d-6c67-4c5b-b112-36a304b66dad`. En organisasjonskonto krever `xms_edov == true`. Et manglende claim tolkes aldri som «personlig konto». Det er ingen fallback til `preferred_username`. `iss` valideres mot `tid`.
2. **Den signerte OIDC-staten bærer nonce og utstedelsestid.** Nonce sendes til leverandøren og sjekkes mot `id_token.nonce`. En state eldre enn 10 minutter avvises. Det blir ingen ny tilstand på serveren.
3. **Feil i føderert innlogging gir en generisk feilkode på innloggingssiden, aldri feiltekst fra biblioteket og aldri en automatisk ny runde mot leverandøren.** Årsaken går til audit og logg.
4. **En refresh-familie er enheten for tilbaketrekking.** Rotasjonen (konsum + barn) er én transaksjon. Gjenbruk eller presentasjon av et revokert token revokerer hele familien uansett `used`. Logout revokerer familien til cookien, og deaktivering revokerer alle familiene til brukeren.
5. **Ingen toleransevindu for samtidig refresh.** Prod-data (17 reuse, 11 av dem samtidige kall fra klarsyn før klientens single-flight-fiks 2026-07-28, 0 reuse på 1 406 rotasjoner siden 2026-08-18) viser at problemet er løst hos klienten. Reuse-audit får tidsgap, slik at et vindu kan innføres på data hvis behovet kommer tilbake.
6. **Avvisning av `service_id`-avvik ved refresh (ADN 9 pkt 3) utsettes.** Den lagrede tjenesten er allerede autoritativ, så avvisning tetter ingen hull. Datagrunnlaget (4 rotasjoner) er for tynt til å utelukke legitime klienter.

**Begrunnelse:** ADN 7 sier at kauth eier identiteten. Da må kauth også eie beslutningen om *hvilke* påstander fra en leverandør som er gode nok til å bli identitet. Uten den kan e-post fra en fremmed Entra-tenant ta over en eksisterende konto (nOAuth, ROADMAP H4). For refresh sier OAuth Security BCP (RFC 9700 §4.14.2) at gjenbruk skal ugyldiggjøre den aktive tokenen. Det holder bare hvis rotasjonen er atomisk og revokeringen treffer hele familien (ROADMAP H6). At logout ikke revokerte noe, var et tap fra Quarkus-porten: de 115 `user_logout`-revokeringene i prod er alle fra mai 2026, før kauth-go fantes.

**Konsekvens:**
- `xms_edov` må konfigureres som optional claim i begge Entra-appene (`bcc08970-…` «Klarsyn» og `6e5fb3bf-…` for spekto/spekto-dev) før håndhevingen deployes. Ellers avvises organisasjonskontoer (0 i prod i dag).
- Ingen migrasjon og ingen endring i tokens eller claims. Innlogginger som pågår rundt deploy, feiler én gang.
- Et ekte refresh-race logger nå ut begge parter i stedet for tilfeldig den ene.
- Varig identitet på `(tid, oid)` og `tid`-allowlist per tjeneste kommer i Fase 2/5 (ROADMAP B1, B5).

---

## ADN 11 — Engangshemmeligheter lagres som hash og brukes opp bare ved en bevisst handling fra samme origin. Admin-tilgang og audit følger DB-en (2026-10-13)

**Status:** Implementert (2026-10-14). Vedtatt 2026-10-14, i prod som `009-a` og `009-b`
→ Analyse: [doc/features/009_AN_HERD_FLYTER_DEL2.md](features/009_AN_HERD_FLYTER_DEL2.md)

**Beslutning:**
1. **Alle engangshemmeligheter lagres bare som SHA-256-hash**, slik refresh-tokens allerede gjør. Det gjelder magic-tokens (tjeneste og admin) og autorisasjonskoder. Hashingen skjer i én funksjon i `internal/token`. Skjemaendringer er additive (`ADD COLUMN`, tømming), slik at rollback fortsatt er forrige binær.
2. **En GET bruker aldri opp en hemmelighet.** En magic link viser en bekreftelsesside med én knapp. Konsumet skjer på POST. Det gjelder også `/admin/verify`. Siden har tjenestens tema og viser ikke e-postadressen.
3. **Tilstandsendrende POST fra nettleseren krever samme origin:** `Sec-Fetch-Site: same-origin`, eller, når headeren mangler, en `Origin` lik egen origin. `same-site` er ikke nok, fordi søster-apper under samme domene er trusselen. `Origin: null` godtas aldri (ADN 9-tillegget). Sjekken er middleware for hele `/admin` og brukes også på bekreftelses-POST for magic link.
4. **`/logout` forblir GET**, men revokerer og sletter cookies bare ved bevisst navigasjon: samme origin eller same-site, toppnivå-navigasjon (`Mode=navigate`, `Dest=document`), eller ingen `Sec-Fetch-*`. Cross-site-underressurser og iframes endrer ingenting.
5. **Tjenesten til et magic-token er den lagrede.** URL-en er bare et tema-hint. Formålet (`service`/`admin`) er en egen kolonne som håndheves i `WHERE`. Rate limit er en betinget innsetting i DB per normalisert e-post og formål, så innsetting, limit og «ingen e-post ved feil» er én operasjon.
6. **En autorisasjonskode brennes bare når klient, `redirect_uri` og PKCE stemmer.** Konsum og første refresh-rad er én transaksjon, og koden husker familien sin. Gjenbruk revokerer den familien (RFC 6749 §4.1.2).
7. **Admin-tilgang slås opp i DB ved hver forespørsel.** Det signerte admin-tokenet er nødvendig, men ikke tilstrekkelig. Deaktivering eller fjernet `konge` virker umiddelbart.
8. **Audit skrives via en begrenset kø med én skriver, og køen tømmes ved shutdown.** Ved full kø droppes hendelser med tellende logg. Admin-skriv auditeres synkront med aktør. `/token` og innlogging blokkeres aldri av audit.
9. **E-post normaliseres (`trim` + `lower`) ved inngang**, og databasen har en unik indeks på normalisert e-post, slik at duplikater ikke kan oppstå stille.

**Begrunnelse:** ADN 9 sa at kauth skal stole på sin egen tilstand, ikke på URL-en. 009 utvider prinsippet til nettleseren og til lagring: en lenke som åpnes av en e-postskanner, en POST fra en søster-app og et 8-timers JWT for en admin som er fjernet, er alle tilfeller der kauth handler på noe den ikke har sjekket. Klartekst-hemmeligheter i DB gjør en lesbar backup til en innlogging. Fetch Metadata gir CSRF-vern uten ny tilstand og uten endring i skjemaene, og `Referrer-Policy: no-referrer` (007 F5) gjør `Origin` alene ubrukelig. Prod-data (0 rader i begge engangstabellene, 0 e-poster som ikke er normalisert, maks 4 audit-hendelser/s) gjør endringene trygge å innføre nå.

**Konsekvens:**
- Magic link krever ett ekstra klikk. Lenker i omløp ved deploy (≤ 15 min) blir ugyldige.
- Nettlesere som verken sender `Sec-Fetch-Site` eller `Origin` kan ikke bekrefte magic link eller bruke admin (fail-closed, under produktbeslutning PB2 i analysen).
- To additive migrasjoner (`purpose` og `family_id`, og unik indeks på `lower(trim(email))`). Tokens og claims er uendret.
- Access-tokens fra en gjenbrukt kode lever ut TTL til `jti` finnes (H5, 010).
- Limit per IP på bestilling av magic link står igjen (BACKLOG).
- Akseptert restrisiko, login-CSRF (P1): bekreftelsessiden viser ikke e-postadressen. Et offer som trykker på en lenke en angriper har bestilt til sin egen adresse, kan dermed logges inn som angriperen (sosial manipulering).
- Akseptert restrisiko, logout (P2/PB3): `same-site` og bar GET revokerer. En kompromittert søster-app, eller toppnivå-navigasjon fra en annen side, kan logge brukeren ut. Det gir en uønsket utlogging, ingen tilgang.
- Akseptert restrisiko: 3 bestillinger per 15 min blokkerer offerets magic link (kvote-DoS, som før).
