# Backlog

**Hva dette er:** én liste over arbeid som faktisk gjenstår, med eier og hvorfor det venter. Oppdateres som del av feature-lifecycle.

**Hva dette ikke er:** en beslutningslogg. *Hvorfor* noe er bestemt står i [ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md). Faser, risikoregister og estimater står i [ROADMAP.md](ROADMAP.md). Ved motstrid er ADN-en fasit.

Sist gjennomgått: 2026-10-14

---

## Neste (rekkefølge)

| # | Sak | Hvorfor | Ref |
|---|-----|---------|-----|
| 1 | **007 Akutt sikkerhetsherding** (Fase 0) | Ett-klikks kjede fra lenke til admin-overtakelse i prod (K1+K2). Tilgangskrav nulles stille ved admin-lagring (H1) | ROADMAP §2.1–2.2 |
| 2 | Beslutning B1–B6 | Blokkerer analyse for Fase 1–2 | ROADMAP §4 |
| 3 | 010 Herd eksisterende flyter, del 3 (Fase 1): `aud`/`jti` på alle tokens (H5) | 008 og 009 er levert. Gjenstår: `aud`, `jti` og tilbaketrekking av access-tokens, også fra en gjenbrukt kode | ROADMAP §5 |
| 4 | 011–012 Stabil identitet (Fase 2) | Må være på plass før flere leverandører kommer til | ADN 7 |

## Senere

| Sak | Hvorfor den venter | Ref |
|-----|--------------------|-----|
| wspekto: send `service` på Google/MS-knappene i login.html, deretter håndhev L4 | L4 logges fra 007. Å håndheve før dette er rettet ville brukket Google-login for wspekto | ROADMAP L4, ADN 9 |
| CORS for `klarsyn.net` og `klarsyn.lilleklo.work` | Refresh fra disse vertene feiler i dag. Først avklares det om de skal refreshe fra nettleser | ROADMAP H7 |
| Nekt `KAUTH_SMTP_MOCK=true` ved https-issuer | Mock-mailen skriver gyldige magic-lenker til journald. Ikke satt i prod i dag, men ingenting hindrer det (007 F1, security review U1) | ROADMAP I3 |
| Generiske feilmeldinger til klient | `err.Error()` fra JWT-validering og SQLite sendes til klienten, bl.a. i `microsoft.go` og admin-middleware (007 F1, security review U2) | ROADMAP M7 |
| Fjern avsluttende `/` fra `KAUTH_BASE_URL` i `config.Load` | Gir `//magic-login/` i lenkene ved feilkonfig. Prod er korrekt i dag (007 F1, code review A1) | — |
| Valider `callback_url` ved lagring i admin, og bruk første trimmede oppføring på nivå 2–5 | Feltet lagres uvalidert. En CSV-verdi eller relativ URL gir feil redirect på nivå 2–5, og nivå 1 godtar alt admin registrerer (007 F3, security M2 og code review S3) | ROADMAP L3 |
| Plant `redirect_uri`-cookien bare når den er gyldig for tjenesten (google.go, login.html) | Ufarlig etter F3, men det er selve inngangen til redirect på tvers av tjenester (007 F3, security S1) | ROADMAP L4 |
| Valider tjeneste-ID (slug `^[a-z0-9-]+$`) ved opprettelse i admin | `HandleCreate` bruker ID-en i filsti for bakgrunnsbilde, så `../` skriver utenfor `static/` (bak admin-innlogging) (007 F4, security S3) | — |
| Rotering av per-tjeneste OAuth-credentials | Kan ikke gjøres i admin-UI etter 007 F4 (bevisst). Må gjøres direkte i DB, eller i et eget skjema med secret-felt som bare kan skrives | ROADMAP M12 |
| Rate limit og dummy-bcrypt på `/do-login`, eller fjern passordkoden helt (B4) | Når `KAUTH_PASSWORD_LOGIN_ENABLED=true` gjelder fortsatt: ingen rate limit og et timing-orakel for brukeroppregning. Bryteren står av i prod (007 F6, security M1) | ROADMAP M10, B4 |
| Strip standardport og konverter IDN i `KAUTH_CORS_ORIGINS` | `https://a.example:443` og Unicode-verter godtas, men matcher aldri det nettleseren sender (007 F7, code review S-b) | ROADMAP H7 |
| Begrens audit-rader fra gjentatte `/dispatch`-kall | En autentisert bruker kan generere mange audit-rader via gjentatte `/dispatch`-kall (`redirect_service_mismatch`). Vurder rate limit eller dedup (007 F9) | — |
| Sterkere kilde-autentisering for `CF-Connecting-IP` | Loopback-tillit betyr at lokale prosesser på boksen kan sette klient-IP. Vurder unix-socket eller delt hemmelighet fra cloudflared (007 F10) | — |
| vinkjeller: del refresh på tvers av faner (Web Locks/single-flight, som klarsyn) | Samtidige refresh fra flere faner gir reuse, og etter 008 logger det ut begge parter (008 F2, ADN 10 pkt 5) | ROADMAP H6 |
| Overvåk W1-utløseren: reuse med `gap_s ≤ 2`, samme IP og UA | Slår den til, revurder idempotensvindu for samtidig refresh. Ellers ingen tiltak (008, ADN 10 pkt 5) | ROADMAP H6 |
| Audit-volum fra gjentatte presentasjoner av revokerte tokens | Hver presentasjon logger `refresh_token_revoked_presented`. Vurder rate limit eller dedup (008 F3) | — |
| Fase 3–6 | Forutsetter Fase 2 | ROADMAP §5 |
| Apple Sign In | Løpende kostnad. Kommer som adapter etter Fase 4 ved dokumentert behov | ADN 7 |
| GitHub/LinkedIn m.fl. | Kan i stor grad dekkes av generisk OIDC (Fase 4) | ROADMAP §5 |
| Deaktivert bruker på tjeneste med auto-register gir `login_failed` i stedet for `access_denied` | Uventet feilkode, ufarlig (008 F10 S2) | — |
| Audit for «ingen konto», policybrudd og DB-feil i vanlig gren av Google-flyten | Bare avvisning på `email_verified` auditeres i dag (008 F10 S3) | — |
| OIDC-klient i authorization_code-flyten mister `oidc_authz` ved ugyldig state og får ingen spec-feil-redirect | Klienten ender på `/login` i stedet for `redirect_uri?error=` (008 F9 S3) | — |
| Limit per IP på `POST /magic-login` | Også e-postflom via aliaser (`x+1@`) mot én innboks. Kvoten per e-post stopper dem ikke. Krever en IP-modell (ADN 9 pkt 7, 009 F3) | ADN 11 |
| vinkjeller og univers-authgate kaller ikke kauth `/logout` | Refresh-familien revokeres ikke ved utlogging der. spekto bør bekreftes (009 P-betingelser) | ROADMAP H6 |
| Audit i samme transaksjon som admin-endringen | I dag logges `LogSync` etter at endringen er lagret. Feiler audit, står endringen og listen viser advarsel. Gjøres ved behov (009 F7) | ADN 11 |
| PB2 fail-open som beredskap | Magic-bekreftelse og admin-POST avvises når både `Sec-Fetch-Site` og gyldig `Origin` mangler. Viser P7 (iPhone-Mail, Gmail-appen) eller drift problemer, kan sjekken snus til fail-open uten DB-endring (009 PB2) | ADN 11 |
| Magic link og passord resolver host før `?service=` | Samme mønster som Google/MS hadde før PR #6: en undertjeneste uten egen `auth_host` (analyse, wspekto) resolves som foreldretjenesten på delt host (`magic.go`, `password.go`). Ved OIDC svikter det lukket (Nivå 0 mismatcher). Bruk `resolveSocialService`-regelen (PR #6 review) | ADN 11 |
| SMTP-grenen i `internal/mail` mangler dial-timeout | `smtp.Dial` uten tidsgrense, og sendingen er asynkron. En hengende SMTP-server gir opphopning av goroutiner. Bruk `net.DialTimeout` + deadline, ev. semafor rundt sendingen. Brevo har 10 s (009 F3 S-a) | — |
| Kvote-DoS på magic link | 3 bestillinger per 15 min blokkerer offerets magic link. Akseptert risiko, som før 009 (009 F3 S3s) | ADN 11 |
| Unicode-bretting for eldre ikke-ASCII-rader | Go `ToLower` bretter Unicode, SQLite `lower()` bare ASCII. En eldre rad som `Ø@x.no` finnes ikke med `ø@x.no` og gir duplikatkonto. 0 slike rader i prod. Løses med varig identitet i Fase 2 (009 F9 S1) | ROADMAP M11, ADN 7 |
| Tilbaketrekking av access-tokens fra gjenbrukt autorisasjonskode | Familien revokeres, men access-tokens lever ut TTL til `jti` finnes. Hører til H5 i 010 (009 F8) | ROADMAP H5 |
