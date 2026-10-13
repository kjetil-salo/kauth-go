# Backlog

**Hva dette er:** én liste over arbeid som faktisk gjenstår, med eier og hvorfor det venter. Oppdateres som del av feature-lifecycle.

**Hva dette ikke er:** en beslutningslogg. *Hvorfor* noe er bestemt står i [ARCHITECTURE_DESIGN_NOTES.md](ARCHITECTURE_DESIGN_NOTES.md). Faser, risikoregister og estimater står i [ROADMAP.md](ROADMAP.md). Ved motstrid er ADN-en fasit.

Sist gjennomgått: 2026-10-13

---

## Neste (rekkefølge)

| # | Sak | Hvorfor | Ref |
|---|-----|---------|-----|
| 1 | **007 Akutt sikkerhetsherding** (Fase 0) | Ett-klikks kjede fra lenke til admin-overtakelse i prod (K1+K2). Tilgangskrav nulles stille ved admin-lagring (H1) | ROADMAP §2.1–2.2 |
| 2 | Beslutning B1–B6 | Blokkerer analyse for Fase 1–2 | ROADMAP §4 |
| 3 | 008–010 Herd eksisterende flyter (Fase 1) | nOAuth, `aud`, refresh-transaksjon, magic link | ROADMAP §5 |
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
| Fase 3–6 | Forutsetter Fase 2 | ROADMAP §5 |
| Apple Sign In | Løpende kostnad. Kommer som adapter etter Fase 4 ved dokumentert behov | ADN 7 |
| GitHub/LinkedIn m.fl. | Kan i stor grad dekkes av generisk OIDC (Fase 4) | ROADMAP §5 |
