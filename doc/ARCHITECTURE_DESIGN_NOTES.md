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

