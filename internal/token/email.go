package token

import "strings"

// NormalizeEmail er den kanoniske formen for e-post i lagring og kvotetelling.
//
// Den må være et fast punkt for SQL-uttrykket lower(trim(email)) som brukes av
// den unike indeksen og brukeroppslaget: SQLite trim() fjerner bare mellomrom
// (0x20) og lower() bretter bare ASCII, så en verdi som Go har normalisert må
// aldri endres av dem. Det holder fordi TrimSpace også fjerner alt SQLite
// trim() ville fjernet (resultatet starter og slutter aldri med 0x20), og
// ToLower aldri produserer ASCII-store bokstaver. Ikke-ASCII bretting
// (f.eks. «É» til «é») gjør Go alene, og SQLite lar den stå urørt. Gjør ikke
// normaliseringen mer aggressiv uten å kjøre TestNormalizeEmail_FixedPointInSQLite.
func NormalizeEmail(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// ValidEmail er en grov grensesjekk av en allerede normalisert adresse: kort
// nok til RFC 5321, nøyaktig én @ med innhold på begge sider og ingen
// kontrolltegn. Hindrer at tull blir lagret som kvotenøkkel eller havner i
// e-posthoder.
func ValidEmail(s string) bool {
	if len(s) == 0 || len(s) > 254 || strings.Count(s, "@") != 1 {
		return false
	}
	if s[0] == '@' || s[len(s)-1] == '@' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return false
		}
	}
	return true
}
