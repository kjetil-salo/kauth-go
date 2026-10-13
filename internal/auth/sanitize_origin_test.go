package auth

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Origin er angriperstyrt og havner i audit og journald, så den må renses
// før den logges: ingen kontrolltegn, begrenset lengde og gyldig UTF-8.
func TestSanitizeOrigin(t *testing.T) {
	cases := map[string]string{
		"https://evil.example":             "https://evil.example",
		"https://evil.example\r\nX-Inj: 1": "https://evil.exampleX-Inj: 1",
		"null\x00":                         "null",
	}
	for in, want := range cases {
		if got := sanitizeOrigin(in); got != want {
			t.Errorf("sanitizeOrigin(%q) = %q, vil ha %q", in, got, want)
		}
	}
	got := sanitizeOrigin("https://" + strings.Repeat("æ", 300))
	if len(got) > 200 {
		t.Errorf("lengde %d, maks 200", len(got))
	}
	if !utf8.ValidString(got) {
		t.Errorf("ugyldig UTF-8 etter avkorting: %q", got)
	}
}
