package token

import (
	"testing"
	"time"
)

func TestGapLabel(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 10, 0, time.UTC)
	tests := []struct{ name, created, want string }{
		{"normal", "2026-01-01T12:00:00Z", "gap_s=10"},
		{"framtidig gir 0", "2026-01-01T12:05:00Z", "gap_s=0"},
		{"ugyldig format", "ikke-en-tid", "gap_s=unknown"},
		{"tom", "", "gap_s=unknown"},
	}
	for _, tc := range tests {
		if got := gapLabel(tc.created, now); got != tc.want {
			t.Errorf("%s: fikk %q, ville ha %q", tc.name, got, tc.want)
		}
	}
}
