package auth_test

import (
	"testing"

	"github.com/zral/kauth-go/internal/auth"
)

// RFC 7636 vedlegg B.
func TestS256Challenge_RFC7636Vector(t *testing.T) {
	got := auth.S256Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
	if want := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"; got != want {
		t.Fatalf("S256Challenge = %q, vil ha %q", got, want)
	}
}
