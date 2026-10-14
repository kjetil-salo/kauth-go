package auth_test

import (
	"testing"

	"github.com/zral/kauth-go/internal/auth"
)

func TestSignAndVerifyState_Valid(t *testing.T) {
	secret := []byte("test-secret-32bytes-padded-here!")
	state := auth.SignState(secret, "spekto", "abc123nonce")
	svcID, ok := auth.VerifyState(secret, state)
	if !ok {
		t.Fatal("forventet gyldig state")
	}
	if svcID != "spekto" {
		t.Fatalf("feil serviceID: %q", svcID)
	}
}

func TestVerifyState_WrongSecret(t *testing.T) {
	state := auth.SignState([]byte("riktig-secret-32bytes-padded!!"), "spekto", "nonce")
	_, ok := auth.VerifyState([]byte("feil-secret-32bytes-padded-!!"), state)
	if ok {
		t.Fatal("feil secret skal feile")
	}
}

func TestVerifyState_TamperedPayload(t *testing.T) {
	secret := []byte("secret-32bytes-padded-here-!!!!")
	state := auth.SignState(secret, "spekto", "nonce")
	tampered := state[:len(state)-4] + "XXXX"
	_, ok := auth.VerifyState(secret, tampered)
	if ok {
		t.Fatal("manipulert state skal feile")
	}
}
