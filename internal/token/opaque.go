package token

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Formål for magic-link-tokens. En tjenestelenke og en adminlenke er ulike
// flyter og skal ikke kunne løses inn på hverandres endepunkt.
const (
	MagicPurposeService = "service"
	MagicPurposeAdmin   = "admin"
)

// HashOpaque gir SHA-256-hex av en engangshemmelighet (refresh-token,
// magic-token, autorisasjonskode). Kun hashen lagres, slik at en lest
// database ikke gir bruker en gyldig hemmelighet. Hemmelighetene har høy
// entropi og kort levetid, så en rask hash er nok.
func HashOpaque(plain string) string {
	s := sha256.Sum256([]byte(plain))
	return hex.EncodeToString(s[:])
}

var ErrMagicPurposeMismatch = errors.New("magic-token: formål stemmer ikke med tjenestebinding")

// CheckMagicPurpose håndhever at admin-tokens aldri har tjeneste, og at
// tjenestetokens alltid har det.
func CheckMagicPurpose(purpose string, serviceID *string) error {
	switch purpose {
	case MagicPurposeAdmin:
		if serviceID == nil {
			return nil
		}
	case MagicPurposeService:
		if serviceID != nil {
			return nil
		}
	}
	return ErrMagicPurposeMismatch
}
