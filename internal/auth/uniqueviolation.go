package auth

import (
	"errors"

	"modernc.org/sqlite"
)

const (
	sqliteConstraintPrimaryKey = 1555 // SQLITE_CONSTRAINT_PRIMARYKEY
	sqliteConstraintUnique     = 2067 // SQLITE_CONSTRAINT_UNIQUE
)

// isUniqueViolation skiller en reell kollisjon (f.eks. deaktivert konto med
// samme normaliserte e-post) fra tekniske feil som lukket DB eller I/O. Bare
// kollisjonen er et avslag; alt annet skal være en intern feil.
func isUniqueViolation(err error) bool {
	var se *sqlite.Error
	if !errors.As(err, &se) {
		return false
	}
	switch se.Code() {
	// Bare utvidede koder: den generiske SQLITE_CONSTRAINT (19) dekker også
	// NOT NULL og CHECK, som er feil i koden vår og ikke en kollisjon.
	case sqliteConstraintUnique, sqliteConstraintPrimaryKey:
		return true
	}
	return false
}
