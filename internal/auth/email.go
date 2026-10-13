package auth

import "github.com/zral/kauth-go/internal/token"

// NormalizeEmail delegerer til token.NormalizeEmail, som admin-pakken også
// bruker (admin kan ikke importere auth uten sirkel i testene).
func NormalizeEmail(s string) string { return token.NormalizeEmail(s) }
