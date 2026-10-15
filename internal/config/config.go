package config

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DBPath  string
	Issuer  string
	BaseURL string

	PrivateKey *rsa.PrivateKey
	PublicKey  *rsa.PublicKey

	OIDCStateSecret []byte

	SMTPHost     string
	SMTPPort     int
	SMTPUser     string
	SMTPPassword string
	SMTPFrom     string
	SMTPStartTLS bool
	SMTPMock     bool

	// BrevoAPIKey aktiverer Brevo som transport for tjenester med satt
	// services.email_from_address (BACKLOG F21). Rå SMTP over forblir
	// uendret fallback for tjenester uten egen avsenderadresse.
	BrevoAPIKey string

	GoogleClientID        string
	GoogleClientSecret    string
	MicrosoftClientID     string
	MicrosoftClientSecret string

	AccessTokenTTL time.Duration
	AdminTokenTTL  time.Duration

	HTTPPort    string
	CORSOrigins []string
	LogLevel    string

	// ExtraScopes er scope-verdier utover openid/email/profile som denne
	// instansen annonserer i scopes_supported. kauth validerer ikke scope
	// mot en liste — det speiles fra autorisasjonskoden til access-tokenet —
	// så dette er rent metadata for klienter som leser discovery-dokumentet
	// for å finne ut hva de kan be om. Ressursspesifikke scopes (f.eks.
	// priser:skriv mot en RFC 8707 resource indicator) hører til den enkelte
	// instansen, ikke til kauth selv, og settes derfor i miljøet.
	ExtraScopes []string
}

func Load() (*Config, error) {
	c := &Config{}
	var errs []string

	require := func(key string) string {
		v := os.Getenv(key)
		if v == "" {
			errs = append(errs, key+" er påkrevd")
		}
		return v
	}
	optional := func(key, def string) string {
		if v := os.Getenv(key); v != "" {
			return v
		}
		return def
	}

	c.DBPath = require("KAUTH_DB_PATH")
	c.Issuer = require("KAUTH_ISSUER")
	c.BaseURL = require("KAUTH_BASE_URL")

	// RSA-nøkler: PEM-fil eller PEM-innhold direkte
	privPEM := os.Getenv("KAUTH_PRIVATE_KEY_PEM")
	if privPEM == "" {
		path := require("KAUTH_PRIVATE_KEY_PATH")
		if path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, "kan ikke lese KAUTH_PRIVATE_KEY_PATH: "+err.Error())
			} else {
				privPEM = string(b)
			}
		}
	} else {
		b, err := base64.StdEncoding.DecodeString(privPEM)
		if err == nil {
			privPEM = string(b)
		}
	}
	if privPEM != "" {
		key, err := parseRSAPrivateKey(privPEM)
		if err != nil {
			errs = append(errs, "ugyldig privat RSA-nøkkel: "+err.Error())
		} else {
			c.PrivateKey = key
		}
	}

	pubPEM := os.Getenv("KAUTH_PUBLIC_KEY_PEM")
	if pubPEM == "" {
		path := require("KAUTH_PUBLIC_KEY_PATH")
		if path != "" {
			b, err := os.ReadFile(path)
			if err != nil {
				errs = append(errs, "kan ikke lese KAUTH_PUBLIC_KEY_PATH: "+err.Error())
			} else {
				pubPEM = string(b)
			}
		}
	} else {
		b, err := base64.StdEncoding.DecodeString(pubPEM)
		if err == nil {
			pubPEM = string(b)
		}
	}
	if pubPEM != "" {
		key, err := parseRSAPublicKey(pubPEM)
		if err != nil {
			errs = append(errs, "ugyldig offentlig RSA-nøkkel: "+err.Error())
		} else {
			c.PublicKey = key
		}
	}

	secretB64 := require("KAUTH_OIDC_STATE_SECRET")
	if secretB64 != "" {
		b, err := base64.StdEncoding.DecodeString(secretB64)
		if err != nil || len(b) < 32 {
			errs = append(errs, "KAUTH_OIDC_STATE_SECRET må være minst 32 bytes base64-kodet")
		} else {
			c.OIDCStateSecret = b
		}
	}

	c.SMTPHost = optional("KAUTH_SMTP_HOST", "")
	c.SMTPPort, _ = strconv.Atoi(optional("KAUTH_SMTP_PORT", "587"))
	c.SMTPUser = optional("KAUTH_SMTP_USER", "")
	c.SMTPPassword = os.Getenv("KAUTH_SMTP_PASSWORD")
	c.SMTPFrom = optional("KAUTH_SMTP_FROM", "noreply@localhost")
	c.SMTPStartTLS = optional("KAUTH_SMTP_STARTTLS", "true") == "true"
	c.SMTPMock = optional("KAUTH_SMTP_MOCK", "false") == "true"
	c.BrevoAPIKey = os.Getenv("KAUTH_BREVO_API_KEY")

	if c.SMTPHost == "" && !c.SMTPMock {
		fmt.Println("ADVARSEL: KAUTH_SMTP_HOST ikke satt og KAUTH_SMTP_MOCK=false — magic link vil feile")
	}

	c.GoogleClientID = os.Getenv("KAUTH_GOOGLE_CLIENT_ID")
	c.GoogleClientSecret = os.Getenv("KAUTH_GOOGLE_CLIENT_SECRET")
	c.MicrosoftClientID = os.Getenv("KAUTH_MICROSOFT_CLIENT_ID")
	c.MicrosoftClientSecret = os.Getenv("KAUTH_MICROSOFT_CLIENT_SECRET")

	accessTTL := optional("KAUTH_ACCESS_TOKEN_TTL", "PT15M")
	d, err := parseISO8601(accessTTL)
	if err != nil {
		errs = append(errs, "ugyldig KAUTH_ACCESS_TOKEN_TTL: "+err.Error())
	}
	c.AccessTokenTTL = d

	adminTTL := optional("KAUTH_ADMIN_TOKEN_TTL", "PT8H")
	d, err = parseISO8601(adminTTL)
	if err != nil {
		errs = append(errs, "ugyldig KAUTH_ADMIN_TOKEN_TTL: "+err.Error())
	}
	c.AdminTokenTTL = d

	c.HTTPPort = optional("KAUTH_HTTP_PORT", "8080")
	c.LogLevel = optional("KAUTH_LOG_LEVEL", "info")

	if cors := os.Getenv("KAUTH_CORS_ORIGINS"); cors != "" {
		for _, o := range strings.Split(cors, ",") {
			if t := strings.TrimSpace(o); t != "" {
				c.CORSOrigins = append(c.CORSOrigins, t)
			}
		}
	}

	for _, sc := range strings.FieldsFunc(os.Getenv("KAUTH_EXTRA_SCOPES"), func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n'
	}) {
		c.ExtraScopes = append(c.ExtraScopes, sc)
	}

	if len(errs) > 0 {
		return nil, errors.New("konfigurasjonsfeil:\n  - " + strings.Join(errs, "\n  - "))
	}
	return c, nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("ugyldig PEM-blokk")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// prøv PKCS1
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("ikke en RSA-nøkkel")
	}
	return rsaKey, nil
}

func parseRSAPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("ugyldig PEM-blokk")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("ikke en RSA-nøkkel")
	}
	return rsaKey, nil
}

// parseISO8601 støtter PT15M, PT8H, P30D, P1DT2H
func parseISO8601(s string) (time.Duration, error) {
	s = strings.ToUpper(strings.TrimSpace(s))
	if !strings.HasPrefix(s, "P") {
		return 0, fmt.Errorf("må starte med P: %s", s)
	}
	s = s[1:] // fjern 'P'
	var total time.Duration
	for len(s) > 0 {
		if s[0] == 'T' {
			s = s[1:] // hopp over T-separatoren
			continue
		}
		i := 0
		for i < len(s) && (s[i] >= '0' && s[i] <= '9') {
			i++
		}
		if i == 0 || i >= len(s) {
			return 0, fmt.Errorf("ugyldig ISO-8601 varighet: %s", s)
		}
		n, _ := strconv.Atoi(s[:i])
		unit := s[i]
		s = s[i+1:]
		switch unit {
		case 'D':
			total += time.Duration(n) * 24 * time.Hour
		case 'H':
			total += time.Duration(n) * time.Hour
		case 'M':
			total += time.Duration(n) * time.Minute
		case 'S':
			total += time.Duration(n) * time.Second
		default:
			return 0, fmt.Errorf("ukjent enhet %c", unit)
		}
	}
	return total, nil
}
