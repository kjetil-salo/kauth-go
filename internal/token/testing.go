package token

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"time"

	"github.com/zral/kauth-go/internal/audit"
	"github.com/zral/kauth-go/internal/db/gen"
)

// NewIssuerForTest lager en Issuer med generert RSA-nøkkel for bruk i tester.
// Panics ved feil — kun ment for testoppsett.
func NewIssuerForTest() *Issuer {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	iss, err := NewIssuer(key, &key.PublicKey, "https://test.example.com", 15*time.Minute, 8*time.Hour)
	if err != nil {
		panic(err)
	}
	return iss
}

// IssueAdminForTest utsteder et signert admin-token for en test-bruker.
// Bruker fast 8-timers TTL. Panics ved feil — kun ment for testoppsett.
func (i *Issuer) IssueAdminForTest(email, role string) string {
	tok, err := i.IssueAdmin(gen.User{Email: email, Roles: role, Orgs: "test"}, 8*time.Hour)
	if err != nil {
		panic(err)
	}
	return tok
}

// SignForTest signerer vilkårlige claims med Issuer sin nøkkel, slik at tester
// kan lage tokens Issue* aldri produserer (f.eks. et admin-token uten aud, som
// en sesjon utstedt før aud ble innført). Kun ment for testoppsett.
func (i *Issuer) SignForTest(claims Claims) string {
	s, err := i.sign(claims)
	if err != nil {
		panic(err)
	}
	return s
}

// NewRefreshServiceWithRunner lar tester injisere stub-querier og egen
// transaksjonsløper. Kun ment for testoppsett; produksjon bruker NewRefreshService.
func NewRefreshServiceWithRunner(q RefreshQuerier, run TxRunner, aud *audit.Service) *RefreshService {
	return &RefreshService{db: q, run: run, audit: aud}
}

// StubTxRunner kjører fn direkte mot q uten transaksjon (for stub-querier).
func StubTxRunner(q RefreshQuerier) TxRunner {
	return func(_ context.Context, fn func(RefreshQuerier) error) error { return fn(q) }
}

// HashForTest eksponerer token-hashen slik at tester kan slå opp rader.
func HashForTest(plain string) string { return HashOpaque(plain) }
