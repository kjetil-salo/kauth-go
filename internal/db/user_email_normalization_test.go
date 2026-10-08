package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/zral/kauth-go/internal/db/gen"
)

// Migrasjon 009 og lower(trim(...))-oppslagene retter at e-post ble lagret og
// slått opp eksakt slik brukeren skrev den. SQLite sammenligner TEXT med =
// byte for byte, så GetActiveUserByEmail("Kari@...") traff ikke raden
// "kari@...", og innloggingsveien opprettet en NY konto: nytt subject_id, og
// dermed ny sub i OIDC-tokenene. En ressursserver som knytter rader til sub
// ser da to personer der det er én.

func nyBruker(t *testing.T, q *gen.Queries, epost string) gen.User {
	t.Helper()
	u, err := q.CreateUser(context.Background(), gen.CreateUserParams{
		Email: epost, Roles: "user", Orgs: "",
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	require.NoError(t, err)
	return u
}

// CreateUser normaliserer i SQL, så ingen innloggingsvei kan glemme det.
func TestCreateUser_NormalisererEpost(t *testing.T) {
	_, q := openTestDB(t)
	u := nyBruker(t, q, "  Kari.Nordmann@Eksempel.NO ")
	require.Equal(t, "kari.nordmann@eksempel.no", u.Email,
		"e-posten skal lagres normalisert, ikke slik den ble tastet")
}

// Kjernen i bugen: samme person, annen bokstavstørrelse, skal treffe samme rad
// — ikke føre til at en ny konto opprettes.
func TestGetUserByEmail_ErCaseInsensitiv(t *testing.T) {
	_, q := openTestDB(t)
	ctx := context.Background()
	opprettet := nyBruker(t, q, "kari@eksempel.no")

	for _, variant := range []string{
		"kari@eksempel.no",
		"Kari@eksempel.no",
		"KARI@EKSEMPEL.NO",
		" kari@eksempel.no ",
	} {
		funnet, err := q.GetUserByEmail(ctx, variant)
		require.NoError(t, err, "%q skal treffe samme bruker", variant)
		require.Equal(t, opprettet.ID, funnet.ID, "%q traff feil rad", variant)

		aktiv, err := q.GetActiveUserByEmail(ctx, variant)
		require.NoError(t, err, "%q skal treffe samme aktive bruker", variant)
		require.Equal(t, opprettet.ID, aktiv.ID, "%q traff feil rad", variant)

		require.NotNil(t, funnet.SubjectID)
		require.Equal(t, *opprettet.SubjectID, *funnet.SubjectID,
			"%q: sub må være den samme — det er hele poenget", variant)
	}
}

// En rad lagret FØR migrasjon 009 kan ha stor forbokstav. Normaliseringen må
// derfor ligge på kolonnen også, ikke bare på parameteren: ellers ville
// fiksen gjort det verre for nettopp de brukerne som allerede var rammet.
func TestGetUserByEmail_FinnerRadLagretMedStorBokstav(t *testing.T) {
	sqldb, q := openTestDB(t)
	ctx := context.Background()

	// Utenom CreateUser, for å etterlikne en rad fra før normaliseringen.
	_, err := sqldb.ExecContext(ctx,
		`INSERT INTO users (email, roles, orgs, created_at, subject_id)
		 VALUES ('Gammel@Eksempel.NO', 'user', '', ?, 'abc123')`,
		time.Now().UTC().Format(time.RFC3339))
	require.NoError(t, err)

	funnet, err := q.GetUserByEmail(ctx, "gammel@eksempel.no")
	require.NoError(t, err, "en rad fra før 009 må fortsatt kunne logge inn")
	require.Equal(t, "abc123", *funnet.SubjectID)
}

// Den unike indeksen fra 009 hindrer at to kontoer for samme menneske kan
// oppstå på nytt. Uten den ville en framtidig vei som setter inn utenom
// CreateUser gjeninnføre dubletten, og lower(trim(...))-oppslaget ville da
// velge vilkårlig rad med LIMIT 1.
func TestUsers_UnikIndeksHindrerCaseDublett(t *testing.T) {
	sqldb, q := openTestDB(t)
	ctx := context.Background()
	nyBruker(t, q, "kari@eksempel.no")

	_, err := sqldb.ExecContext(ctx,
		`INSERT INTO users (email, roles, orgs, created_at, subject_id)
		 VALUES ('KARI@eksempel.no', 'user', '', ?, 'dublett')`,
		time.Now().UTC().Format(time.RFC3339))
	require.Error(t, err, "to rader som kun skiller seg i bokstavstørrelse skal avvises")

	antall, err := q.CountUsers(ctx)
	require.NoError(t, err)
	require.Equal(t, int64(1), antall)
}

// last_login skrives på e-post. Den må følge samme regel, ellers ville
// oppdateringen stilltiende treffe null rader for en bruker lagret med annen
// bokstavstørrelse.
func TestUpdateUserLastLogin_ErCaseInsensitiv(t *testing.T) {
	_, q := openTestDB(t)
	ctx := context.Background()
	opprettet := nyBruker(t, q, "kari@eksempel.no")
	require.Nil(t, opprettet.LastLogin)

	naa := time.Now().UTC().Format(time.RFC3339)
	require.NoError(t, q.UpdateUserLastLogin(ctx, gen.UpdateUserLastLoginParams{
		LastLogin: &naa, Email: "KARI@Eksempel.no",
	}))

	etter, err := q.GetUserByEmail(ctx, "kari@eksempel.no")
	require.NoError(t, err)
	require.NotNil(t, etter.LastLogin, "last_login skal være satt")
	require.Equal(t, naa, *etter.LastLogin)
}
