package i18n

// catalog er oversettelsene. Alle locales må ha alle felt utfylt —
// TestCatalogComplete håndhever det.
var catalog = map[string]Strings{
	"en": {
		SignIn:              "Sign in",
		EmailPlaceholder:    "Email address",
		PasswordPlaceholder: "Password",
		Or:                  "or",

		ContinueWithGoogle:    "Continue with Google",
		ContinueWithMicrosoft: "Continue with Microsoft",
		SignInWithEmailLink:   "Sign in with an email link",

		MagicPageTitle:    "Email sign-in",
		MagicSubmit:       "Send sign-in link",
		MagicSending:      "Sending…",
		MagicCheckInbox:   "Check your inbox",
		MagicSentToBefore: "We've sent a sign-in link to",
		MagicSentToAfter:  ". Click the link to sign in.",
		MagicValidMinutes: "The link is valid for 15 minutes.",
		BackToSignIn:      "Back to sign-in",

		MagicConfirmTitle:   "Confirm sign-in",
		MagicConfirmButton:  "Sign in",
		MagicConfirmHint:    "Tap Sign in to finish. The link only works once.",
		MagicConfirmBlocked: "Sign-in couldn't be completed here. Copy the link from the email and paste it into your browser.",

		ErrAccessDenied:    "Access denied.",
		ErrLoginFailed:     "Sign-in failed. Please try again.",
		ErrInvalidRedirect: "Invalid return address. Please start the sign-in again.",
		ErrExpiredLink:     "The link has expired or has already been used. Please try again.",
		ErrTooManyRequests: "Too many requests. Please wait a few minutes and try again.",
		ErrNoAccount:       "No account found for this email address.",
		ErrInternal:        "Something went wrong on our end. Please try again.",

		MailSubject: "Your sign-in link",
		MailBody:    "Hello!\n\nClick to sign in (valid for 15 minutes):\n\n{link}\n\nIf you didn't request this, you can ignore this email.\n",
	},

	"nb": {
		SignIn:              "Logg inn",
		EmailPlaceholder:    "E-postadresse",
		PasswordPlaceholder: "Passord",
		Or:                  "eller",

		ContinueWithGoogle:    "Fortsett med Google",
		ContinueWithMicrosoft: "Fortsett med Microsoft",
		SignInWithEmailLink:   "Logg inn med e-postlenke",

		MagicPageTitle:    "E-postinnlogging",
		MagicSubmit:       "Send innloggingslenke",
		MagicSending:      "Sender…",
		MagicCheckInbox:   "Sjekk innboksen din",
		MagicSentToBefore: "Vi har sendt en innloggingslenke til",
		MagicSentToAfter:  ". Klikk på lenken for å logge inn.",
		MagicValidMinutes: "Lenken er gyldig i 15 minutter.",
		BackToSignIn:      "Tilbake til innlogging",

		MagicConfirmTitle:   "Bekreft innlogging",
		MagicConfirmButton:  "Logg inn",
		MagicConfirmHint:    "Trykk «Logg inn» for å fullføre. Lenken virker bare én gang.",
		MagicConfirmBlocked: "Innloggingen kunne ikke fullføres her. Kopier lenken fra e-posten og lim den inn i nettleseren.",

		ErrAccessDenied:    "Tilgang nektet.",
		ErrLoginFailed:     "Innloggingen feilet. Prøv igjen.",
		ErrInvalidRedirect: "Ugyldig retur-adresse. Start innloggingen på nytt.",
		ErrExpiredLink:     "Lenken er utløpt eller allerede brukt. Prøv igjen.",
		ErrTooManyRequests: "For mange forespørsler. Vent noen minutter og prøv igjen.",
		ErrNoAccount:       "Ingen konto funnet for denne e-postadressen.",
		ErrInternal:        "Noe gikk galt hos oss. Prøv igjen.",

		MailSubject: "Din innloggingslenke",
		MailBody:    "Hei!\n\nKlikk for å logge inn (gyldig 15 min):\n\n{link}\n\nHvis du ikke ba om dette, ignorer denne e-posten.\n",
	},

	"de": {
		SignIn:              "Anmelden",
		EmailPlaceholder:    "E-Mail-Adresse",
		PasswordPlaceholder: "Passwort",
		Or:                  "oder",

		ContinueWithGoogle:    "Mit Google fortfahren",
		ContinueWithMicrosoft: "Mit Microsoft fortfahren",
		SignInWithEmailLink:   "Mit E-Mail-Link anmelden",

		MagicPageTitle:    "E-Mail-Anmeldung",
		MagicSubmit:       "Anmeldelink senden",
		MagicSending:      "Wird gesendet…",
		MagicCheckInbox:   "Prüfen Sie Ihren E-Mail-Eingang",
		MagicSentToBefore: "Wir haben einen Anmeldelink an",
		MagicSentToAfter:  " gesendet. Klicken Sie auf den Link, um sich anzumelden.",
		MagicValidMinutes: "Der Link ist 15 Minuten gültig.",
		BackToSignIn:      "Zurück zur Anmeldung",

		MagicConfirmTitle:   "Anmeldung bestätigen",
		MagicConfirmButton:  "Anmelden",
		MagicConfirmHint:    "Klicken Sie auf „Anmelden“, um fortzufahren. Der Link ist nur einmal gültig.",
		MagicConfirmBlocked: "Die Anmeldung konnte hier nicht abgeschlossen werden. Kopieren Sie den Link aus der E-Mail und öffnen Sie ihn im Browser.",

		ErrAccessDenied:    "Zugriff verweigert.",
		ErrLoginFailed:     "Anmeldung fehlgeschlagen. Bitte versuchen Sie es erneut.",
		ErrInvalidRedirect: "Ungültige Rücksprungadresse. Bitte starten Sie die Anmeldung neu.",
		ErrExpiredLink:     "Der Link ist abgelaufen oder wurde bereits verwendet. Bitte versuchen Sie es erneut.",
		ErrTooManyRequests: "Zu viele Anfragen. Bitte warten Sie einige Minuten und versuchen Sie es erneut.",
		ErrNoAccount:       "Für diese E-Mail-Adresse wurde kein Konto gefunden.",
		ErrInternal:        "Bei uns ist etwas schiefgelaufen. Bitte versuchen Sie es erneut.",

		MailSubject: "Ihr Anmeldelink",
		MailBody:    "Hallo!\n\nKlicken Sie, um sich anzumelden (15 Minuten gültig):\n\n{link}\n\nFalls Sie dies nicht angefordert haben, ignorieren Sie diese E-Mail.\n",
	},
}
