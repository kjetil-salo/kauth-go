#!/usr/bin/env bash
# PoC for en full OIDC authorization_code+PKCE-runde mot en kauth-go-instans,
# uten å gå via Google/Microsoft (som krever ekte nettleser-samtykke).
# Bruker magic-link som innloggingsmetode siden den går gjennom akkurat
# samme oidc_authz-cookie / /dispatch Nivå 0-kodesti som Google/Microsoft —
# kun selve InitiateLogin/HandleCallback-resolvet skiller dem.
#
# Brukt til å verifisere fiksen for github.com/kjetil-salo/kauth-go sin
# "fix-oidc-service-resolve"-branch (2026-10-02): /login sine Google/MS-
# knapper mistet client_id/service på veien, slik at /dispatch falt tilbake
# til den gamle ?token=...#rt=...-mekanismen i stedet for ?code=&state=.
#
# Dekker også etappe 2 (scope, resource indicators, stabil sub): sett
# POC_RESOURCE for å be om en RFC 8707-ressurs, og POC_SCOPE for et annet
# scope enn standard. Scriptet sender da resource både på /authorize og på
# /token, slik at likhetssjekken i §2.2 faktisk blir utøvd, og printer JWT-
# HEADEREN i tillegg til claims — der typ=at+jwt (RFC 9068) skal stå på
# access-tokenet, men ikke på id_tokenet.
#
# Bruk:
#   ./poc-oidc-login.sh start <base_url> <client_id> <redirect_uri> <email> [service]
#     Sender magic-link-epost, lagrer state i .poc-oidc-state/
#   ./poc-oidc-login.sh finish <magic_link_url>
#     Konsumerer lenken fra e-posten, følger /dispatch, bytter koden inn
#     mot /token, og printer dekodede JWT-claims for id_token/access_token.
#
# Eksempel (veivakt mot drivstoffprisene):
#   ./poc-oidc-login.sh start https://auth.drivstoffprisene.no veivakt \
#       http://localhost:5173/ kjetil@vikebo.com
#
# Samme runde med delegert skrivetilgang mot drivstoffprisene:
#   POC_RESOURCE=https://drivstoffprisene.no POC_SCOPE="openid priser:skriv" \
#   ./poc-oidc-login.sh start https://auth.drivstoffprisene.no veivakt \
#       http://localhost:5173/ kjetil@vikebo.com
#   # sjekk e-post, lim inn lenken:
#   ./poc-oidc-login.sh finish "https://auth.drivstoffprisene.no/magic-login/<token>?service=veivakt&lang=en"

set -euo pipefail

STATE_DIR="$(dirname "$0")/.poc-oidc-state"
COOKIES="$STATE_DIR/cookies.txt"
ENV_FILE="$STATE_DIR/session.env"

b64url() { python3 -c "import sys,base64; print(base64.urlsafe_b64encode(sys.stdin.buffer.read()).rstrip(b'=').decode())"; }
urlenc() { python3 -c "import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=''))" "$1"; }
decode_jwt() {
    python3 -c "
import sys, json, base64
payload = sys.argv[1].split('.')[1]
payload += '=' * (-len(payload) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(payload)), indent=2))
" "$1"
}
decode_jwt_header() {
    python3 -c "
import sys, json, base64
header = sys.argv[1].split('.')[0]
header += '=' * (-len(header) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(header)), indent=2))
" "$1"
}

cmd="${1:-}"

case "$cmd" in
start)
    base_url="$2"; client_id="$3"; redirect_uri="$4"; email="$5"; service="${6:-$client_id}"
    scope="${POC_SCOPE:-openid email}"
    resource="${POC_RESOURCE:-}"
    mkdir -p "$STATE_DIR"
    rm -f "$COOKIES"

    verifier=$(openssl rand 32 | b64url)
    challenge=$(printf '%s' "$verifier" | openssl dgst -sha256 -binary | b64url)
    state=$(openssl rand 16 | b64url)

    {
        echo "BASE_URL=$base_url"
        echo "CLIENT_ID=$client_id"
        echo "REDIRECT_URI=$redirect_uri"
        echo "VERIFIER=$verifier"
        echo "STATE=$state"
        echo "RESOURCE=$resource"
    } > "$ENV_FILE"

    enc_redirect=$(urlenc "$redirect_uri")
    authorize_url="$base_url/login?response_type=code&client_id=$client_id&redirect_uri=$enc_redirect&state=$state&code_challenge=$challenge&code_challenge_method=S256&scope=$(urlenc "$scope")"
    if [ -n "$resource" ]; then
        authorize_url="$authorize_url&resource=$(urlenc "$resource")"
    fi
    curl -s -c "$COOKIES" -b "$COOKIES" "$authorize_url" -o /dev/null

    curl -s -c "$COOKIES" -b "$COOKIES" \
        -X POST "$base_url/magic-login" \
        --data-urlencode "email=$email" \
        --data-urlencode "service=$service" \
        -o /dev/null

    echo "Magic-link sendt til $email for client_id=$client_id. Sjekk innboksen, og kjør:"
    echo "  $0 finish \"<lenken fra e-posten>\""
    ;;

finish)
    magic_url="$2"
    [ -f "$ENV_FILE" ] || { echo "Fant ikke $ENV_FILE — kjør 'start' først." >&2; exit 1; }
    # shellcheck source=/dev/null
    source "$ENV_FILE"

    location=$(curl -s -c "$COOKIES" -b "$COOKIES" -D - -o /dev/null "$magic_url" \
        | grep -i '^location' | sed 's/^[Ll]ocation: //' | tr -d '\r')
    [ -n "$location" ] || { echo "Ingen redirect fra magic-link-lenken — token utløpt/brukt?" >&2; exit 1; }

    dispatch_location=$(curl -s -c "$COOKIES" -b "$COOKIES" -D - -o /dev/null "$BASE_URL$location" \
        | grep -i '^location' | sed 's/^[Ll]ocation: //' | tr -d '\r')
    echo "=== /dispatch svarte med ==="
    echo "$dispatch_location"

    code=$(python3 -c "
import sys, urllib.parse
q = urllib.parse.urlparse(sys.argv[1]).query
print(urllib.parse.parse_qs(q).get('code', [''])[0])
" "$dispatch_location")
    [ -n "$code" ] || { echo "Ingen ?code= i svaret — fikk dispatch i stedet et ?token=? Da er bugen fortsatt der." >&2; exit 1; }

    token_args=(
        --data-urlencode "grant_type=authorization_code"
        --data-urlencode "code=$code"
        --data-urlencode "redirect_uri=$REDIRECT_URI"
        --data-urlencode "client_id=$CLIENT_ID"
        --data-urlencode "code_verifier=$VERIFIER"
    )
    # Sendes med når runden ba om en ressurs: da sjekker /token at den er
    # identisk med kodens egen (RFC 8707 §2.2), ikke bare at den finnes.
    if [ -n "${RESOURCE:-}" ]; then
        token_args+=(--data-urlencode "resource=$RESOURCE")
    fi
    token_json=$(curl -s -X POST "$BASE_URL/token" "${token_args[@]}")

    echo "=== /token-respons ==="
    echo "$token_json" | python3 -m json.tool 2>/dev/null || echo "$token_json"

    for key in id_token access_token; do
        jwt=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get(sys.argv[2],''))" "$token_json" "$key")
        if [ -n "$jwt" ]; then
            echo "=== $key header ==="
            decode_jwt_header "$jwt"
            echo "=== $key claims ==="
            decode_jwt "$jwt"
        fi
    done

    rm -rf "$STATE_DIR"
    ;;

*)
    echo "Bruk: $0 start <base_url> <client_id> <redirect_uri> <email> [service]" >&2
    echo "  eller: $0 finish <magic_link_url>" >&2
    exit 1
    ;;
esac
