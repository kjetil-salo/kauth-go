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

cmd="${1:-}"

case "$cmd" in
start)
    base_url="$2"; client_id="$3"; redirect_uri="$4"; email="$5"; service="${6:-$client_id}"
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
    } > "$ENV_FILE"

    enc_redirect=$(urlenc "$redirect_uri")
    curl -s -c "$COOKIES" -b "$COOKIES" \
        "$base_url/login?response_type=code&client_id=$client_id&redirect_uri=$enc_redirect&state=$state&code_challenge=$challenge&code_challenge_method=S256&scope=openid%20email" \
        -o /dev/null

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

    token_json=$(curl -s -X POST "$BASE_URL/token" \
        --data-urlencode "grant_type=authorization_code" \
        --data-urlencode "code=$code" \
        --data-urlencode "redirect_uri=$REDIRECT_URI" \
        --data-urlencode "client_id=$CLIENT_ID" \
        --data-urlencode "code_verifier=$VERIFIER")

    echo "=== /token-respons ==="
    echo "$token_json" | python3 -m json.tool 2>/dev/null || echo "$token_json"

    for key in id_token access_token; do
        jwt=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get(sys.argv[2],''))" "$token_json" "$key")
        if [ -n "$jwt" ]; then
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
