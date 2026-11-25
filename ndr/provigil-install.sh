#!/bin/bash
# ProVigil installer: one file for every customer and every PC (specs/provigil-packages.md).
#
#   sudo bash provigil-install.sh [--role allinone|master|datalake|ainode|sensor]
#        [--licence FILE|TOKEN] [--master-ip IP] [--datalake URL] [--datalake-user USER]
#        [--datalake-password-file FILE] [--dir /opt/provigil] [--version X.Y.Z]
#        [--master https://ADDRESS --tenant-id ID --sensor-key KEY]   (NDR sensor)
#
# The role is this PC's job: all-in-one (everything on one PC), master (with a separate data lake
# PC), data lake, AI node, or NDR sensor. On the master the licence decides the modules: only the
# licensed modules' images are installed and only their services run; the console shows only
# their pages.
#
# Online: the installer kit is downloaded from the ProVigil release (PROVIGIL_DOWNLOAD_URL, a
# GitHub releases API address; PROVIGIL_DOWNLOAD_TOKEN when the release is private).
# Offline: run it from the unpacked customer zip (provigil-kit-*.tar.gz, images/, licence.jwt next
# to it); nothing is downloaded. Every kit and image bundle is checked against ProVigil's
# signature before it is used.
set -euo pipefail

# Set by release-kit.sh when the release is built (base64 of ProVigil's public key).
PROVIGIL_PUBLIC_KEY=""
PROVIGIL_DOWNLOAD_URL="${PROVIGIL_DOWNLOAD_URL:-https://api.github.com/repos/jithinjoseph-workspace/provigil-releases/releases}"

ROLE=""; LICENCE=""; MASTER_IP=""; DL_URL=""; DL_USER="provigil"; DL_PASS_FILE=""; DIR="/opt/provigil"; WANT_VERSION=""
NO_VERIFY=0; WITH_VALKEY=""; MASTER_URL=""; TENANT_ID=""; SENSOR_KEY=""
while [ $# -gt 0 ]; do
    case "$1" in
        --role) ROLE="${2:-}"; shift 2 ;;
        --licence|--license) LICENCE="${2:-}"; shift 2 ;;
        --master-ip) MASTER_IP="${2:-}"; shift 2 ;;
        --datalake) DL_URL="${2:-}"; shift 2 ;;
        --datalake-user) DL_USER="${2:-}"; shift 2 ;;
        --datalake-password-file) DL_PASS_FILE="${2:-}"; shift 2 ;;
        --dir) DIR="${2:-}"; shift 2 ;;
        --version) WANT_VERSION="${2:-}"; shift 2 ;;
        --no-verify) NO_VERIFY=1; shift ;;   # development copies only (no key built in)
        --with-valkey) WITH_VALKEY=1; shift ;;   # data lake of a Windows master
        --master) MASTER_URL="${2:-}"; shift 2 ;;     # NDR sensor: the master's address (LAN IP or domain)
        --tenant-id) TENANT_ID="${2:-}"; shift 2 ;;
        --sensor-key) SENSOR_KEY="${2:-}"; shift 2 ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown option $1 (see --help)"; exit 2 ;;
    esac
done

say()  { printf '\033[0;32m[provigil]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[provigil]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[provigil] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }

HERE=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT

# ── signatures (RS256 = RSA PKCS#1 v1.5 with SHA-256, base64url: provigil-license's format) ──
b64url_decode() {
    local s; s=$(printf '%s' "$1" | tr '_-' '/+' | tr -d ' \r\n')
    case $(( ${#s} % 4 )) in 2) s="${s}==" ;; 3) s="${s}=" ;; esac
    printf '%s' "$s" | base64 -d
}
public_pem() { printf '%s' "$PROVIGIL_PUBLIC_KEY" | base64 -d > "$WORK/public.pem" 2>/dev/null && grep -q "BEGIN PUBLIC KEY" "$WORK/public.pem"; }
# signed text, base64url signature: 0 when ProVigil's key made it
signed_by_provigil() {
    b64url_decode "$2" > "$WORK/sig.bin" 2>/dev/null || return 1
    printf '%s' "$1" | openssl dgst -sha256 -verify "$WORK/public.pem" -signature "$WORK/sig.bin" >/dev/null 2>&1
}
# a file with FILE.sig next to it (the signature covers its SHA-256, as provigil-license sign does)
check_file() {
    local f=$1
    [ "$NO_VERIFY" = 1 ] && { warn "not checking $(basename "$f") (--no-verify)"; return 0; }
    [ -f "$f.sig" ] || die "$(basename "$f") has no signature file ($(basename "$f").sig)"
    signed_by_provigil "$(sha256sum "$f" | cut -d' ' -f1)" "$(cat "$f.sig")" || die "$(basename "$f") is not ProVigil's or was changed: not installing it"
    say "signature good: $(basename "$f")"
}

[ "$(id -u)" = 0 ] || die "run as root: sudo bash $0"
. /etc/os-release 2>/dev/null || true
[ "${ID:-}" = ubuntu ] || warn "only Ubuntu 22.04/24.04 is supported (found ${ID:-unknown})"
for c in openssl curl tar python3 sha256sum; do command -v $c >/dev/null 2>&1 || { apt-get update -q >/dev/null && apt-get install -y -q openssl curl tar python3 coreutils >/dev/null; break; }; done
if [ "$NO_VERIFY" = 0 ]; then
    public_pem || die "this installer has no ProVigil key built in (a development copy): use the released provigil-install.sh, or --no-verify for testing"
fi

# ── 1. the installer kit: next to this file (offline zip), else from the release ──
OFFLINE=""
KIT=$(ls "$HERE"/provigil-kit-*.tar.gz 2>/dev/null | sort -V | tail -1 || true)
if [ -n "$KIT" ]; then
    [ -d "$HERE/images" ] && OFFLINE="$HERE"
    say "using the kit next to this installer: $(basename "$KIT")${OFFLINE:+ (offline, images included)}"
else
    say "downloading the installer kit from the ProVigil release..."
    REL="$PROVIGIL_DOWNLOAD_URL/latest"; [ -n "$WANT_VERSION" ] && REL="$PROVIGIL_DOWNLOAD_URL/tags/v$WANT_VERSION"
    api() { if [ -n "${PROVIGIL_DOWNLOAD_TOKEN:-}" ]; then curl -fsSL -H "Authorization: Bearer $PROVIGIL_DOWNLOAD_TOKEN" "$@"; else curl -fsSL "$@"; fi; }
    if ! api -H "Accept: application/vnd.github+json" "$REL" -o "$WORK/release.json" 2>/dev/null; then
        [ -z "${PROVIGIL_DOWNLOAD_TOKEN:-}" ] || die "the release at $REL could not be read with the download token"
        read -rsp "  Download token (from ProVigil; the release is private): " PROVIGIL_DOWNLOAD_TOKEN \n            || die "the release at $REL needs a download token: set PROVIGIL_DOWNLOAD_TOKEN or run this in a terminal"
        echo
        api -H "Accept: application/vnd.github+json" "$REL" -o "$WORK/release.json" || die "the release at $REL could not be read (token, network?)"
    fi
    asset() { python3 -c "import json,sys; a=[x for x in json.load(open(sys.argv[1]))['assets'] if x['name'].startswith('provigil-kit-') and x['name'].endswith(sys.argv[2])]; print(a[0]['url'] if a else '')" "$WORK/release.json" "$1"; }
    NAME=$(python3 -c "import json,sys; print(next((x['name'] for x in json.load(open(sys.argv[1]))['assets'] if x['name'].startswith('provigil-kit-') and x['name'].endswith('.tar.gz')), ''))" "$WORK/release.json")
    [ -n "$NAME" ] || die "the release has no installer kit"
    KIT="$WORK/$NAME"
    api -H "Accept: application/octet-stream" "$(asset .tar.gz)" -o "$KIT" || die "the kit did not download"
    api -H "Accept: application/octet-stream" "$(asset .tar.gz.sig)" -o "$KIT.sig" || die "the kit's signature did not download"
fi
check_file "$KIT"
mkdir -p "$DIR"
tar -xzf "$KIT" -C "$DIR"
chmod +x "$DIR"/*.sh "$DIR"/scripts/*.sh "$DIR"/datalake/*.sh "$DIR"/ainode/*.sh 2>/dev/null || true
say "kit $(cat "$DIR/VERSION" 2>/dev/null || echo '?') unpacked into $DIR"
if [ -n "$OFFLINE" ]; then for f in "$OFFLINE"/images/*.tar.gz; do check_file "$f"; done; fi

# ── 2. this PC's role ──
if [ -z "$ROLE" ]; then
    cat <<'EOF'

  What is this PC?
    1) All-in-one   everything on this PC (small sites)
    2) Master       the console and services; events go to a separate data lake PC
    3) Data lake    the database PC of a master (install this one first)
    4) AI node      the local AI model PC of a master (optional)
    5) NDR sensor   captures network traffic for an NDR master
EOF
    read -rp "  Choice [1-5]: " c
    case "$c" in 1) ROLE=allinone ;; 2) ROLE=master ;; 3) ROLE=datalake ;; 4) ROLE=ainode ;; 5) ROLE=sensor ;; *) die "choose 1-5" ;; esac
fi
ask_master_ip() { [ -n "$MASTER_IP" ] || read -rp "  The master PC's IP address: " MASTER_IP; }

case "$ROLE" in
    datalake)
        ask_master_ip
        if [ -z "$WITH_VALKEY" ]; then
            read -rp "  Is the master a Windows PC (the MSI)? It then keeps its sessions here [y/N]: " w || w=n
            case "$w" in y|Y|yes) WITH_VALKEY=1 ;; esac
        fi
        exec bash "$DIR/datalake/install-datalake.sh" --master-ip "$MASTER_IP" ${WITH_VALKEY:+--with-valkey} ;;
    ainode)
        ask_master_ip
        exec bash "$DIR/ainode/install-ainode.sh" --master-ip "$MASTER_IP" ;;
    sensor)
        # where the sensor sends its traffic data: the master's LAN IP on site, its domain when hosted
        [ -n "$MASTER_URL" ] || read -rp "  The master's address (LAN IP, or https://domain when hosted): " MASTER_URL
        [ -n "$TENANT_ID" ] || read -rp "  Tenant id (console: Sensors, Add sensor): " TENANT_ID
        [ -n "$SENSOR_KEY" ] || { read -rsp "  Sensor key (console: Sensors, Add sensor): " SENSOR_KEY; echo; }
        case "$MASTER_URL" in http://*|https://*) ;; *) MASTER_URL="https://$MASTER_URL" ;; esac
        [ -n "$TENANT_ID" ] && [ -n "$SENSOR_KEY" ] || die "the sensor needs the tenant id and the sensor key"
        exec bash "$DIR/scripts/install-sensor.sh" --cloud-url "$MASTER_URL" --tenant-id "$TENANT_ID" --api-key "$SENSOR_KEY" ;;
    allinone|master) ;;
    *) die "unknown role $ROLE (allinone, master, datalake, ainode, sensor)" ;;
esac

# ── 3. the licence (master and all-in-one): checked, then its modules decide what is installed ──
if [ -z "$LICENCE" ] && [ -f "$HERE/licence.jwt" ]; then LICENCE="$HERE/licence.jwt"; fi
if [ -z "$LICENCE" ] && [ -f "$DIR/.env" ]; then LICENCE=$(grep '^LICENSE_TOKEN=' "$DIR/.env" | cut -d= -f2- || true); fi
if [ -z "$LICENCE" ]; then read -rp "  Paste your ProVigil licence: " LICENCE; fi
[ -f "$LICENCE" ] && LICENCE=$(tr -d ' \r\n' < "$LICENCE")
LICENCE=$(printf '%s' "$LICENCE" | tr -d ' \r\n')
[ "$(printf '%s' "$LICENCE" | tr -cd . | wc -c)" = 2 ] || die "that is not a ProVigil licence"
if [ "$NO_VERIFY" = 0 ]; then
    signed_by_provigil "${LICENCE%.*}" "${LICENCE##*.}" || die "the licence is not signed by ProVigil (or was changed)"
fi
CLAIMS=$(b64url_decode "$(printf '%s' "$LICENCE" | cut -d. -f2)")
read -r CUSTOMER MODULES EXPIRES <<<"$(printf '%s' "$CLAIMS" | python3 -c '
import json, sys, time
c = json.load(sys.stdin)
print((c.get("tenant_name") or c.get("tenant_id") or "?").replace(" ", "_"), ",".join(c.get("features") or []) or "-",
      time.strftime("%Y-%m-%d", time.gmtime(c.get("exp", 0))))')"
[ "$MODULES" = "-" ] && MODULES=""
say "licence: ${CUSTOMER//_/ }, modules ${MODULES:-all}, valid until $EXPIRES"
python3 -c "import json,sys,time; sys.exit(0 if json.loads(sys.argv[1]).get('exp',0) > time.time() else 1)" "$CLAIMS" \
    || warn "this licence has expired: the console works, new PCs cannot enrol until it is renewed"
case ",$MODULES," in *,siem,*|*,ndr,*|,,) ;; *) warn "the licence has no SIEM or NDR module: the SIEM is installed as the base for ${MODULES}" ;; esac

# ── 4. master: the data lake PC (install-datalake.sh printed its address, user and password) ──
DL_PASS=""
if [ "$ROLE" = master ]; then
    [ -n "$DL_URL" ] || read -rp "  Data lake address (e.g. http://192.168.1.20:8123): " DL_URL
    case "$DL_URL" in http://*|https://*) ;; *) DL_URL="http://$DL_URL:8123" ;; esac
    if [ -n "$DL_PASS_FILE" ]; then DL_PASS=$(head -n1 "$DL_PASS_FILE"); else read -rsp "  Data lake password for $DL_USER: " DL_PASS; echo; fi
    ANSWER=$(curl -s --max-time 10 -u "$DL_USER:$DL_PASS" "$DL_URL/?query=SELECT%201" || true)
    [ "$ANSWER" = 1 ] || die "the data lake at $DL_URL did not accept $DL_USER (answer: ${ANSWER:-none}). Check the address, the password and that it allows this PC's address"
    say "data lake answers: $DL_URL"
fi

# ── 5. the services: the rest is install-customer.sh, told the role, licence and image source ──
export PV_ROLE="$ROLE" PV_MODULES="$MODULES" PV_LICENSE_TOKEN="$LICENCE" PV_LICENSE_PUBLIC_KEY="$PROVIGIL_PUBLIC_KEY"
export PV_DATALAKE_URL="${DL_URL}" PV_DATALAKE_USER="${DL_URL:+$DL_USER}" PV_DATALAKE_PASSWORD="$DL_PASS"
export PV_OFFLINE_DIR="$OFFLINE"
[ -n "${PROVIGIL_REGISTRY_TOKEN:-}" ] && export REGISTRY_TOKEN="$PROVIGIL_REGISTRY_TOKEN"
cd "$DIR"
exec bash "$DIR/install-customer.sh" "$DIR"
