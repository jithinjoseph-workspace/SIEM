#!/bin/bash
# ProVigil installer for @CUSTOMER@ (licence.jwt next to this file).
# On each Ubuntu 22.04/24.04 PC, in this folder:   sudo bash install.sh
# It downloads ProVigil's installer, checks ProVigil's signature on it, and runs it with this
# licence. It asks what the PC is; for three PCs install the data lake first, then the AI node
# (optional), then the master.
set -euo pipefail
cd "$(dirname "$0")"
KEY="@KEY@"
URL="${PROVIGIL_DOWNLOAD_URL:-@URL@}"
export PROVIGIL_DOWNLOAD_URL="$URL"   # the installer downloads its kit from the same release
for c in curl openssl python3; do
    command -v "$c" >/dev/null 2>&1 || { apt-get update -q >/dev/null && apt-get install -y -q curl openssl python3 >/dev/null; break; }
done
# A public release first, through GitHub's download addresses: the API allows 60 calls an hour per
# address without a token (a site installing several PCs, or behind one public address, ran out).
REPO=$(printf '%s' "$URL" | sed -nE 's#^https://api\.github\.com/repos/([^/]+/[^/]+)/releases/?$#\1#p')
V=""
[ -n "$REPO" ] && V=$(curl -fsSL "https://raw.githubusercontent.com/$REPO/main/VERSION" 2>/dev/null | tr -d ' \r\n')
if [ -n "$V" ] && curl -fsSL "https://github.com/$REPO/releases/download/v$V/provigil-install.sh" -o provigil-install.sh \
    && curl -fsSL "https://github.com/$REPO/releases/download/v$V/provigil-install.sh.sig" -o provigil-install.sh.sig; then
    export PROVIGIL_VERSION_WANTED="$V"
else
    # a private release (or another address): the API, with a download token when needed
    api() { if [ -n "${PROVIGIL_DOWNLOAD_TOKEN:-}" ]; then curl -fsSL -H "Authorization: Bearer $PROVIGIL_DOWNLOAD_TOKEN" "$@"; else curl -fsSL "$@"; fi; }
    if ! api -H "Accept: application/vnd.github+json" "$URL/latest" -o release.json 2>/dev/null; then
        read -rsp "  Download token (from ProVigil): " PROVIGIL_DOWNLOAD_TOKEN || { echo "The ProVigil release needs a download token: set PROVIGIL_DOWNLOAD_TOKEN or run this in a terminal."; exit 1; }
        echo
        export PROVIGIL_DOWNLOAD_TOKEN
        api -H "Accept: application/vnd.github+json" "$URL/latest" -o release.json || { echo "The ProVigil release could not be read (token, network?)"; exit 1; }
    fi
    asset() { python3 -c 'import json,sys; print(next(a["url"] for a in json.load(open("release.json"))["assets"] if a["name"] == sys.argv[1]))' "$1"; }
    api -H "Accept: application/octet-stream" "$(asset provigil-install.sh)" -o provigil-install.sh
    api -H "Accept: application/octet-stream" "$(asset provigil-install.sh.sig)" -o provigil-install.sh.sig
fi
# ProVigil's signature over the installer's SHA-256 (RS256, base64url)
printf '%s' "$KEY" | base64 -d > provigil-public.pem
s=$(tr '_-' '/+' < provigil-install.sh.sig | tr -d ' \r\n'); case $(( ${#s} % 4 )) in 2) s="$s==" ;; 3) s="$s=" ;; esac
printf '%s' "$s" | base64 -d > provigil-install.sig.bin
if ! printf '%s' "$(sha256sum provigil-install.sh | cut -d' ' -f1)" | openssl dgst -sha256 -verify provigil-public.pem -signature provigil-install.sig.bin >/dev/null 2>&1; then
    echo "The downloaded installer is not ProVigil's (or was changed): stopped."; exit 1
fi
rm -f provigil-install.sig.bin release.json
exec bash provigil-install.sh --licence licence.jwt "$@"
