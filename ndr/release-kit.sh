#!/usr/bin/env bash
# Builds the ProVigil installer release (specs/provigil-packages.md) into dist/<version>/:
#   provigil-install.sh            the one installer, ProVigil's public key built in (customers download this)
#   provigil-kit-<v>.tar.gz(.sig)  compose file, scripts, config, data lake and AI node setup
#   images/*.tar.gz(.sig)          --offline: the images for sites without internet, by part
#                                  (core, ndr, clickhouse), so a customer zip holds only its parts
#   parts.json                     every file with its SHA-256
# Every file is signed with ProVigil's licence key (the provigil-license format), and the
# installer refuses anything unsigned or changed.
#
#   ./release-kit.sh <version> --key private.pem [--offline] [--upload]
#   ./release-kit.sh customer <version> <licence.jwt|token> [ndr]   offline zip for one customer
#
# --upload publishes the files as release v<version> of PROVIGIL_RELEASE_REPO (default
# jithinjoseph-workspace/NDR-Demo; GITHUB_TOKEN). The images themselves are pushed by release.sh.
set -euo pipefail
cd "$(dirname "$0")"
NDR=$(pwd); ROOT=$(cd .. && pwd)
REGISTRY="${PROVIGIL_REGISTRY:-ghcr.io/jithinjoseph-workspace}"
REPO="${PROVIGIL_RELEASE_REPO:-jithinjoseph-workspace/NDR-Demo}"

# python3, or python where python3 is only the Windows Store placeholder
PY=python3; $PY -c 1 2>/dev/null || PY=python

log() { printf '\033[0;34m[kit]\033[0m %s\n' "$*"; }
die() { printf '\033[0;31m[kit]\033[0m %s\n' "$*" >&2; exit 1; }

# the third-party images of a part, as docker-compose.yml names them
compose_image() { awk -v s="  $1:" '$0==s{f=1;next} f&&/^  [a-z0-9-]+:$/{f=0} f&&/^    image:/{print $2; exit}' "$NDR/docker-compose.yml"; }
part_images() {
    case "$1" in
        core) echo "$REGISTRY/provigil-auth:latest $REGISTRY/siem-api:latest $REGISTRY/ndr-ui:latest $(compose_image ndr-valkey) $(compose_image nginx)" ;;
        ndr) echo "$REGISTRY/ndr-engine:latest $(compose_image kafka1) $(compose_image vector) $(compose_image qdrant) $(compose_image opensearch)" ;;
        clickhouse) echo "$(compose_image clickhouse-keeper) $(compose_image clickhouse1)" ;;
    esac
}

# ── one customer's offline zip: the release's installer, kit, the parts the licence needs, the licence
if [ "${1:-}" = customer ]; then
    V="${2:?version}"; LIC="${3:?licence file or token}"; D="dist/$V"
    [ -f "$D/provigil-install.sh" ] || die "build the release first: ./release-kit.sh $V --key ... --offline"
    [ -f "$LIC" ] && LIC=$(tr -d ' \r\n' < "$LIC")
    P=$(printf '%s' "$LIC" | cut -d. -f2 | tr '_-' '/+'); case $(( ${#P} % 4 )) in 2) P="$P==";; 3) P="$P=";; esac
    read -r WHO MODS <<<"$(printf '%s' "$P" | base64 -d | $PY -c 'import json,sys; c=json.load(sys.stdin); print((c.get("tenant_id") or "customer"), ",".join(c.get("features") or []) or "-")')"
    OUT="dist/ProVigil-$WHO-$V"; rm -rf "$OUT"; mkdir -p "$OUT/images"
    cp "$D/provigil-install.sh" "$D"/provigil-kit-"$V".tar.gz* "$OUT/"
    PARTS="core clickhouse"; case ",$MODS," in *,ndr,*|,-,) PARTS="$PARTS ndr" ;; esac
    for p in $PARTS; do cp "$D/images/$p.tar.gz" "$D/images/$p.tar.gz.sig" "$OUT/images/" 2>/dev/null || die "no offline images in $D (build with --offline)"; done
    printf '%s\n' "$LIC" > "$OUT/licence.jwt"
    cat > "$OUT/README.txt" <<EOF
ProVigil $V for $WHO (modules: ${MODS/-/all})

On each Ubuntu 22.04/24.04 PC, in this folder:   sudo bash provigil-install.sh
It asks what the PC is. Order for three PCs: data lake, then AI node (optional), then master.
Everything is checked against ProVigil's signature; nothing is downloaded.
EOF
    (cd dist && rm -f "ProVigil-$WHO-$V.zip" && $PY -c "import shutil,sys; shutil.make_archive(sys.argv[1], 'zip', '.', sys.argv[1])" "ProVigil-$WHO-$V")
    log "dist/ProVigil-$WHO-$V.zip (parts: $PARTS)"; exit 0
fi

V="${1:-}"; shift || true
[ -n "$V" ] || die "usage: ./release-kit.sh <version> --key private.pem [--offline] [--upload]"
KEY=""; OFFLINE=0; UPLOAD=0
while [ $# -gt 0 ]; do
    case "$1" in --key) KEY="$2"; shift 2 ;; --offline) OFFLINE=1; shift ;; --upload) UPLOAD=1; shift ;; *) die "unknown option $1" ;; esac
done
[ -f "$KEY" ] || die "--key: ProVigil's private licence key (PEM) is needed to sign the release"
command -v openssl >/dev/null || die "openssl is needed"

# signature text of a file: RS256 over its SHA-256 (hex), base64url — what provigil-license sign writes
sign() {
    printf '%s' "$(sha256sum "$1" | cut -d' ' -f1)" | openssl dgst -sha256 -sign "$KEY" | base64 -w0 | tr '+/' '-_' | tr -d '=' > "$1.sig"
}

D="dist/$V"; S="$D/stage"; rm -rf "$D"; mkdir -p "$S/datalake" "$S/ainode" "$S/rust/ndr-engine"
log "kit $V"
cp docker-compose.yml install-customer.sh start.sh stop.sh status.sh "$S/"
printf '%s\n' "$V" > "$S/VERSION"
cp -r config scripts "$S/"
cp -r rust/ndr-engine/rules "$S/rust/ndr-engine/"
SRV="$ROOT/wazuh-rust-angular/backend-rust/deploy/server"
cp "$SRV/install-datalake.sh" "$SRV/backup-datalake.sh" "$S/datalake/"
cp "$ROOT/wazuh-rust-angular/clickhouse/init.sql" "$ROOT/wazuh-rust-angular/clickhouse/ndr-cluster.xml" "$ROOT/wazuh-rust-angular/clickhouse/ndr-compat-profile.xml" "$S/datalake/"
cp config/clickhouse/init.sql "$S/datalake/ndr-init.sql"
cp "$SRV/install-ainode.sh" "$S/ainode/"
find "$S" -name '*.sh' -exec sed -i 's/\r$//' {} +
tar -czf "$D/provigil-kit-$V.tar.gz" -C "$S" .
rm -rf "$S"
sign "$D/provigil-kit-$V.tar.gz"

# the installer with the public key built in (base64 of PEM, one line)
PUB=$(openssl pkey -in "$KEY" -pubout | base64 -w0)
sed "s|^PROVIGIL_PUBLIC_KEY=\"\"$|PROVIGIL_PUBLIC_KEY=\"$PUB\"|" provigil-install.sh | sed 's/\r$//' > "$D/provigil-install.sh"
grep -q "^PROVIGIL_PUBLIC_KEY=\"$PUB\"$" "$D/provigil-install.sh" || die "the key was not built into provigil-install.sh"
sign "$D/provigil-install.sh"

if [ "$OFFLINE" = 1 ]; then
    mkdir -p "$D/images"
    for part in core ndr clickhouse; do
        imgs=$(part_images "$part")
        for i in $imgs; do docker image inspect "$i" >/dev/null 2>&1 || docker pull -q "$i" >/dev/null || die "image $i is not available"; done
        log "images/$part.tar.gz: $imgs"
        # shellcheck disable=SC2086
        docker save $imgs | gzip -6 > "$D/images/$part.tar.gz"
        sign "$D/images/$part.tar.gz"
    done
fi

(cd "$D" && find . -type f ! -name '*.sig' ! -name parts.json | sort | while read -r f; do
    printf '{"file":"%s","bytes":%s,"sha256":"%s"}\n' "${f#./}" "$(stat -c %s "$f")" "$(sha256sum "$f" | cut -d' ' -f1)"
done | $PY -c 'import json,sys; json.dump({"version":sys.argv[1],"files":[json.loads(l) for l in sys.stdin]}, open("parts.json","w"), indent=1)' "$V")
log "dist/$V ready: $(cd "$D" && find . -type f | wc -l) files"

if [ "$UPLOAD" = 1 ]; then
    [ -n "${GITHUB_TOKEN:-}" ] || die "--upload needs GITHUB_TOKEN"
    H=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json")
    ID=$(curl -fsS "${H[@]}" "https://api.github.com/repos/$REPO/releases/tags/v$V" 2>/dev/null | $PY -c 'import json,sys; print(json.load(sys.stdin)["id"])' 2>/dev/null || true)
    if [ -z "$ID" ]; then
        ID=$(curl -fsS "${H[@]}" -X POST "https://api.github.com/repos/$REPO/releases" \
            -d "{\"tag_name\":\"v$V\",\"name\":\"ProVigil $V\",\"body\":\"Installer: provigil-install.sh. Offline parts in images/.\"}" \
            | $PY -c 'import json,sys; print(json.load(sys.stdin)["id"])') || die "could not create release v$V on $REPO"
    fi
    (cd "$D" && find . -type f | sort) | while read -r f; do
        name=$(basename "$f"); [ "${f#./images/}" != "$f" ] && name="images-$name"
        log "upload $name"
        curl -fsS "${H[@]}" -H "Content-Type: application/octet-stream" --data-binary @"$D/${f#./}" \
            "https://uploads.github.com/repos/$REPO/releases/$ID/assets?name=$name" >/dev/null || die "upload of $name failed"
    done
    log "release v$V published on $REPO"
fi
