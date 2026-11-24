#!/usr/bin/env bash
# Build and push the images (ndr-engine, provigil-auth, the one console ndr-ui, siem-api) to GHCR,
# then bump VERSION.
# Usage:
#   ./release.sh 1.1.0          — build all four, tag as 1.1.0
#   ./release.sh 1.1.0 engine   — ndr-engine only
#   ./release.sh 1.1.0 auth     — provigil-auth only
#   ./release.sh 1.1.0 ui       — ndr-ui (the one console, wazuh-rust-angular/ndr-ui) only
#   ./release.sh 1.1.0 siem     — siem-api only
set -euo pipefail

REGISTRY="ghcr.io/jithinjoseph-workspace"
NEW_VERSION="${1:-}"
TARGET="${2:-all}"

log()  { printf '\033[0;34m[release]\033[0m %s\n' "$*"; }
ok()   { printf '\033[0;32m[  ok  ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[ warn ]\033[0m %s\n' "$*"; }
die()  { printf '\033[0;31m[ fail ]\033[0m %s\n' "$*" >&2; exit 1; }

[ -z "$NEW_VERSION" ] && die "Usage: ./release.sh <version> [engine|auth|ui|siem|all]"

cd "$(dirname "$0")"

# ── Auth ───────────────────────────────────────────────────────────────────────
if [ -z "${GITHUB_TOKEN:-}" ]; then
    if command -v gh &>/dev/null && gh auth status &>/dev/null; then
        GITHUB_TOKEN=$(gh auth token)
    else
        die "Set GITHUB_TOKEN or run 'gh auth login' first"
    fi
fi
echo "$GITHUB_TOKEN" | docker login ghcr.io -u jithinjoseph-workspace --password-stdin
ok "Authenticated to ghcr.io"

# ── Push with one retry — a single transient network blip on the :latest
# push must not leave it stale while the version tag already went through.
push_with_retry() {
    local image="$1"
    if docker push "$image" 2>/tmp/ndr_release_push_err; then
        return 0
    fi
    warn "push failed for ${image}, retrying once ($(tail -2 /tmp/ndr_release_push_err | tr '\n' ' '))..."
    sleep 3
    docker push "$image" 2>>/tmp/ndr_release_push_err
}

# Each build_* function builds+pushes and returns 0/1 rather than relying on
# set -e to abort the whole script — that let an early success (e.g.
# ndr-engine) get permanently stuck in the registry at a new version while a
# later failure (e.g. ndr-ui) meant the version bump/commit never happened,
# leaving git with zero record that a partial, version-skewed release had
# already shipped. Now every target is attempted, failures are collected, and
# the version bump/commit only happens if every requested target succeeded.
build_engine() {
    log "Building ndr-engine:${NEW_VERSION}..."
    docker build \
        --build-arg CACHEBUST="$(date +%s)" \
        -t "${REGISTRY}/ndr-engine:${NEW_VERSION}" \
        -t "${REGISTRY}/ndr-engine:latest" \
        -f rust/Dockerfile \
        .. || { warn "ndr-engine build failed"; return 1; }
    push_with_retry "${REGISTRY}/ndr-engine:${NEW_VERSION}" || { warn "ndr-engine push failed for :${NEW_VERSION}"; return 1; }
    push_with_retry "${REGISTRY}/ndr-engine:latest"          || { warn "ndr-engine push failed for :latest"; return 1; }
    ok "ndr-engine pushed → :${NEW_VERSION} and :latest"
}

build_auth() {
    log "Building provigil-auth:${NEW_VERSION}..."
    docker build \
        -t "${REGISTRY}/provigil-auth:${NEW_VERSION}" \
        -t "${REGISTRY}/provigil-auth:latest" \
        -f rust/docker/auth-service.Dockerfile \
        .. || { warn "provigil-auth build failed"; return 1; }
    push_with_retry "${REGISTRY}/provigil-auth:${NEW_VERSION}" || { warn "provigil-auth push failed for :${NEW_VERSION}"; return 1; }
    push_with_retry "${REGISTRY}/provigil-auth:latest"          || { warn "provigil-auth push failed for :latest"; return 1; }
    ok "provigil-auth pushed → :${NEW_VERSION} and :latest"
}

build_siem_api() {
    log "Building siem-api:${NEW_VERSION}..."
    docker build \
        -t "${REGISTRY}/siem-api:${NEW_VERSION}" \
        -t "${REGISTRY}/siem-api:latest" \
        -f ../wazuh-rust-angular/backend-rust/docker/siem-api.Dockerfile \
        .. || { warn "siem-api build failed"; return 1; }
    push_with_retry "${REGISTRY}/siem-api:${NEW_VERSION}" || { warn "siem-api push failed for :${NEW_VERSION}"; return 1; }
    push_with_retry "${REGISTRY}/siem-api:latest"          || { warn "siem-api push failed for :latest"; return 1; }
    ok "siem-api pushed → :${NEW_VERSION} and :latest"
}

build_ui() {
    log "Building ndr-ui:${NEW_VERSION}..."
    docker build \
        -t "${REGISTRY}/ndr-ui:${NEW_VERSION}" \
        -t "${REGISTRY}/ndr-ui:latest" \
        ../wazuh-rust-angular/ndr-ui || { warn "ndr-ui build failed"; return 1; }
    push_with_retry "${REGISTRY}/ndr-ui:${NEW_VERSION}" || { warn "ndr-ui push failed for :${NEW_VERSION}"; return 1; }
    push_with_retry "${REGISTRY}/ndr-ui:latest"          || { warn "ndr-ui push failed for :latest"; return 1; }
    ok "ndr-ui pushed → :${NEW_VERSION} and :latest"
}

FAILED=()
SUCCEEDED=()

run_target() {
    local name="$1" fn="$2"
    if "$fn"; then
        SUCCEEDED+=("$name")
    else
        FAILED+=("$name")
    fi
}

case "$TARGET" in
    engine) run_target "ndr-engine" build_engine ;;
    auth)   run_target "provigil-auth" build_auth ;;
    ui)     run_target "ndr-ui" build_ui ;;
    siem)   run_target "siem-api" build_siem_api ;;
    all)
        run_target "ndr-engine" build_engine
        run_target "provigil-auth" build_auth
        run_target "ndr-ui" build_ui
        run_target "siem-api" build_siem_api
        ;;
    *) die "Unknown target '$TARGET'. Use: engine | auth | ui | all" ;;
esac

if [ "${#FAILED[@]}" -gt 0 ]; then
    printf '\n'
    warn "Partial release — NOT bumping VERSION or committing, so git never claims a release that didn't fully ship."
    [ "${#SUCCEEDED[@]}" -gt 0 ] && warn "Already pushed to the registry at :${NEW_VERSION} and :latest: ${SUCCEEDED[*]}"
    warn "Failed (registry still on the previous version for these): ${FAILED[*]}"
    warn "Fix the issue above, then re-run just the failed target(s), e.g.:"
    for t in "${FAILED[@]}"; do
        case "$t" in
            ndr-engine)    warn "  ./release.sh ${NEW_VERSION} engine" ;;
            provigil-auth) warn "  ./release.sh ${NEW_VERSION} auth" ;;
            ndr-ui)        warn "  ./release.sh ${NEW_VERSION} ui" ;;
            siem-api)      warn "  ./release.sh ${NEW_VERSION} siem" ;;
        esac
    done
    die "Release v${NEW_VERSION} incomplete (${#SUCCEEDED[@]} succeeded, ${#FAILED[@]} failed)."
fi

# ── Bump version in Cargo.toml and VERSION file — only reached once every
# requested target has genuinely built and pushed successfully. ───────────────
log "Bumping version → $NEW_VERSION"
sed -i "s/^version = \".*\"/version = \"${NEW_VERSION}\"/" \
    rust/ndr-engine/Cargo.toml \
    ../wazuh-rust-angular/backend-rust/crates/auth-service/Cargo.toml \
    ../wazuh-rust-angular/backend-rust/crates/provigil-common/Cargo.toml
printf '%s\n' "$NEW_VERSION" > VERSION
ok "VERSION file and Cargo.toml files updated"

# ── Commit version bump ────────────────────────────────────────────────────────
log "Committing version bump..."
git add VERSION rust/ndr-engine/Cargo.toml ../wazuh-rust-angular/backend-rust/crates/auth-service/Cargo.toml ../wazuh-rust-angular/backend-rust/crates/provigil-common/Cargo.toml
git commit -m "$(cat <<EOF
chore: release v${NEW_VERSION}

Powered by PromaSecure
EOF
)"
git push origin "$(git branch --show-current)"
ok "Version bump committed and pushed"

printf '\n\033[0;32mRelease v%s complete.\033[0m\n' "$NEW_VERSION"
printf 'On-premise customers will see the update notification within 6 hours.\n\n'
