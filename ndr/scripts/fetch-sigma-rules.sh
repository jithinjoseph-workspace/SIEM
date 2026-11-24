#!/usr/bin/env bash
# Fetch SigmaHQ community network rules into the engine rules directory.
# Only downloads rules the NDR engine can parse (skips aggregation/temporal).
# Usage: ./scripts/fetch-sigma-rules.sh [rules-dir]
#
# Requires: curl, python3 (or jq)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RULES_DIR="${1:-$SCRIPT_DIR/../rust/ndr-engine/rules}"
GITHUB_API="https://api.github.com/repos/SigmaHQ/sigma/contents/rules/network"
GITHUB_ACCEPT="Accept: application/vnd.github.v3+json"
UA="NDR-Engine/1.0 (SigmaHQ community rules sync)"

echo "==> SigmaHQ network rules sync"
echo "    Destination: $RULES_DIR"
mkdir -p "$RULES_DIR"

# Fetch file listing from GitHub API
echo "    Fetching file list from SigmaHQ..."
listing=$(curl -sSf -H "$GITHUB_ACCEPT" -H "User-Agent: $UA" "$GITHUB_API")

# Extract download URLs (python3 fallback to jq)
if command -v python3 &>/dev/null; then
    urls=$(python3 -c "
import sys, json
data = json.loads('''$listing''')
for f in data:
    if isinstance(f, dict) and f.get('type') == 'file':
        url = f.get('download_url', '')
        name = f.get('name', '')
        if (name.endswith('.yml') or name.endswith('.yaml')) and url:
            print(url + ' ' + name)
" 2>/dev/null)
elif command -v jq &>/dev/null; then
    urls=$(echo "$listing" | jq -r '.[] | select(.type=="file") | select(.name | test("\\.ya?ml$")) | [.download_url, .name] | @tsv')
else
    echo "ERROR: python3 or jq required" >&2
    exit 1
fi

if [[ -z "$urls" ]]; then
    echo "    No YAML files found — check GitHub API access"
    exit 1
fi

saved=0
skipped=0

while IFS=' ' read -r url name; do
    [[ -z "$url" || -z "$name" ]] && continue
    dest="$RULES_DIR/community_$name"

    content=$(curl -sSf -H "User-Agent: $UA" "$url" 2>/dev/null) || { ((skipped++)); continue; }

    # Skip rules with unsupported condition types (aggregation/temporal)
    if echo "$content" | grep -qE "^\s+condition:.*count\(|^\s+condition:.*near "; then
        ((skipped++))
        continue
    fi

    echo "$content" > "$dest"
    ((saved++))
done <<< "$urls"

echo ""
echo "==> Done: $saved rules saved, $skipped skipped (unsupported conditions)"
echo "    Run 'curl -X POST http://localhost:8080/api/rules/reload' to hot-reload"
