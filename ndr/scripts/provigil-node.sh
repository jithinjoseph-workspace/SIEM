#!/bin/bash
# ProVigil node (specs/provigil-nodes.md, N2): joins an AI or data lake box (Ubuntu or macOS) to its
# master and reports the box's health every 10 s. The join token is never sent: requests are signed
# with it (HMAC-SHA256), and the master's answer is checked the same way.
#
#   provigil-node.sh join --master https://10.10.10.1 --token pvj_... --role ai|datalake [--name N] [--address IP]
#   provigil-node.sh run              # the heartbeat loop (the service runs this)
#   provigil-node.sh install-service  # start at boot: systemd on Linux, launchd on macOS
#   provigil-node.sh beat             # one heartbeat now, with the master's answer (troubleshooting)
#   provigil-node.sh status
set -euo pipefail

OS=$(uname -s)
if [ "$OS" = Darwin ]; then CONF_DIR=/usr/local/etc/provigil; else CONF_DIR=/etc/provigil; fi
CONF="$CONF_DIR/node.conf"
EVERY=10

die() { echo "[provigil-node] ERROR: $*" >&2; exit 1; }
say() { echo "[provigil-node] $*"; }
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is needed"; }
need curl; need openssl

sha256() { printf '%s' "$1" | openssl dgst -sha256 | awk '{print $NF}'; }
hmac() { printf '%s' "$2" | openssl dgst -sha256 -hmac "$1" | awk '{print $NF}'; }
json_field() { printf '%s' "$1" | sed -n "s/.*\"$2\":\"\([^\"]*\)\".*/\1/p"; }

# ── the box ──
cpus() { if [ "$OS" = Darwin ]; then sysctl -n hw.ncpu; else nproc; fi; }
mem_total() { if [ "$OS" = Darwin ]; then sysctl -n hw.memsize; else awk '/^MemTotal:/{print $2*1024}' /proc/meminfo; fi; }
mem_used() {
    if [ "$OS" = Darwin ]; then
        local page; page=$(sysctl -n hw.pagesize)
        vm_stat | awk -v p="$page" '/Pages active|Pages wired down|occupied by compressor/{gsub("\\.","",$NF); s+=$NF} END{printf "%.0f", s*p}'
    else
        awk '/^MemTotal:/{t=$2} /^MemAvailable:/{a=$2} END{printf "%.0f", (t-a)*1024}' /proc/meminfo
    fi
}
data_disk() { if [ "$OS" = Darwin ]; then echo /System/Volumes/Data; else echo /; fi; }
disk_total() { df -kP "$(data_disk)" | awk 'NR==2{printf "%.0f", $2*1024}'; }
disk_used() { df -kP "$(data_disk)" | awk 'NR==2{printf "%.0f", $3*1024}'; }
load() { if [ "$OS" = Darwin ]; then sysctl -n vm.loadavg | awk '{print $2}'; else cut -d' ' -f1 /proc/loadavg; fi; }
platform() { if [ "$OS" = Darwin ]; then echo "macos-$(uname -m)"; else echo "linux-$(uname -m)"; fi; }
first_ip() {
    if [ "$OS" = Darwin ]; then ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true
    else ip -o -4 addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1; fi
}
# the role's own service answers locally
service_up() {
    case "$1" in
        ai) curl -fsS --max-time 3 http://127.0.0.1:11434/api/version >/dev/null 2>&1 ;;
        datalake) [ "$(curl -fsS --max-time 3 'http://127.0.0.1:8123/?query=SELECT%201' 2>/dev/null)" = 1 ] ;;
        *) return 1 ;;
    esac
}

# the master's certificate is ProVigil's own; the signatures, not the certificate, prove who is who
post() { curl -sS -k --max-time 15 -X POST -H 'Content-Type: application/json' "$@"; }

cmd_join() {
    local master="" token="" role="" name="" address=""
    while [ $# -gt 0 ]; do
        case "$1" in
            --master) master="${2:-}"; shift 2 ;; --token) token="${2:-}"; shift 2 ;; --role) role="${2:-}"; shift 2 ;;
            --name) name="${2:-}"; shift 2 ;; --address) address="${2:-}"; shift 2 ;;
            *) die "unknown option $1" ;;
        esac
    done
    [ -n "$master" ] && [ -n "$token" ] || die "join needs --master and --token"
    case "$role" in ai|datalake) ;; *) die "--role must be ai or datalake" ;; esac
    case "$master" in http://*|https://*) ;; *) master="https://$master" ;; esac
    master="${master%/}"
    name="${name:-$(hostname -s)}"; address="${address:-$(first_ip)}"
    echo "$name" | grep -Eq '^[A-Za-z0-9._-]{1,63}$' || die "--name: letters, digits, . _ - only"
    echo "$address" | grep -Eq '^[A-Za-z0-9.:-]{1,100}$' || die "no address found: pass --address <this box's cluster IP>"
    local body time nonce sig answer id proof
    body=$(printf '{"name":"%s","role":"%s","address":"%s","platform":"%s","version":"%s","cpus":%s,"mem_total":%s,"disk_total":%s}' \
        "$name" "$role" "$address" "$(platform)" "${PROVIGIL_VERSION:-}" "$(cpus)" "$(mem_total)" "$(disk_total)")
    time=$(date +%s); nonce=$(openssl rand -hex 16)
    sig=$(hmac "$token" "$(printf 'join\n%s\n%s\n%s' "$time" "$nonce" "$(sha256 "$body")")")
    answer=$(post -H "X-Join-Time: $time" -H "X-Join-Nonce: $nonce" -H "X-Join-Sig: $sig" --data-binary "$body" "$master/api/cluster/join") \
        || die "the master at $master did not answer"
    id=$(json_field "$answer" node_id); proof=$(json_field "$answer" proof)
    [ -n "$id" ] || die "join refused: $answer"
    [ "$proof" = "$(hmac "$token" "$(printf 'joined\n%s\n%s' "$nonce" "$id")")" ] || die "the answer was not signed with this token: not the real master"
    mkdir -p "$CONF_DIR"; umask 077
    printf 'MASTER=%s\nNODE_ID=%s\nSECRET=%s\nROLE=%s\n' "$master" "$id" "$(hmac "$token" "$(printf 'node\n%s' "$nonce")")" "$role" > "$CONF"
    chmod 600 "$CONF"
    say "joined $master as $role node $name ($id); start the heartbeat: $0 install-service"
}

beat_once() {
    # shellcheck disable=SC1090
    . "$CONF"
    local up=false body time sig model=""
    service_up "$ROLE" && up=true
    # an AI node: the model it serves (MODEL= in node.conf, else the first one installed)
    if [ "$ROLE" = ai ] && [ "$up" = true ]; then
        model=${MODEL:-$(curl -fsS --max-time 3 http://127.0.0.1:11434/api/tags 2>/dev/null | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)}
        printf '%s' "$model" | grep -Eq '^[A-Za-z0-9._:/-]{0,100}$' || model=""
    fi
    body=$(printf '{"mem_used":%s,"disk_used":%s,"load":%s,"detail":{"service_up":%s,"model":"%s"}}' "$(mem_used)" "$(disk_used)" "$(load)" "$up" "$model")
    time=$(date +%s)
    sig=$(hmac "$SECRET" "$(printf 'beat\n%s\n%s\n%s' "$NODE_ID" "$time" "$(sha256 "$body")")")
    post -H "X-Node-Id: $NODE_ID" -H "X-Time: $time" -H "X-Sig: $sig" --data-binary "$body" "$MASTER/api/cluster/heartbeat"
}

cmd_run() {
    [ -f "$CONF" ] || die "not joined yet: $0 join ..."
    while true; do
        beat_once >/dev/null 2>&1 || say "heartbeat not delivered (master unreachable?)"
        sleep "$EVERY"
    done
}

cmd_install_service() {
    [ -f "$CONF" ] || die "not joined yet"
    local self; self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
    if [ "$OS" = Darwin ]; then
        local plist=/Library/LaunchDaemons/com.provigil.node.plist
        cat > "$plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>com.provigil.node</string>
  <key>ProgramArguments</key><array><string>/bin/bash</string><string>$self</string><string>run</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardErrorPath</key><string>/var/log/provigil-node.log</string>
</dict></plist>
EOF
        launchctl bootout system "$plist" 2>/dev/null || true
        launchctl bootstrap system "$plist"
    else
        cat > /etc/systemd/system/provigil-node.service <<EOF
[Unit]
Description=ProVigil node heartbeat
After=network-online.target
Wants=network-online.target
[Service]
ExecStart=/bin/bash $self run
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable --now provigil-node.service
    fi
    say "heartbeat service started"
}

case "${1:-}" in
    join) shift; cmd_join "$@" ;;
    run) cmd_run ;;
    beat) [ -f "$CONF" ] || die "not joined yet"; beat_once; echo ;;   # one heartbeat, the master's answer shown
    install-service) cmd_install_service ;;
    status) [ -f "$CONF" ] && grep -v '^SECRET=' "$CONF" || echo "not joined" ;;
    *) sed -n '2,10p' "$0"; exit 2 ;;
esac
