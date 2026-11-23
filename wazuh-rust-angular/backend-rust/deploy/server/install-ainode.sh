#!/bin/sh
# ProVigil AI node (PC 3): a local model server (Ollama) on Ubuntu, open only to the master.
#
#   sudo ./install-ainode.sh --master-ip 192.168.1.10 [--model gpt-oss:20b] [--ollama-version 0.x.y] [--no-firewall]
#
# Then, in the console (Admin > AI providers): type openai, base URL http://<this PC>:11434,
# the model name, no key, priority 1. Ollama keeps no prompts or answers: logs sent for
# analysis stay on this PC only while they are being answered.
# A GPU with about 16 GB of memory runs gpt-oss:20b; without a GPU pick a small model.
set -eu

MASTER_IP=""; MODEL="gpt-oss:20b"; OLLAMA_VER=""; FIREWALL=1
while [ $# -gt 0 ]; do
    case "$1" in
        --master-ip) MASTER_IP="${2:-}"; shift 2 ;;
        --model) MODEL="${2:-}"; shift 2 ;;
        --ollama-version) OLLAMA_VER="${2:-}"; shift 2 ;;
        --no-firewall) FIREWALL=0; shift ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done

say() { echo "[provigil] $*"; }
die() { echo "[provigil] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
. /etc/os-release 2>/dev/null || true
[ "${ID:-}" = ubuntu ] || die "Ubuntu is required (found ${ID:-unknown})"
echo "$MASTER_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || die "--master-ip must be the master's IPv4 address"
for p in $(echo "$MASTER_IP" | tr . ' '); do [ "$p" -le 255 ] || die "--master-ip is not a valid address"; done
# a model name goes into a command line and a JSON body: letters, digits and . : _ / - only
echo "$MODEL" | grep -Eq '^[A-Za-z0-9._:/-]{1,100}$' || die "--model has characters a model name cannot have"
[ -z "$OLLAMA_VER" ] || echo "$OLLAMA_VER" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || die "--ollama-version must look like 0.12.3"
[ -d /run/systemd/system ] || die "systemd is required"

if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1; then
    say "GPU: $(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader | head -n1)"
else
    say "no NVIDIA GPU found: the model runs on the CPU, slowly; consider a small model (--model qwen2.5:7b)"
fi

# 1. Ollama (its own installer: binary, service user, GPU libraries when a GPU is present)
if ! command -v ollama >/dev/null 2>&1; then
    # its installer needs curl and zstd (the release archive is zstd-compressed)
    if ! command -v curl >/dev/null 2>&1 || ! command -v zstd >/dev/null 2>&1; then apt-get update -q && apt-get install -y -q curl ca-certificates zstd; fi
    say "installing Ollama ${OLLAMA_VER:-latest}"
    curl -fsSL https://ollama.com/install.sh -o /tmp/ollama-install.sh
    OLLAMA_VERSION="$OLLAMA_VER" sh /tmp/ollama-install.sh
    rm -f /tmp/ollama-install.sh
else
    say "Ollama is already installed ($(ollama --version 2>/dev/null | tail -n1))"
fi

# 2. listen on the network (the firewall limits it to the master); keep the model loaded
install -d /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/provigil.conf <<'EOF'
[Service]
Environment="OLLAMA_HOST=0.0.0.0:11434"
Environment="OLLAMA_KEEP_ALIVE=24h"
EOF
systemctl daemon-reload
systemctl enable ollama >/dev/null 2>&1 || true
systemctl restart ollama
i=0; until curl -fs http://127.0.0.1:11434/api/version >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ] || die "Ollama did not start (journalctl -u ollama)"; sleep 1; done

# 3. the model
say "downloading the model $MODEL (several GB for large models)"
OLLAMA_HOST=127.0.0.1:11434 ollama pull "$MODEL"

# 4. firewall: SSH stays open, 11434 only from the master
if [ "$FIREWALL" = 1 ]; then
    command -v ufw >/dev/null 2>&1 || apt-get install -y -q ufw
    ufw allow OpenSSH >/dev/null
    ufw allow from "$MASTER_IP" to any port 11434 proto tcp >/dev/null
    ufw --force enable >/dev/null
    say "firewall: SSH open, model server 11434 only from $MASTER_IP"
fi

# 5. the same call ProVigil makes (OpenAI format, no key)
say "test question through the OpenAI-format address ProVigil uses"
ANSWER=$(curl -fsS -m 300 http://127.0.0.1:11434/v1/chat/completions -H 'Content-Type: application/json' \
    -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word OK.\"}],\"max_tokens\":200}") || die "the test question failed"
echo "$ANSWER" | grep -q '"content"' || die "unexpected answer: $ANSWER"
say "the model answered"

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
say "done. In the console, Admin > AI providers > add:"
echo "  name: local-ai   type: openai   base URL: http://${IP:-<this machine>}:11434   model: $MODEL   key: (empty)   priority: 1"
