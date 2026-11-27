#!/bin/sh
# ProVigil data lake (PC 2): installs ClickHouse on Ubuntu 22.04/24.04, open only to the master.
#
#   sudo ./install-datalake.sh --master-ip 192.168.1.10 [--password-file FILE] [--keep-days 14] [--no-firewall] [--with-valkey] [--joining]
#
# --joining: one more data lake node of a running system (with --password-file: the same password as
# the first). It creates no tables: once the master's layout is applied, the master gives it the
# tables and they fill from the other nodes (specs/provigil-nodes.md, N4d).
#
# --with-valkey: also the master's session store (a Windows master: Valkey has no Windows build),
# a Redis-compatible server with a password, port 6379 open to the master only.
#
# Needs next to it (the server kit has them): init.sql, ndr-cluster.xml, ndr-compat-profile.xml,
# backup-datalake.sh. Prints the three settings the master needs (CLICKHOUSE_URL/USER/PASSWORD).
# The password is generated unless --password-file is given; it is shown once and stored only as
# a SHA-256 hash in ClickHouse's settings. Run again safely: every step checks what is there.
set -eu

MASTER_IP=""; PASSWORD_FILE=""; KEEP_DAYS=14; FIREWALL=1; VALKEY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --master-ip) MASTER_IP="${2:-}"; shift 2 ;;
        --password-file) PASSWORD_FILE="${2:-}"; shift 2 ;;
        --keep-days) KEEP_DAYS="${2:-}"; shift 2 ;;
        --no-firewall) FIREWALL=0; shift ;;
        --with-valkey) VALKEY=1; shift ;;
        --joining) JOINING=1; shift ;;
        *) echo "unknown option $1"; exit 2 ;;
    esac
done

say() { echo "[provigil] $*"; }
die() { echo "[provigil] ERROR: $*" >&2; exit 1; }

[ "$(id -u)" = 0 ] || die "run as root (sudo)"
. /etc/os-release 2>/dev/null || true
[ "${ID:-}" = ubuntu ] || die "Ubuntu is required (found ${ID:-unknown})"
# an IPv4 address: each part 0-255 (it goes into the firewall and the settings file)
echo "$MASTER_IP" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$' || die "--master-ip must be the master's IPv4 address"
for p in $(echo "$MASTER_IP" | tr . ' '); do [ "$p" -le 255 ] || die "--master-ip is not a valid address"; done
case "$KEEP_DAYS" in ''|*[!0-9]*) die "--keep-days must be a number";; esac

HERE=$(cd "$(dirname "$0")" && pwd)
FILES="$HERE"; [ -f "$FILES/init.sql" ] || FILES="$HERE/../../../clickhouse"
for f in init.sql ndr-cluster.xml ndr-compat-profile.xml; do [ -f "$FILES/$f" ] || die "$f not found next to this script"; done
[ -f "$HERE/backup-datalake.sh" ] || die "backup-datalake.sh not found next to this script"

# 1. ClickHouse from its own signed package repository
if ! command -v clickhouse-server >/dev/null 2>&1; then
    say "installing ClickHouse"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q
    apt-get install -y -q apt-transport-https ca-certificates curl gnupg
    curl -fsSL 'https://packages.clickhouse.com/rpm/lts/repodata/repomd.xml.key' | gpg --dearmor --yes -o /usr/share/keyrings/clickhouse-keyring.gpg
    echo "deb [signed-by=/usr/share/keyrings/clickhouse-keyring.gpg arch=$(dpkg --print-architecture)] https://packages.clickhouse.com/deb lts main" > /etc/apt/sources.list.d/clickhouse.list
    apt-get update -q
    apt-get install -y -q clickhouse-server clickhouse-client
else
    say "ClickHouse is already installed"
fi

# 2. the ProVigil user: a random password unless one is given
if [ -n "$PASSWORD_FILE" ]; then
    PASSWORD=$(head -n1 "$PASSWORD_FILE")
elif [ -f /etc/clickhouse-server/users.d/provigil.xml ]; then
    PASSWORD=""   # already installed: keep the existing password (only its hash is stored)
else
    PASSWORD=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
fi
[ -z "$PASSWORD" ] || [ ${#PASSWORD} -ge 16 ] || die "the password must have at least 16 characters"

cp "$FILES/ndr-cluster.xml" /etc/clickhouse-server/config.d/ndr-cluster.xml
cp "$FILES/ndr-compat-profile.xml" /etc/clickhouse-server/users.d/ndr-compat-profile.xml
cat > /etc/clickhouse-server/config.d/provigil-listen.xml <<'EOF'
<clickhouse>
    <!-- reachable from the master; the firewall and the user's networks limit who connects -->
    <listen_host>0.0.0.0</listen_host>
</clickhouse>
EOF
if [ -n "$PASSWORD" ]; then
    HASH=$(printf '%s' "$PASSWORD" | sha256sum | cut -d' ' -f1)
    cat > /etc/clickhouse-server/users.d/provigil.xml <<EOF
<clickhouse>
    <users>
        <provigil>
            <password_sha256_hex>$HASH</password_sha256_hex>
            <networks>
                <ip>$MASTER_IP</ip>
                <ip>127.0.0.1</ip>
                <ip>::1</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </provigil>
        <!-- the built-in user: this machine only (backups run as it) -->
        <default>
            <networks replace="replace">
                <ip>127.0.0.1</ip>
                <ip>::1</ip>
            </networks>
        </default>
    </users>
</clickhouse>
EOF
fi
chown -R clickhouse:clickhouse /etc/clickhouse-server/config.d /etc/clickhouse-server/users.d

# 3. start, then the schema (every statement is IF NOT EXISTS)
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl enable clickhouse-server >/dev/null 2>&1 || true
    systemctl restart clickhouse-server
else
    die "systemd is required"
fi
i=0; until clickhouse-client -q "SELECT 1" >/dev/null 2>&1; do i=$((i+1)); [ $i -lt 60 ] || die "ClickHouse did not start (journalctl -u clickhouse-server)"; sleep 1; done
if [ "${JOINING:-0}" = 1 ]; then
    say "joining data lake node: no tables now; the master creates them once this node has its layout"
else
clickhouse-client --multiquery < "$FILES/init.sql"
# the NDR module's schema, when the installer kit has it (after the SIEM one: the shared users and
# tenants tables then get the NDR columns; every statement is IF NOT EXISTS)
if [ -f "$FILES/ndr-init.sql" ]; then clickhouse-client --multiquery < "$FILES/ndr-init.sql" >/dev/null; fi
fi
say "schema ready: $(clickhouse-client -q "SELECT count() FROM system.tables WHERE database = 'ndr'") tables in ndr"

# 3b. the session store of a Windows master (--with-valkey): password kept across reinstalls
VK_PASS=""
if [ "$VALKEY" = 1 ]; then
    command -v redis-server >/dev/null 2>&1 || apt-get install -y -q redis-server >/dev/null
    VK_PASS=$(sed -n 's/^requirepass //p' /etc/redis/provigil.conf 2>/dev/null | head -1)
    [ -n "$VK_PASS" ] || VK_PASS=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')
    printf 'bind 0.0.0.0\nprotected-mode yes\nrequirepass %s\n' "$VK_PASS" > /etc/redis/provigil.conf
    chown redis:redis /etc/redis/provigil.conf; chmod 640 /etc/redis/provigil.conf
    grep -q '^include /etc/redis/provigil.conf' /etc/redis/redis.conf || echo 'include /etc/redis/provigil.conf' >> /etc/redis/redis.conf
    systemctl enable redis-server >/dev/null 2>&1 || true
    systemctl restart redis-server
    i=0; until redis-cli -a "$VK_PASS" --no-auth-warning ping 2>/dev/null | grep -q PONG; do i=$((i+1)); [ $i -lt 30 ] || die "the session store did not start (journalctl -u redis-server)"; sleep 1; done
    say "session store ready (port 6379, password set)"
fi

# 4. firewall: SSH stays open, 8123 only from the master
if [ "$FIREWALL" = 1 ]; then
    command -v ufw >/dev/null 2>&1 || apt-get install -y -q ufw
    ufw allow OpenSSH >/dev/null
    ufw allow from "$MASTER_IP" to any port 8123 proto tcp >/dev/null
    [ "$VALKEY" = 1 ] && ufw allow from "$MASTER_IP" to any port 6379 proto tcp >/dev/null
    ufw --force enable >/dev/null
    say "firewall: SSH open, ClickHouse 8123 only from $MASTER_IP"
fi

# 5. daily backups at 02:15
install -d -m 755 /opt/provigil
install -m 755 "$HERE/backup-datalake.sh" /opt/provigil/backup-datalake.sh
echo "15 2 * * * root KEEP_DAYS=$KEEP_DAYS /opt/provigil/backup-datalake.sh >> /var/log/provigil-backup.log 2>&1" > /etc/cron.d/provigil-backup
chmod 644 /etc/cron.d/provigil-backup
say "daily backup at 02:15 into /var/lib/clickhouse/backups, kept $KEEP_DAYS days (copy that folder off this machine)"

IP=$(hostname -I 2>/dev/null | awk '{print $1}')
say "done. Settings for the master's .env:"
echo "CLICKHOUSE_URL=http://${IP:-<this machine>}:8123"
echo "CLICKHOUSE_USER=provigil"
[ "$VALKEY" = 1 ] && echo "VALKEY_URL=redis://:$VK_PASS@${IP:-<this machine>}:6379"
if [ -n "$PASSWORD" ] && [ -z "$PASSWORD_FILE" ]; then
    echo "CLICKHOUSE_PASSWORD=$PASSWORD"
    say "the password is shown only now: put it in the master's .env, then clear this screen"
elif [ -z "$PASSWORD" ]; then
    say "the existing password was kept"
fi
