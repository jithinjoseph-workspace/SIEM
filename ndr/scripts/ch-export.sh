#!/bin/bash
# Export ALL NDR ClickHouse databases (ndr + all ndr_* tenant DBs)
# Run this while host ClickHouse is still running.
# Output goes to /home/user/ch-export/

set -e
EXPORT_DIR="/home/user/ch-export"
mkdir -p "$EXPORT_DIR"

CH_USER="ndr"
# Password comes from the environment or the install's .env - never hardcoded.
# (Migrating from an OLD host ClickHouse that still uses a different password?
#  run:  CLICKHOUSE_PASSWORD='that-password' ./scripts/ch-export.sh)
CH_PASS="${CLICKHOUSE_PASSWORD:-$(grep '^CLICKHOUSE_PASSWORD=' "$(dirname "$0")/../.env" 2>/dev/null | cut -d= -f2-)}"
[ -n "$CH_PASS" ] || { echo "ERROR: CLICKHOUSE_PASSWORD not set and not found in .env" >&2; exit 1; }
CH_DEFAULT_USER="default"

log()  { echo -e "\033[0;32m[EXPORT]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }

# ── Discover all NDR databases ────────────────────────────────────────
DATABASES=$(clickhouse-client --user="$CH_DEFAULT_USER" \
    --query "SELECT name FROM system.databases WHERE name = 'ndr' OR name LIKE 'ndr\_%'" \
    2>/dev/null)

log "Found databases: $(echo $DATABASES | tr '\n' ' ')"

for DB in $DATABASES; do
    log "━━━ Exporting database: $DB ━━━"
    mkdir -p "$EXPORT_DIR/$DB"

    # ── Export CREATE DATABASE statement ──────────────────────────────
    echo "CREATE DATABASE IF NOT EXISTS $DB;" > "$EXPORT_DIR/$DB/_create_db.sql"

    # ── Discover tables in this database ─────────────────────────────
    TABLES=$(clickhouse-client --user="$CH_DEFAULT_USER" \
        --query "SHOW TABLES FROM $DB" 2>/dev/null)

    for TABLE in $TABLES; do
        # ── Export CREATE TABLE schema ────────────────────────────────
        clickhouse-client --user="$CH_DEFAULT_USER" \
            --query "SHOW CREATE TABLE $DB.$TABLE" \
            2>/dev/null \
            > "$EXPORT_DIR/$DB/${TABLE}.sql" || warn "Schema failed: $DB.$TABLE"

        # ── Export data in Native format ──────────────────────────────
        ROW_COUNT=$(clickhouse-client --user="$CH_USER" --password="$CH_PASS" \
            --query "SELECT count() FROM $DB.$TABLE" 2>/dev/null || echo "0")

        if [ "$ROW_COUNT" = "0" ]; then
            log "  $TABLE — empty, skipping data export"
            touch "$EXPORT_DIR/$DB/${TABLE}.native"
        else
            log "  $TABLE — $ROW_COUNT rows"
            clickhouse-client --user="$CH_USER" --password="$CH_PASS" \
                --query "SELECT * FROM $DB.$TABLE FORMAT Native" \
                > "$EXPORT_DIR/$DB/${TABLE}.native" \
                2>/dev/null || warn "Data export failed: $DB.$TABLE"
        fi
    done

    log "✅ $DB done"
done

log ""
log "Export complete. Files:"
du -sh "$EXPORT_DIR"/*/
echo ""
echo "Total:"
du -sh "$EXPORT_DIR"
