#!/bin/bash
# Import ALL NDR ClickHouse databases into the containerized ClickHouse.
# Run AFTER: host ClickHouse is stopped, container is healthy.
# Uses exported files from /home/user/ch-export/

set -e
EXPORT_DIR="/home/user/ch-export"
INIT_SQL="/home/user/Music/NDR/NDR-Demo/config/clickhouse/init.sql"
CONTAINER="clickhouse"
CH_USER="ndr"
# Password comes from the environment or the install's .env - never hardcoded.
# (Migrating from an OLD host ClickHouse that still uses a different password?
#  run:  CLICKHOUSE_PASSWORD='that-password' ./scripts/ch-import.sh)
CH_PASS="${CLICKHOUSE_PASSWORD:-$(grep '^CLICKHOUSE_PASSWORD=' "$(dirname "$0")/../.env" 2>/dev/null | cut -d= -f2-)}"
[ -n "$CH_PASS" ] || { echo "ERROR: CLICKHOUSE_PASSWORD not set and not found in .env" >&2; exit 1; }

log()  { echo -e "\033[0;32m[IMPORT]\033[0m $1"; }
warn() { echo -e "\033[1;33m[WARN]\033[0m $1"; }

ch() {
    docker exec -i "$CONTAINER" \
        clickhouse-client --user="$CH_USER" --password="$CH_PASS" "$@"
}

# ── Wait for container to be healthy ─────────────────────────────────
log "Waiting for ClickHouse container to be healthy..."
for i in {1..30}; do
    if docker exec "$CONTAINER" wget --spider -q http://localhost:8123/ping 2>/dev/null; then
        log "✅ ClickHouse is ready"
        break
    fi
    echo -n "."
    sleep 3
done
echo ""

# ── Verify ndr user can connect ───────────────────────────────────────
if ! docker exec "$CONTAINER" \
    clickhouse-client --user="$CH_USER" --password="$CH_PASS" \
    --query "SELECT 1" > /dev/null 2>&1; then
    echo "[ERROR] Cannot connect as ndr user."
    exit 1
fi
log "✅ Connected as ndr user"

# ── Create schema for a tenant database using init.sql as template ────
create_tenant_schema() {
    local DB="$1"
    # Replace all occurrences of "ndr." with "<tenant_db>." in init.sql
    # This works because all tenant DBs share the same schema as ndr
    sed "s/\bndr\./$(echo "$DB" | sed 's/[[\.*^$()+?{}|]/\\&/g')./g" "$INIT_SQL" \
        | sed "s/CREATE DATABASE IF NOT EXISTS ndr;/CREATE DATABASE IF NOT EXISTS $DB;/" \
        | ch 2>/dev/null || true
}

# ── Import each exported database ────────────────────────────────────
for DB_DIR in "$EXPORT_DIR"/*/; do
    DB=$(basename "$DB_DIR")
    log "━━━ Importing database: $DB ━━━"

    # Create the database
    ch --query "CREATE DATABASE IF NOT EXISTS $DB" 2>/dev/null || true

    if [ "$DB" = "ndr" ]; then
        # ndr schema already created by init.sql entrypoint — skip schema step
        log "  (schema already created by container init)"
    else
        # Tenant databases: use init.sql as template with DB name substituted
        log "  Creating schema from init.sql template..."
        create_tenant_schema "$DB"
    fi

    # Import data
    IMPORTED=0
    SKIPPED=0
    FAILED=0
    for NATIVE_FILE in "$DB_DIR"*.native; do
        [ -f "$NATIVE_FILE" ] || continue
        TABLE=$(basename "$NATIVE_FILE" .native)
        SIZE=$(stat -c%s "$NATIVE_FILE" 2>/dev/null || echo 0)

        if [ "$SIZE" -eq 0 ]; then
            SKIPPED=$((SKIPPED + 1))
            continue
        fi

        if ch --query "INSERT INTO $DB.$TABLE FORMAT Native" \
            < "$NATIVE_FILE" 2>/dev/null; then
            log "  ✅ $TABLE — $(du -sh "$NATIVE_FILE" | cut -f1)"
            IMPORTED=$((IMPORTED + 1))
        else
            warn "  ⚠️  $TABLE — import failed"
            FAILED=$((FAILED + 1))
        fi
    done
    log "  imported: $IMPORTED  skipped(empty): $SKIPPED  failed: $FAILED"
done

# ── Row count verification ────────────────────────────────────────────
log ""
log "Row count verification:"
for DB_DIR in "$EXPORT_DIR"/*/; do
    DB=$(basename "$DB_DIR")
    echo "  ── $DB ──"
    for NATIVE_FILE in "$DB_DIR"*.native; do
        [ -f "$NATIVE_FILE" ] || continue
        SIZE=$(stat -c%s "$NATIVE_FILE" 2>/dev/null || echo 0)
        [ "$SIZE" -eq 0 ] && continue
        TABLE=$(basename "$NATIVE_FILE" .native)
        COUNT=$(ch --query "SELECT count() FROM $DB.$TABLE" 2>/dev/null || echo "ERROR")
        printf "    %-35s %s rows\n" "$TABLE" "$COUNT"
    done
done

log ""
log "✅ Import complete. Run ./start.sh to bring up the full stack."
