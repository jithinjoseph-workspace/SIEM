#!/bin/sh
# ProVigil data lake backup and restore. Runs on the data-lake node (where ClickHouse runs),
# daily from cron:   15 2 * * *  /opt/provigil/backup-datalake.sh >> /var/log/provigil-backup.log 2>&1
#
#   backup-datalake.sh                      back up every ProVigil database (ndr, ndr_<tenant>)
#   backup-datalake.sh --restore DAY [DB]   restore DAY's backup (all databases, or one) over the live ones
#   backup-datalake.sh --list               the backups kept
#
# Settings (environment): KEEP_DAYS (14), BACKUP_DIR (/var/lib/clickhouse/backups, ClickHouse's
# allowed backup path; File() paths are relative to it), CH (clickhouse-client command, e.g. "clickhouse-client --password ...").
# Copy BACKUP_DIR off this machine (NAS, other disk): a backup on the same disk does not survive the disk.
set -eu
KEEP_DAYS="${KEEP_DAYS:-14}"
BACKUP_DIR="${BACKUP_DIR:-/var/lib/clickhouse/backups}"
CH="${CH:-clickhouse-client}"
DBS="${DBS:-}"   # tests only: limit to these databases

say() { echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) $*"; }
q() { $CH -q "$1"; }
valid_name() { case "$1" in *[!A-Za-z0-9_-]*|'') return 1;; esac; }

databases() {
    if [ -n "$DBS" ]; then echo "$DBS" | tr ' ' '\n'; return; fi
    q "SELECT name FROM system.databases WHERE name = 'ndr' OR name LIKE 'ndr\\_%' ORDER BY name"
}

backup() {
    day=$(date -u +%Y-%m-%d)
    failed=0
    for db in $(databases); do
        valid_name "$db" || { say "skip odd name $db"; continue; }
        dest="$day/$db"
        [ -d "$BACKUP_DIR/$day/$db" ] && { say "$db: $day already backed up"; continue; }
        status=$(q "BACKUP DATABASE \`$db\` TO File('$dest') FORMAT TSV" | cut -f2)
        if [ "$status" = "BACKUP_CREATED" ]; then
            say "$db: backed up to $BACKUP_DIR/$day/$db"
        else
            say "$db: BACKUP FAILED ($status)"; failed=1
        fi
    done
    # retention: whole days only, named YYYY-MM-DD, never anything else in the folder
    old=$(date -u -d "-$KEEP_DAYS days" +%Y-%m-%d 2>/dev/null || date -u -v-"$KEEP_DAYS"d +%Y-%m-%d)
    for d in "$BACKUP_DIR"/????-??-??; do
        [ -d "$d" ] || continue
        n=$(basename "$d")
        if [ "$n" \< "$old" ]; then rm -rf -- "$d"; say "removed old backup $n"; fi
    done
    return $failed
}

restore() {
    day="$1"; only="${2:-}"
    case "$day" in [0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]) ;; *) say "day must be YYYY-MM-DD"; exit 2;; esac
    [ -d "$BACKUP_DIR/$day" ] || { say "no backup for $day"; exit 2; }
    for path in "$BACKUP_DIR/$day"/*; do
        db=$(basename "$path")
        valid_name "$db" || continue
        [ -n "$only" ] && [ "$db" != "$only" ] && continue
        say "$db: restoring from $day (the live database is replaced)"
        # the live copy is kept first, so a failed restore loses nothing (replicated tables
        # cannot sit beside their restored copy, so it is a backup, not a rename)
        if q "EXISTS DATABASE \`$db\`" | grep -q 1; then
            keep="pre-restore-$(date -u +%Y%m%d%H%M%S)/$db"
            status=$(q "BACKUP DATABASE \`$db\` TO File('$keep') FORMAT TSV" | cut -f2)
            [ "$status" = "BACKUP_CREATED" ] || { say "$db: could not keep the live copy ($status); nothing changed"; exit 1; }
            say "$db: live copy kept in $BACKUP_DIR/$keep"
        fi
        q "DROP DATABASE IF EXISTS \`$db\` SYNC"
        status=$(q "RESTORE DATABASE \`$db\` FROM File('$day/$db') FORMAT TSV" | cut -f2)
        [ "$status" = "RESTORED" ] || { say "$db: RESTORE FAILED ($status)"; exit 1; }
        say "$db: restored"
    done
}

case "${1:-}" in
    --restore) [ $# -ge 2 ] || { echo "usage: $0 --restore YYYY-MM-DD [database]"; exit 2; }; restore "$2" "${3:-}" ;;
    --list) ls -1 "$BACKUP_DIR" 2>/dev/null | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' || true ;;
    '') backup ;;
    *) echo "usage: $0 [--restore YYYY-MM-DD [database] | --list]"; exit 2 ;;
esac
