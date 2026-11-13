/* Pins SQLite's notion of the current time ('now' in date functions) for
 * differential tests: the default VFS is copied under another name with
 * xCurrentTime / xCurrentTimeInt64 replaced, and registered as the
 * default. Shared by siem-sqlite and the C oracle harness so both sides
 * see the same clock. */
#include "sqlite3.h"

static sqlite3_vfs siem_wrap;
static sqlite3_vfs *siem_orig;
static volatile sqlite3_int64 siem_fixed_ms = -1;

/* Julian day number of the Unix epoch, in milliseconds */
#define SIEM_UNIX_EPOCH_JD_MS 210866760000000LL

static int siem_current_time_int64(sqlite3_vfs *vfs, sqlite3_int64 *now) {
    (void)vfs;
    if (siem_fixed_ms >= 0) {
        *now = siem_fixed_ms + SIEM_UNIX_EPOCH_JD_MS;
        return SQLITE_OK;
    }
    return siem_orig->xCurrentTimeInt64(siem_orig, now);
}

static int siem_current_time(sqlite3_vfs *vfs, double *now) {
    (void)vfs;
    if (siem_fixed_ms >= 0) {
        *now = (double)(siem_fixed_ms + SIEM_UNIX_EPOCH_JD_MS) / 86400000.0;
        return SQLITE_OK;
    }
    return siem_orig->xCurrentTime(siem_orig, now);
}

/* unix_secs < 0 restores the real clock. */
int siem_sqlite_fix_time(sqlite3_int64 unix_secs) {
    if (!siem_orig) {
        if (sqlite3_initialize() != SQLITE_OK) {
            return -1;
        }
        siem_orig = sqlite3_vfs_find(0);
        if (!siem_orig) {
            return -1;
        }
        siem_wrap = *siem_orig;
        siem_wrap.zName = "siem-fixed-time";
        siem_wrap.pNext = 0;
        siem_wrap.xCurrentTime = siem_current_time;
        if (siem_wrap.iVersion >= 2) {
            siem_wrap.xCurrentTimeInt64 = siem_current_time_int64;
        }
        if (sqlite3_vfs_register(&siem_wrap, 1) != SQLITE_OK) {
            return -1;
        }
    }
    siem_fixed_ms = unix_secs < 0 ? -1 : unix_secs * 1000;
    return 0;
}
