/* Differential oracle for wazuh-db: Wazuh's real wazuh_db/ library (every
 * file but main.c) with SQLite 3.50.4, driven like run_worker() drives it.
 *
 * stdin lines:
 *   Q <hex>   a request as read from the socket (run_worker: trailing '\n'
 *             stripped and re-added to the answer, '{' -> wdbcom_dispatch,
 *             else wdb_parse)
 *   T <secs>  move the pinned clock (time(), gettimeofday, SQLite 'now')
 *   G         one run_gc() pass (commit old, fragmentation, close old)
 * stdout lines:
 *   R <hex>   the answer sent to the peer (none when empty)
 *   S <hex>   a message streamed to the peer (wdb_exec_stmt_send "due")
 *   E <n> <hex>  a router publication (n: 1 agent events, 2 inventory)
 *   M <level> <hex>  an error/warning/info log message
 *   P <n>     before each request (progress, for crash recovery)
 * then, after wdb_close_all(), a dump of every database file:
 *   F <path>, then per table "D <name> <hex sql>" and "W <hex row>".
 */
#include "shared.h"
#include "wazuh_db/wdb.h"
#include "wazuh_db/wdb_state.h"
#include <dirent.h>
#include <utime.h>

extern wdb_state_t wdb_state;
int siem_sqlite_fix_time(sqlite3_int64 unix_secs);
extern time_t oracle_clock;

static void hex(FILE *f, const unsigned char *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "%02x", p[i]);
    }
}

static int unhex(const char *s, char *out, size_t max) {
    size_t n = 0;
    while (s[0] && s[1] && n < max) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) {
            break;
        }
        out[n++] = (char)v;
        s += 2;
    }
    return (int)n;
}

/* the router */
int router_provider_send(ROUTER_PROVIDER_HANDLE handle, const char *message, unsigned int message_size) {
    printf("E %ld ", (long)(intptr_t)handle);
    hex(stdout, (const unsigned char *)message, message_size);
    printf("\n");
    return 0;
}

/* the peer socket */
int OS_SetSendTimeout(int socket, int seconds) { return 0; }
int OS_SendSecureTCP(int sock, uint32_t size, const void *msg) {
    printf("S ");
    hex(stdout, msg, size);
    printf("\n");
    return 0;
}

static void dump_value(FILE *f, sqlite3_stmt *st, int i) {
    switch (sqlite3_column_type(st, i)) {
    case SQLITE_INTEGER:
        fprintf(f, "i%lld", (long long)sqlite3_column_int64(st, i));
        break;
    case SQLITE_FLOAT:
        fprintf(f, "f%.17g", sqlite3_column_double(st, i));
        break;
    case SQLITE_NULL:
        fprintf(f, "n");
        break;
    default: {
        const unsigned char *t = sqlite3_column_text(st, i);
        int n = sqlite3_column_bytes(st, i);
        fprintf(f, "t");
        hex(f, t, n);
    }
    }
}

/* every table of a database file, rows in rowid order when there is one */
static void dump_db(const char *path) {
    sqlite3 *db;
    printf("F %s\n", path);
    if (sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, NULL) != SQLITE_OK) {
        printf("X open %s\n", sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return;
    }
    sqlite3_stmt *tables;
    if (sqlite3_prepare_v2(db, "SELECT type, name, IFNULL(sql, '') FROM sqlite_master ORDER BY type, name;", -1, &tables, NULL) != SQLITE_OK) {
        printf("X master %s\n", sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return;
    }
    while (sqlite3_step(tables) == SQLITE_ROW) {
        const char *type = (const char *)sqlite3_column_text(tables, 0);
        const char *name = (const char *)sqlite3_column_text(tables, 1);
        const char *sql = (const char *)sqlite3_column_text(tables, 2);
        printf("D %s %s ", type, name);
        hex(stdout, (const unsigned char *)sql, strlen(sql));
        printf("\n");
        if (strcmp(type, "table") != 0) {
            continue;
        }
        char q[1024];
        sqlite3_stmt *rows;
        snprintf(q, sizeof(q), "SELECT * FROM \"%s\" ORDER BY rowid;", name);
        if (sqlite3_prepare_v2(db, q, -1, &rows, NULL) != SQLITE_OK) {
            snprintf(q, sizeof(q), "SELECT * FROM \"%s\";", name);
            if (sqlite3_prepare_v2(db, q, -1, &rows, NULL) != SQLITE_OK) {
                printf("X rows %s\n", sqlite3_errmsg(db));
                continue;
            }
        }
        while (sqlite3_step(rows) == SQLITE_ROW) {
            printf("W");
            for (int i = 0; i < sqlite3_column_count(rows); i++) {
                printf(" ");
                dump_value(stdout, rows, i);
            }
            printf("\n");
        }
        sqlite3_finalize(rows);
    }
    sqlite3_finalize(tables);
    sqlite3_close_v2(db);
}

static int cmpstr(const void *a, const void *b) { return strcmp(*(char *const *)a, *(char *const *)b); }

/* The backup selection goes by file mtime (real time): the files that
 * appeared during a request get the pinned clock as mtime so both sides
 * see the same times. */
static char *seen_backups[4096];
static int n_seen_backups;
static void pin_new_backups(void) {
    char *now[4096];
    int n = 0;
    DIR *d = opendir(WDB_BACKUP_FOLDER);
    if (!d) {
        return;
    }
    struct dirent *e;
    while ((e = readdir(d)) && n < 4096) {
        if (e->d_name[0] == '.') {
            continue;
        }
        now[n++] = strdup(e->d_name);
        int found = 0;
        for (int i = 0; i < n_seen_backups; i++) {
            if (strcmp(seen_backups[i], e->d_name) == 0) {
                found = 1;
                break;
            }
        }
        if (!found) {
            char p[PATH_MAX];
            snprintf(p, sizeof(p), "%s/%s", WDB_BACKUP_FOLDER, e->d_name);
            struct utimbuf u = { oracle_clock, oracle_clock };
            utime(p, &u);
        }
    }
    closedir(d);
    for (int i = 0; i < n_seen_backups; i++) {
        free(seen_backups[i]);
    }
    memcpy(seen_backups, now, n * sizeof(char *));
    n_seen_backups = n;
}

/* the files of a directory, sorted; databases are dumped, others listed */
static void dump_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        return;
    }
    char *names[4096];
    int n = 0;
    struct dirent *e;
    while ((e = readdir(d)) && n < 4096) {
        if (e->d_name[0] != '.' || strcmp(e->d_name, ".template.db") == 0) {
            if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
                names[n++] = strdup(e->d_name);
            }
        }
    }
    closedir(d);
    qsort(names, n, sizeof(char *), cmpstr);
    for (int i = 0; i < n; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s", dir, names[i]);
        size_t l = strlen(names[i]);
        if (l > 3 && strcmp(names[i] + l - 3, ".db") == 0) {
            dump_db(path);
        } else {
            struct stat st;
            stat(path, &st);
            /* FNV-1a 64 of the content */
            unsigned long long h = 0xcbf29ce484222325ULL;
            FILE *fp = fopen(path, "rb");
            if (fp) {
                int c;
                while ((c = fgetc(fp)) != EOF) {
                    h = (h ^ (unsigned char)c) * 0x100000001b3ULL;
                }
                fclose(fp);
            }
            printf("L %s %lld %016llx\n", path, (long long)st.st_size, h);
        }
        free(names[i]);
    }
}

static void clear_dir(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) {
        return;
    }
    struct dirent *e;
    while ((e = readdir(d))) {
        if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) {
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "%s/%s", dir, e->d_name);
            unlink(path);
        }
    }
    closedir(d);
}

/* The harness as functions, so the HTTP API oracle (http_harness.cpp)
 * drives the same library and line protocol. */
int harness_init(const char *home) {
    if (chdir(home) < 0) {
        return -1;
    }
    const char *t = getenv("ORACLE_TIME");
    oracle_clock = t ? atol(t) : 1759658400;
    siem_sqlite_fix_time(oracle_clock);

    mkdir("queue", 0750);
    mkdir(WDB2_DIR, 0750);
    mkdir(WDB_TASK_DIR, 0750);
    mkdir("backup", 0750);
    mkdir(WDB_BACKUP_FOLDER, 0750);
    clear_dir(WDB2_DIR);
    clear_dir(WDB_TASK_DIR);
    clear_dir(WDB_BACKUP_FOLDER);

    /* main(): internal options (the defaults of internal_options.conf) */
    wconfig.worker_pool_size = 8;
    wconfig.commit_time_min = 10;
    wconfig.commit_time_max = 60;
    wconfig.open_db_limit = 64;
    wconfig.fragmentation_threshold = 75;
    wconfig.fragmentation_delta = 5;
    wconfig.free_pages_percentage = 0;
    wconfig.max_fragmentation = 90;
    wconfig.check_fragmentation_interval = 7200;
    wconfig.is_worker_node = false;
    wdb_init_conf();
    wdb_pool_init();
    router_agent_events_handle = (ROUTER_PROVIDER_HANDLE)1;
    router_inventory_events_handle = (ROUTER_PROVIDER_HANDLE)2;
    wdb_state.uptime = time(NULL);
    wdb_create_profile();
    return 0;
}

/* One T / G / Q line (without the newline). */
void harness_line(char *line) {
    static char buffer[OS_MAXSTR + 1];
    static char response[OS_MAXSTR + 1];
    static long n = 0;
    if (line[0] == 'T' && line[1] == ' ') {
        oracle_clock = atol(line + 2);
        siem_sqlite_fix_time(oracle_clock);
    } else if (line[0] == 'G') {
        wdb_commit_old();
        wdb_check_fragmentation();
        wdb_close_old();
    } else if (line[0] == 'Q' && line[1] == ' ') {
        printf("P %ld\n", n);
        fprintf(stderr, "P %ld\n", n++);
        fflush(stdout);
        /* run_worker reuses its buffer; zero it so bytes past a cut are
         * deterministic (the Rust CBuf pads with zeros) */
        memset(buffer, 0, sizeof(buffer));
        int length = unhex(line + 2, buffer, OS_MAXSTR);
        int terminal;
        if (length > 0 && buffer[length - 1] == '\n') {
            buffer[length - 1] = '\0';
            terminal = 1;
        } else {
            buffer[length] = '\0';
            terminal = 0;
        }
        *response = '\0';
        /* wdb_remove_multiple_agents tests errno without resetting it:
         * a stale ERANGE/EINVAL left by any earlier failing libc call of
         * the worker thread (SQLite I/O included) rejects valid ids.
         * That carry-over is not reproducible, so every request starts
         * clean (the port models errno within a request). */
        errno = 0;
        if (buffer[0] == '{') {
            wdbcom_dispatch(buffer, response);
        } else {
            wdb_parse(buffer, response, 7);
        }
        size_t len = strlen(response);
        if (len > 0) {
            if (terminal && len < OS_MAXSTR - 1) {
                response[len++] = '\n';
            }
            printf("R ");
            hex(stdout, (unsigned char *)response, len);
            printf("\n");
        }
        pin_new_backups();
    }
    fflush(stdout);
}

/* wdb_close_all() and the dump of every database file */
void harness_finish(void) {
    wdb_close_all();
    dump_dir(WDB2_DIR);
    dump_dir(WDB_TASK_DIR);
    dump_dir(WDB_BACKUP_FOLDER);
    fflush(stdout);
}

#ifndef WDB_HARNESS_NO_MAIN
int main(int argc, char **argv) {
    if (argc < 2 || harness_init(argv[1]) < 0) {
        fprintf(stderr, "usage: wdb_oracle <home>\n");
        return 1;
    }
    static char line[3 * OS_MAXSTR + 64];
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = '\0';
        harness_line(line);
    }
    harness_finish();
    return 0;
}
#endif
