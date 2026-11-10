/* Oracle for the Rust siem-analysisd crate: drives Wazuh's real logtest
 * pipeline (w_logtest_initialize_session / w_logtest_process_log).
 *
 * usage: logtest_oracle <wazuh-home> < commands
 *   S            start a new session (prints load messages, then "READY")
 *   E <hex>      process one event (location "stdin"); prints
 *                "O <json>", "A <alert flag>", messages "M <lvl> <text>", "END"
 *
 * The ruleset is loaded once; every session runs in a forked child of the
 * process holding that pristine session, so each one starts from scratch
 * (exactly what a new wazuh-logtest session does).
 */
#include "shared.h"
#include "analysisd.h"
#include "config.h"
#include "fts.h"
#include "logtest.h"
#include "logmsg.h"
#include <sys/wait.h>

static void drain(OSList *list) {
    OSListNode *n;
    while ((n = OSList_GetFirstNode(list))) {
        os_analysisd_log_msg_t *m = n->data;
        char *s = os_analysisd_string_log_msg(m);
        printf("M %d %s\n", m->level, s ? s : "");
        os_free(s);
        os_analysisd_free_log_msg(m);
        OSList_DeleteCurrentlyNode(list);
    }
}

static int unhex(const char *h, char *out) {
    int n = 0;
    while (h[0] && h[1] && h[0] != '\n' && h[0] != '\r' && h[0] != ' ') {
        unsigned v;
        sscanf(h, "%2x", &v);
        out[n++] = (char)v;
        h += 2;
    }
    out[n] = 0;
    return n;
}

int main(int argc, char **argv) {
    if (argc < 2 || chdir(argv[1]) != 0) {
        fprintf(stderr, "usage: %s <home>\n", argv[0]);
        return 1;
    }
    setvbuf(stdout, NULL, _IOFBF, 1 << 20);
    Config.decoder_order_size = 256;
    Config.memorysize = 8192;
    Config.logbylevel = 1;
    Config.mailbylevel = 7;
    Config.hide_cluster_info = 1;
    Config.g_rules_hash = OSHash_Create();
    w_logtest_sessions = OSHash_Create();
    snprintf(__shost, sizeof(__shost), "%s", "manager");
    mkdir("queue", 0770);
    mkdir("queue/fts", 0770);
    if (!FTS_Init(1, &os_analysisd_fts_list, &os_analysisd_fts_store)) {
        fprintf(stderr, "FTS_Init failed\n");
        return 1;
    }
    OSList *list_msg = OSList_Create();
    OSList_SetMaxSize(list_msg, 100000);

    size_t cap = 1 << 16, n = 0;
    char **cmds = malloc(cap * sizeof(char *));
    static char line[1 << 20];
    while (fgets(line, sizeof(line), stdin)) {
        if (n == cap) {
            cap *= 2;
            cmds = realloc(cmds, cap * sizeof(char *));
        }
        cmds[n++] = strdup(line);
    }

    w_logtest_conf.enabled = 1;
    w_logtest_conf.threads = 1;
    w_logtest_conf.max_sessions = getenv("ORACLE_MAX_SESSIONS") ? atoi(getenv("ORACLE_MAX_SESSIONS")) : 64;
    w_logtest_conf.session_timeout = 900;

    if (n > 0 && cmds[0][0] == 'R') {
        /* Protocol mode: every line is "R <hex request>", answered by
         * w_logtest_process_request with "P <response>" and "END". */
        w_logtest_connection_t conn;
        memset(&conn, 0, sizeof(conn));
        pthread_mutex_init(&conn.mutex, NULL);
        static char req[1 << 19];
        for (size_t k = 0; k < n; k++) {
            if (cmds[k][0] != 'R') {
                continue;
            }
            unhex(cmds[k] + 2, req);
            char *resp = w_logtest_process_request(req, &conn);
            printf("P %s\nEND\n", resp ? resp : "null");
            free(resp);
            fflush(stdout);
        }
        return 0;
    }

    w_logtest_session_t *base = w_logtest_initialize_session(list_msg);
    static char ev[1 << 19];
    size_t i = 0;
    while (i < n) {
        if (cmds[i][0] != 'S') {
            i++;
            continue;
        }
        size_t j = i + 1;
        while (j < n && cmds[j][0] != 'S') {
            j++;
        }
        fflush(stdout);
        pid_t pid = fork();
        if (pid == 0) {
            drain(list_msg);
            printf(base ? "READY\n" : "FAIL\n");
            for (size_t k = i + 1; k < j && base; k++) {
                if (cmds[k][0] != 'E') {
                    continue;
                }
                unhex(cmds[k] + 2, ev);
                /* optional location after a space */
                char *sp = strchr(cmds[k] + 2, ' ');
                static char loc[1 << 16];
                if (sp) {
                    unhex(sp + 1, loc);
                } else {
                    strcpy(loc, "stdin");
                }
                cJSON *req = cJSON_CreateObject();
                cJSON_AddStringToObject(req, "event", ev);
                cJSON_AddStringToObject(req, "location", loc);
                cJSON_AddStringToObject(req, "log_format", "syslog");
                w_logtest_extra_data_t extra = { .alert_generated = false, .rules_debug_list = NULL };
                cJSON *out = w_logtest_process_log(req, base, &extra, list_msg);
                char *o = out ? cJSON_PrintUnformatted(out) : NULL;
                printf("O %s\nA %d\n", o ? o : "null", extra.alert_generated ? 1 : 0);
                os_free(o);
                cJSON_Delete(out);
                cJSON_Delete(req);
                drain(list_msg);
                printf("END\n");
                fflush(stdout);
            }
            fflush(stdout);
            _exit(0);
        }
        int st;
        waitpid(pid, &st, 0);
        if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
            /* own line: the child may have died in the middle of one */
            printf("\nCRASH %d\n", WIFSIGNALED(st) ? WTERMSIG(st) : -WEXITSTATUS(st));
        }
        i = j;
    }
    fflush(stdout);
    return 0;
}
