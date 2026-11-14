/* Oracle for the analysisd event path: loads the ruleset the way
 * analysisd's main() does (rules linked to active responses), runs each
 * queue message through OS_CleanMSG + DecodeEvent and a transcription of
 * w_process_event_thread (single thread, writers inlined), and writes the
 * real alerts.log / alerts.json / archives.log / archives.json /
 * firewall.log / AR messages.
 *
 * usage: ad_oracle <wazuh-home> < commands     ("A <hex queue message>")
 * Environment: ORACLE_TIME=<epoch> fixes gettime(); run with TZ=UTC.
 * Output on stdout: "=== <name>" followed by each file's content.
 */
#define _GNU_SOURCE /* CPU_COUNT */
#include <sched.h>
#include "shared.h"
#include "analysisd.h"
#include "config.h"
#include "fts.h"
#include "eventinfo.h"
#include "rules.h"
#include "lists.h"
#include "lists_make.h"
#include "accumulator.h"
#include "alerts/alerts.h"
#include "alerts/getloglocation.h"
#include "output/jsonout.h"
#include "logmsg.h"
#include "logtest.h"
#include "active-response.h"
#include "config/global-config.h"
#include "stats.h"
#include "cleanevent.h"
/* the real counters, JSON reports and state file (static functions too) */
#include "state.c"
/* analysisd.c's hot reload (extracted by build.sh) and the analysis socket
 * dispatcher; the internal decoders have nothing to reset here */
#include "hotreload.h"
static pthread_rwlock_t g_hotreload_ruleset_mutex = PTHREAD_RWLOCK_INITIALIZER;
#include "hotreload.inc"
/* shared/json_op.c (verbatim) */
int* json_parse_agents(const cJSON* agents) {
    int *agent_ids = NULL;
    int agents_size = 0;
    int agent_index = 0;
    int error_flag = 0;

    agents_size = cJSON_GetArraySize(agents);

    os_calloc(agents_size + 1, sizeof(int), agent_ids);
    agent_ids[agent_index] = OS_INVALID;

    while(!error_flag && (agent_index < agents_size)) {
        cJSON *agent = cJSON_GetArrayItem(agents, agent_index);
        if (agent->type == cJSON_Number) {
            agent_ids[agent_index] = agent->valueint;
            agent_ids[agent_index + 1] = OS_INVALID;
        } else {
            error_flag = 1;
        }
        agent_index++;
    }

    if (error_flag) {
        os_free(agent_ids);
        return NULL;
    }

    return agent_ids;
}
#include "asyscom.c"
/* the SCA decoder, for its static request queue */
#include "decoders/security_configuration_assessment.c"

/* RequestDBThread's loop body (the thread is not started) */
static void drain_sca(void) {
    char *msg;
    while ((msg = queue_pop(request_queue))) {
            int rc;
            char *agent_id = msg;
            char *dump_db_msg = strchr(msg,':');
            char *dump_db_msg_original = dump_db_msg;

            if(dump_db_msg) {
                *dump_db_msg++ = '\0';
            } else {
                mdebug1("Wrong dump request format: '%s'. Expected ':'", msg);
                goto end;
            }

            mdebug1("Database dump request for agent: %s", agent_id);

            if(strcmp(agent_id,"000") == 0) {
                if(ConnectToSecurityConfigurationAssessmentSocket() == 0){
                    if ((rc = OS_SendUnix(cfga_socket, dump_db_msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            mdebug1("socketerr (not available)");
                            close(cfga_socket);
                        }
                        /* Unable to send. Socket busy */
                        mdebug2("Socket busy, discarding message.");
                    } else {
                        close(cfga_socket);
                    }
                }
            } else {

                /* Send to agent */
                if(!ConnectToSecurityConfigurationAssessmentSocketRemoted()) {
                    *dump_db_msg_original = ':';

                    if ((rc = OS_SendUnix(cfgar_socket, msg, 0)) < 0) {
                        /* Error on the socket */
                        if (rc == OS_SOCKTERR) {
                            mdebug1("socketerr (not available).");
                            close(cfgar_socket);
                        }
                        /* Unable to send. Socket busy */
                        mdebug2("Socket busy, discarding message.");
                    } else {
                        close(cfgar_socket);
                    }
                }
            }
end:
            os_free(msg);
    }
}

/* analysisd.c globals */
const char *__local_name = "wazuh-analysisd";
OSHash *analysisd_agents_state;
w_queue_t *writer_queue, *writer_queue_log, *writer_queue_log_statistical, *writer_queue_log_firewall;
w_queue_t *decode_queue_syscheck_input, *decode_queue_syscollector_input, *decode_queue_rootcheck_input;
w_queue_t *decode_queue_sca_input, *decode_queue_hostinfo_input, *decode_queue_event_input;
w_queue_t *decode_queue_event_output, *decode_queue_winevt_input, *dispatch_dbsync_input, *upgrade_module_input;
int wdbc_connect() { return -1; }
int wdbc_close(int *sock) { return 0; }
int *wdb_get_agents_ids_of_current_node(const char *connection_status, int *sock, int last_id, int limit) {
    int *a = malloc(5 * sizeof(int));
    a[0] = 1;
    a[1] = 2;
    a[2] = 3;
    a[3] = 4;
    a[4] = -1;
    return a;
}
/* mitre.c's wazuh-db: a small fixed MITRE matrix (mirrored by the test).
 * The last technique has no phases: mitre_load fails there and keeps the
 * techniques loaded before it. */
#include "mitre.h"
#include <openssl/evp.h>
#include <openssl/sha.h>
static const char *fake_mitre(const char *q) {
    static char buf[512];
    const char *p;
    if (strstr(q, "OFFSET 0;")) {
        return "[{\"id\":\"ap-1\",\"name\":\"Password Guessing\",\"external_id\":\"T1110.001\"},"
               "{\"id\":\"ap-2\",\"name\":\"SSH\",\"external_id\":\"T1021.004\"},"
               "{\"id\":\"ap-3\",\"name\":\"Valid Accounts\",\"external_id\":\"T1078\"},"
               "{\"id\":\"ap-4\",\"name\":\"Brute Force\",\"external_id\":\"T1110\"},"
               "{\"id\":\"ap-5\",\"name\":\"Broken\",\"external_id\":\"T1484\"}]";
    }
    if (strstr(q, "OFFSET")) {
        return "[]";
    }
    if (strstr(q, "tech_id = 'ap-1'") || strstr(q, "tech_id = 'ap-4'")) {
        return "[{\"tactic_id\":\"ta-6\"}]";
    }
    if (strstr(q, "tech_id = 'ap-2'")) {
        return "[{\"tactic_id\":\"ta-8\"}]";
    }
    if (strstr(q, "tech_id = 'ap-3'")) {
        return "[{\"tactic_id\":\"ta-1\"},{\"tactic_id\":\"ta-3\"},{\"tactic_id\":\"ta-4\"},{\"tactic_id\":\"ta-5\"}]";
    }
    if (strstr(q, "tech_id = ")) {
        return "[]";
    }
    if ((p = strstr(q, "tactic.id = 'ta-"))) {
        int n = atoi(p + strlen("tactic.id = 'ta-"));
        snprintf(buf, sizeof(buf), "[{\"name\":\"Tactic %d\",\"external_id\":\"TA%04d\"}]", n, n);
        return buf;
    }
    return NULL;
}
int wdbc_connect_with_attempts(int max_attempts) { return 7; }

/* Local component sockets (dbsync answers for agent 000): recorded in
 * out/local.log as "<socket path>|<message>". */
static FILE *local_out;
static const char *local_path;
int OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) {
    local_path = path;
    /* the caller close()s it */
    return open("/dev/null", O_RDONLY);
}
int OS_SendSecureTCP(int sock, uint32_t size, const void *msg) {
    fprintf(local_out, "%s|", local_path);
    fwrite(msg, 1, size, local_out);
    fputc('\n', local_out);
    return 0;
}

/* shared/read-agents.c (verbatim, without the exec branch) */
int send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec)
{
    char agt_msg[OS_MAXSTR + 1];

    if (!exec) {
        snprintf(agt_msg, OS_MAXSTR,
                 "%s %c%c%c %s %s",
                 "(msg_to_agent) []",
                 (agt_id == NULL) ? ALL_AGENTS_C : NONE_C,
                 NO_AR_C,
                 (agt_id != NULL) ? SPECIFIC_AGENT_C : NONE_C,
                 agt_id != NULL ? agt_id : "(null)",
                 msg);

        if ((OS_SendUnix(msocket, agt_msg, 0)) < 0) {
            merror("Error communicating with remoted queue.");
            return (-1);
        }
    }
    return (0);
}

char *agent_file_perm(mode_t mode)
{
    /* rwxrwxrwx0 -> 10 */
    char *permissions;

    os_calloc(10, sizeof(char), permissions);
    permissions[0] = (mode & S_IRUSR) ? 'r' : '-';
    permissions[1] = (mode & S_IWUSR) ? 'w' : '-';
    permissions[2] = (mode & S_ISUID) ? 's' : (mode & S_IXUSR) ? 'x' : '-';
    permissions[3] = (mode & S_IRGRP) ? 'r' : '-';
    permissions[4] = (mode & S_IWGRP) ? 'w' : '-';
    permissions[5] = (mode & S_ISGID) ? 's' : (mode & S_IXGRP) ? 'x' : '-';
    permissions[6] = (mode & S_IROTH) ? 'r' : '-';
    permissions[7] = (mode & S_IWOTH) ? 'w' : '-';
    permissions[8] = (mode & S_ISVTX) ? 't' : (mode & S_IXOTH) ? 'x' : '-';
    permissions[9] = '\0';

    return permissions;
}

int connect_to_remoted()
{
    int arq = -1;

    if ((arq = StartMQ(ARQUEUE, WRITE, 1)) < 0) {
        merror(ARQ_ERROR);
        return (-1);
    }

    return (arq);
}

/* wazuh_db/wdb_shared.c, shared/wazuhdb_op.c (verbatim) */
const char* WDBC_VALID_COMPONENTS[] = {
    [WB_COMP_SYSCOLLECTOR_PROCESSES]            = "syscollector_processes",
    [WB_COMP_SYSCOLLECTOR_PACKAGES]             = "syscollector_packages",
    [WB_COMP_SYSCOLLECTOR_HOTFIXES]             = "syscollector_hotfixes",
    [WB_COMP_SYSCOLLECTOR_PORTS]                = "syscollector_ports",
    [WB_COMP_SYSCOLLECTOR_NETWORK_PROTOCOL]     = "syscollector_network_protocol",
    [WB_COMP_SYSCOLLECTOR_NETWORK_ADDRESS]      = "syscollector_network_address",
    [WB_COMP_SYSCOLLECTOR_NETWORK_IFACE]        = "syscollector_network_iface",
    [WB_COMP_SYSCOLLECTOR_HWINFO]               = "syscollector_hwinfo",
    [WB_COMP_SYSCOLLECTOR_OSINFO]               = "syscollector_osinfo",
    [WB_COMP_SYSCOLLECTOR_USERS]                = "syscollector_users",
    [WB_COMP_SYSCOLLECTOR_GROUPS]               = "syscollector_groups",
    [WB_COMP_SYSCOLLECTOR_BROWSER_EXTENSIONS]   = "syscollector_browser_extensions",
    [WB_COMP_SYSCOLLECTOR_SERVICES]             = "syscollector_services",
    [WB_COMP_SYSCHECK]                          = "syscheck",
    [WB_COMP_FIM_FILE]                          = "fim_file",
    [WB_COMP_FIM_REGISTRY]                      = "fim_registry",
    [WB_COMP_FIM_REGISTRY_KEY]                  = "fim_registry_key",
    [WB_COMP_FIM_REGISTRY_VALUE]                = "fim_registry_value"
};
component_type wdbc_validate_component(const char *component) {
    for (int i = 0; i < WB_COMP_INVALID; i++) {
        if (strcmp(component, WDBC_VALID_COMPONENTS[i]) == 0) {
            return (component_type)i;
        }
    }
    return WB_COMP_INVALID;  // Return invalid if no match is found
}

const char* WDBC_RESULT[] = {
    [WDBC_OK]      = "ok",
    [WDBC_DUE]     = "due",
    [WDBC_ERROR]   = "err",
    [WDBC_IGNORE]  = "ign",
    [WDBC_UNKNOWN] = "unk"
};
int wdbc_parse_result(char *result, char **payload) {

    int retval = WDBC_UNKNOWN;
    char *ptr;

    ptr = strchr(result, ' ');

    if (ptr) {
        *ptr++ = '\0';
    } else {
        ptr = result;
    }

    if (payload) {
        *payload = ptr;
    }

    if (!strcmp(result, WDBC_RESULT[WDBC_OK])) {
        retval = WDBC_OK;
    } else if (!strcmp(result, WDBC_RESULT[WDBC_ERROR])) {
        retval = WDBC_ERROR;
    } else if (!strcmp(result, WDBC_RESULT[WDBC_IGNORE])) {
        retval = WDBC_IGNORE;
    } else if (!strcmp(result, WDBC_RESULT[WDBC_DUE])) {
        retval = WDBC_DUE;
    }

    return retval;
}

/* os_crypto/sha1/sha1_op.c (verbatim) */
void OS_SHA1_Hexdigest(const unsigned char * digest, os_sha1 output) {
    size_t n;

    for (n = 0; n < SHA_DIGEST_LENGTH; n++) {
        sprintf(output + n * 2, "%02x", digest[n]);
    }
}
/* wazuh_db/wdb_shared.c (verbatim) */
 int wdbi_strings_hash(os_sha1 hexdigest, ...) {
    char* parameter = NULL;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digest_size;
    int ret_val = OS_SUCCESS;
    va_list parameters;

    EVP_MD_CTX * ctx = EVP_MD_CTX_create();
    if (!ctx) {
        mdebug2("Failed during hash context creation");
        return OS_INVALID;
    }

    if (1 != EVP_DigestInit(ctx, EVP_sha1()) ) {
        mdebug2("Failed during hash context initialization");
        EVP_MD_CTX_destroy(ctx);
        return OS_INVALID;
    }

    va_start(parameters, hexdigest);

    while(parameter = va_arg(parameters, char*), parameter) {
        if (1 != EVP_DigestUpdate(ctx, parameter, strlen(parameter)) ) {
            mdebug2("Failed during hash context update");
            ret_val = OS_INVALID;
            break;
        }
    }
    va_end(parameters);

    EVP_DigestFinal_ex(ctx, digest, &digest_size);
    EVP_MD_CTX_destroy(ctx);
    if (ret_val != OS_INVALID) {
        OS_SHA1_Hexdigest(digest, hexdigest);
    }

    return ret_val;
 }

/* The syscollector queries ("agent <id> <command> ..."): answered from
 * markers in the query (mirrored by the test). */
static int sysc_query(const char *query) {
    static const char *cmds[] = {"netinfo ", "netproto ", "netaddr ", "osinfo ", "hardware ", "port ",
                                 "package ", "hotfix ", "process ", "dbsync ", NULL};
    const char *sp;
    if (strncmp(query, "agent ", 6) || !(sp = strchr(query + 6, ' '))) {
        return 0;
    }
    for (int i = 0; cmds[i]; i++) {
        if (!strncmp(sp + 1, cmds[i], strlen(cmds[i]))) {
            return 1;
        }
    }
    return 0;
}

/* The fake wazuh-db of the internal decoders (mirrored by the test): every
 * query is recorded in out/wdb.log. */
static FILE *wdb_out;
static OSHash *wdb_seen;
int wdbc_query_ex(int *sock, const char *query, char *response, const int len) {
    fprintf(wdb_out, "%s\n", query);
    if (sysc_query(query)) {
        if (strstr(query, "wdbfail")) {
            return -1;
        }
        snprintf(response, len, "%s",
                 strstr(query, "wdberr") ? "err db" :
                 strstr(query, "wdbbad") ? "bad response" :
                 strstr(query, "wdbok") ? "ok" : "ok done");
        return 0;
    }
    if (strstr(query, " rootcheck save ")) {
        /* the entry without the date: inserted (2) the first time */
        const char *p = strstr(query, " rootcheck save ") + strlen(" rootcheck save ");
        const char *sp = strchr(p, ' ');
        char key[OS_SIZE_6144 + 64];
        snprintf(key, sizeof(key), "%.*s|%s", (int)(strchr(query + 6, ' ') - (query + 6)), query + 6, sp ? sp + 1 : "");
        if (OSHash_Get(wdb_seen, key)) {
            snprintf(response, len, "ok 1");
        } else {
            OSHash_Add(wdb_seen, key, (void *)1);
            snprintf(response, len, "ok 2");
        }
        return 0;
    }
    if (strstr(query, " ciscat save ")) {
        /* refused when the scan has no id */
        snprintf(response, len, strstr(query, " ciscat save NULL|") ? "err no scan id" : "ok");
        return 0;
    }
    if (strstr(query, " save2 ") || strstr(query, " integrity_clear ") || strstr(query, " integrity_check_")) {
        snprintf(response, len, "%s",
                 strstr(query, "Agent404") ? "err Agent not found" :
                 strstr(query, "dberr") ? "err broken" :
                 strstr(query, "noanswer") ? "ok " :
                 strstr(query, "\"checksum\":\"bad") ? "ok checksum_fail" : "ok");
        return 0;
    }
    if (strstr(query, " syscheck load ")) {
        const char *f = strstr(query, " syscheck load ") + 15;
        snprintf(response, len, "%s",
                 strstr(f, "nodb") ? "err db" :
                 strstr(f, "badresp") ? "okay" :
                 strstr(f, "new") ? "ok " :
                 strstr(f, "win") ? "ok 100:|Administrators,0,2032127:S-1-5:S-1-5-18:aaa:bbb:root:root:1600000000:10:ccc:ARCHIVE!0:1600000000" :
                 strstr(f, "same") ? "ok 100:33188:0:0:aaa:bbb:root:root:1600000000:10:ccc" :
                 "ok 100:33188:0:0:aaa:bbb:root:root:1600000000:10:ccc!2:1600000000:/sym\\:old");
        return 0;
    }
    if (strstr(query, " syscheck scan_info_get ")) {
        const char *a = query + 6;
        int start = strstr(query, "start_scan") != NULL;
        snprintf(response, len, "%s",
                 !strncmp(a, "001 ", 4) ? (start ? "ok 5" : "ok 1600000000") :
                 !strncmp(a, "002 ", 4) ? "ok 0" :
                 !strncmp(a, "003 ", 4) ? "err" :
                 (start ? "ok 5" : "ok 1759658401"));
        return 0;
    }
    if (strstr(query, " sca ")) {
        const char *a = strstr(query, " sca ") + 5;
        const char *r = "ok";
        if (!strncmp(a, "query ", 6)) {
            int id = atoi(a + 6);
            r = id == 13 ? "err db" : id % 3 == 0 ? "ok not found" : id % 3 == 1 ? "ok found passed" : "ok found failed";
        } else if (!strncmp(a, "query_scan ", 11)) {
            r = strstr(a, "_new") ? "ok not found" : strstr(a, "bad") ? "err db" : "ok found aaaa 7";
        } else if (!strncmp(a, "query_policy_sha256 ", 20)) {
            r = "ok found hf1";
        } else if (!strncmp(a, "query_policy ", 13)) {
            r = strstr(a, "_new") ? "ok not found" : "ok found";
        } else if (!strncmp(a, "query_results ", 14)) {
            r = strstr(a, "_empty") ? "ok not found" : strstr(a, "bad") ? "err db" : "ok found aaaa";
        } else if (!strncmp(a, "query_policies ", 15)) {
            r = "ok found cis_debian,old_policy,keep_policy";
        } else if (!strncmp(a, "delete_policy ", 14)) {
            r = strstr(a, "keep") ? "err no" : "ok";
        }
        snprintf(response, len, "%s", r);
        return 0;
    }
    snprintf(response, len, "err unknown query");
    return 0;
}
cJSON *wdbc_query_parse_json(int *sock, const char *query, char *response, const int len) {
    const char *r = fake_mitre(query);
    return r ? cJSON_Parse(r) : NULL;
}

struct timespec c_timespec;
/* shared/version_op.c (Linux, CPU_COUNT branch) */
int get_nproc() {
    cpu_set_t set;
    CPU_ZERO(&set);
    if (sched_getaffinity(getpid(), sizeof(set), &set) < 0) {
        return 1;
    }
    return CPU_COUNT(&set);
}

/* stats.c globals (Start_Hour reads them) */
int maxdiff = 0;
int mindiff = 0;
int percent_diff = 20;

static FILE *ar_out;
static FILE *asys_out;
extern FILE *oracle_msgs;

/* exec.c dependencies */
/* queues other than the AR ones get a throwaway fd (the callers close()
 * them); messages to them are recorded in out/mq.log as "<queue>|<msg>" */
static FILE *mq_out;
static const char *mq_key[1024];
int StartMQ(const char *key, short int type, short int n_attempts) {
    if (!strcmp(key, CFGAQUEUE) || !strcmp(key, CFGARQUEUE)) {
        int fd = open("/dev/null", O_RDONLY);
        if (fd >= 0 && fd < 1024) {
            mq_key[fd] = key;
        }
        return fd;
    }
    return 3;
}
int OS_SendUnix(int socket, const char *msg, int size) {
    if (socket >= 0 && socket < 1024 && mq_key[socket]) {
        fprintf(mq_out, "%s|%s\n", mq_key[socket], msg);
        mq_key[socket] = NULL;
        return 0;
    }
    fprintf(ar_out, "%s\n", msg);
    return 0;
}
int OS_CloseSocket(int socket) { return 0; }
char *get_node_name(void) { return strdup("node01"); }
int *wdb_get_agents_by_connection_status(const char *status, int *sock) {
    int *a = malloc(5 * sizeof(int));
    a[0] = 1;
    a[1] = 2;
    a[2] = 3;
    a[3] = 4;
    a[4] = -1;
    return a;
}
cJSON *wdb_get_agent_info(int id, int *sock) { return NULL; }

/* labels.c: agent 000 has the configured labels; the others a version
 * label (004 none) plus a user and a hidden label */
static const char *agent_version(const char *id) {
    if (!strcmp(id, "002")) return "Wazuh v4.1.0";
    if (!strcmp(id, "003")) return "Wazuh v4.2.3";
    if (!strcmp(id, "004")) return NULL;
    return "Wazuh v4.14.7";
}
wlabel_t *labels_find(char *agent_id, int *sock) {
    if (strcmp(agent_id, "000") == 0) {
        return Config.labels;
    }
    size_t n = 0;
    wlabel_t *l = NULL;
    label_flags_t f = { .hidden = 0, .system = 1 };
    const char *v = agent_version(agent_id);
    if (v) {
        l = labels_add(l, &n, "_wazuh_version", v, f, 0);
    }
    f.system = 0;
    l = labels_add(l, &n, "env", "test", f, 0);
    f.hidden = 1;
    l = labels_add(l, &n, "secret", "s3", f, 0);
    return l;
}

static void dump(const char *name) {
    printf("=== %s\n", name);
    FILE *f = fopen(name, "rb");
    if (!f) {
        return;
    }
    char buf[65536];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
        fwrite(buf, 1, n, stdout);
    }
    fclose(f);
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

/* w_writer_log_fts_thread */
static void drain_fts(void) {
    char *l;
    while ((l = queue_pop(writer_queue_log_fts))) {
        w_inc_fts_written();
        FTS_Fprintf(l);
        free(l);
    }
}

static void drain(OSList *list) {
    OSListNode *n;
    while ((n = OSList_GetFirstNode(list))) {
        os_analysisd_log_msg_t *m = n->data;
        os_analysisd_free_log_msg(m);
        OSList_DeleteCurrentlyNode(list);
    }
}

/* AR configuration: <command> and <active-response> blocks of etc/ossec.conf */
static void read_ar(void) {
    OS_XML xml;
    if (OS_ReadXML("etc/ossec.conf", &xml) < 0) {
        return;
    }
    XML_NODE node = OS_GetElementsbyNode(&xml, NULL);
    for (int i = 0; node && node[i]; i++) {
        if (strcmp(node[i]->element, "ossec_config")) {
            continue;
        }
        XML_NODE ch = OS_GetElementsbyNode(&xml, node[i]);
        for (int j = 0; ch && ch[j]; j++) {
            XML_NODE opts = OS_GetElementsbyNode(&xml, ch[j]);
            if (!opts) {
                continue;
            }
            if (!strcmp(ch[j]->element, "global")) {
                /* white lists (and the rest of <global>) */
                Read_Global(&xml, opts, &Config, NULL);
            } else if (!strcmp(ch[j]->element, "rule_test")) {
                Read_Logtest(opts);
            } else if (!strcmp(ch[j]->element, "command")) {
                ReadActiveCommands(opts, ar_commands, active_responses);
            } else if (!strcmp(ch[j]->element, "active-response")) {
                ReadActiveResponses(opts, ar_commands, active_responses);
            }
            OS_ClearNode(opts);
        }
        OS_ClearNode(ch);
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);
}

int main(int argc, char **argv) {
    if (argc < 2 || chdir(argv[1]) != 0) {
        fprintf(stderr, "usage: %s <home>\n", argv[0]);
        return 1;
    }
    /* fresh state: FTS / ignore queues, diffs, outputs */
    if (system("rm -rf queue/fts queue/diff out") != 0) {
        return 1;
    }
    mkdir("etc/shared", 0770);
    mkdir("queue", 0770);
    mkdir("queue/fts", 0770);
    mkdir("out", 0770);
    OSList *list = OSList_Create();
    _Config rs = {0};
    if (!w_logtest_ruleset_load(&rs, list)) {
        fprintf(stderr, "ruleset config failed\n");
        return 1;
    }
    {
        time_t t = w_get_current_time();
        struct tm tm;
        localtime_r(&t, &tm);
        __crt_wday = tm.tm_wday;
    }
    /* GlobalConf defaults (before <global> is read) */
    Config.stats = 4;
    Config.integrity = 8;
    Config.rootcheck = 8;
    Config.hostinfo = 8;
    Config.jsonout_output = 1;
    Config.alerts_log = 1;
    Config.memorysize = 8192;
    Config.mailnotify = -1;
    Config.syscheck_alert_new = 1;
    Config.syscheck_ignore_frequency = 10;
    Config.syscheck_ignore_time = 3600;
    Config.mailbylevel = 7;
    Config.logbylevel = 1;
    Config.label_cache_maxage = 10;
    Config.hide_cluster_info = 1;
    os_calloc(1, sizeof(wlabel_t), Config.labels);
    /* w_logtest_init_parameters */
    w_logtest_conf.enabled = true;
    w_logtest_conf.threads = LOGTEST_THREAD;
    w_logtest_conf.max_sessions = LOGTEST_MAX_SESSIONS;
    w_logtest_conf.session_timeout = LOGTEST_SESSION_TIMEOUT;
    AR_Init();
    /* AR_ReadConfig: reset ar.conf */
    FILE *arf = fopen(DEFAULTAR, "w");
    fprintf(arf, "restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\n"
                 "restart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\n"
                 "restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n");
    fclose(arf);
    read_ar();
    Config.ar = ar_flag == -1 ? 0 : ar_flag;
    /* main(): internal options */
    sys_debug_level = getDefine_Int("analysisd", "debug", 0, 2);
    nofile = getDefine_Int("analysisd", "rlimit_nofile", 1024, 1048576);
    Config.min_rotate_interval = getDefine_Int("analysisd", "min_rotate_interval", 10, 86400);
    Config.label_cache_maxage = getDefine_Int("analysisd", "label_cache_maxage", 0, 60);
    Config.show_hidden_labels = getDefine_Int("analysisd", "show_hidden_labels", 0, 1);
    /* Start_Hour */
    maxdiff = getDefine_Int("analysisd", "stats_maxdiff", 10, 999999);
    mindiff = getDefine_Int("analysisd", "stats_mindiff", 10, 999999);
    percent_diff = getDefine_Int("analysisd", "stats_percent_diff", 5, 9999);
    Config.decoder_order_size = 256;
    Config.memorysize = 8192;
    Config.logbylevel = rs.logbylevel;
    Config.mailbylevel = rs.mailbylevel;
    Config.hide_cluster_info = 1;
    Config.logall = 1;
    Config.logall_json = 1;
    Config.jsonout_output = 1;
    Config.alerts_log = 1;
    Config.logfw = 1;
    Config.stats = 0;
    os_calloc(1, sizeof(wlabel_t), Config.labels);
    snprintf(__shost, sizeof(__shost), "%s", "manager");


    OS_CreateOSDecoderList();
    for (char **f = rs.decoders; f && *f; f++) {
        ReadDecodeXML(*f, &os_analysisd_decoderlist_pn, &os_analysisd_decoderlist_nopn, &os_analysisd_decoder_store, list);
    }
    SetDecodeXML(list, &os_analysisd_decoder_store, &os_analysisd_decoderlist_nopn, &os_analysisd_decoderlist_pn);
    Lists_OP_CreateLists();
    for (char **f = rs.lists; f && *f; f++) {
        Lists_OP_LoadList(*f, &os_analysisd_cdblists, list);
    }
    Lists_OP_MakeAll(0, 0, &os_analysisd_cdblists);
    os_calloc(1, sizeof(EventList), os_analysisd_last_events);
    OS_CreateEventList(Config.memorysize, os_analysisd_last_events);
    Rules_OP_CreateRules();
    for (char **f = rs.includes; f && *f; f++) {
        Rules_OP_ReadRules(*f, &os_analysisd_rulelist, &os_analysisd_cdblists, &os_analysisd_last_events,
                           &os_analysisd_decoder_store, list, true);
    }
    OS_ListLoadRules(&os_analysisd_cdblists, &os_analysisd_cdbrules);
    _setlevels(os_analysisd_rulelist, 0);
    Config.g_rules_hash = OSHash_Create();
    AddHash_Rule(os_analysisd_rulelist);
    drain(list);

    if (!FTS_Init(1, &os_analysisd_fts_list, &os_analysisd_fts_store)) {
        return 1;
    }
    Accumulate_Init(&os_analysisd_acm_store, &os_analysisd_acm_lookups, &os_analysisd_acm_purge_ts);
    OS_InitLog();
    /* analysisd main(): queues, agents state, uptime */
    analysisd_agents_state = OSHash_Create();
    analysisd_state.uptime = time(NULL);
    writer_queue = queue_init(16384);
    writer_queue_log = queue_init(16384);
    writer_queue_log_statistical = queue_init(16384);
    writer_queue_log_firewall = queue_init(16384);
    writer_queue_log_fts = queue_init(16384);
    decode_queue_syscheck_input = queue_init(16384);
    decode_queue_syscollector_input = queue_init(16384);
    decode_queue_rootcheck_input = queue_init(16384);
    decode_queue_sca_input = queue_init(16384);
    decode_queue_hostinfo_input = queue_init(16384);
    decode_queue_winevt_input = queue_init(16384);
    decode_queue_event_input = queue_init(16384);
    decode_queue_event_output = queue_init(16384);
    dispatch_dbsync_input = queue_init(16384);
    upgrade_module_input = queue_init(16384);
    /* w_analysisd_state_main start */
    w_get_initial_queues_size();
    _aflog = fopen("out/alerts.log", "w");
    _jflog = fopen("out/alerts.json", "w");
    _eflog = fopen("out/archives.log", "w");
    _ejflog = fopen("out/archives.json", "w");
    _fflog = fopen("out/firewall.log", "w");
    ar_out = fopen("out/ar.log", "w");
    oracle_msgs = fopen("out/messages.log", "w");
    asys_out = fopen("out/asyscom.log", "w");
    local_out = fopen("out/local.log", "w");
    mq_out = fopen("out/mq.log", "w");
    wdb_out = fopen("out/wdb.log", "w");
    wdb_seen = OSHash_Create();
    /* OS_ReadMSG: the internal decoders */
    RootcheckInit();
    HostinfoInit();
    CiscatInit();
    WinevtInit();
    SecurityConfigurationAssessmentInit();
    SyscollectorInit();
    fim_init();
    /* the syscheck decoder thread's state */
    OSDecoderInfo *fim_decoder;
    _sdb fim_sdb;
    os_calloc(1, sizeof(OSDecoderInfo), fim_decoder);
    sdb_init(&fim_sdb, fim_decoder);
    w_hotreload_fim_registry_decoder(fim_decoder);
    /* analysisd main(): after the ruleset and the queues */
    mitre_load();

    regex_matching decoder_match = { 0 }, rule_match = { 0 };
    int execdq = -1, arq = -1, sock = -1;
    dbsync_context_t dbsync_ctx = { .db_sock = -1, .ar_sock = -1 };
    static char line[1 << 20], msg[1 << 19];
    int idx = -1;
    while (fgets(line, sizeof(line), stdin)) {
        if (line[0] != 'A' && line[0] != 'Q') {
            continue;
        }
        /* progress: the input that crashed is the last one reported */
        fprintf(stderr, "P %d\n", ++idx);
        if (line[0] == 'Q') {
            /* a request on the analysis socket (asyscom_main) */
            char *resp = NULL;
            unhex(line + 2, msg);
            drain_fts();
            asyscom_dispatch(msg, &resp);
            fprintf(asys_out, "%s\n", resp);
            free(resp);
            continue;
        }
        int n = unhex(line + 2, msg);
        drain_fts();
        /* ad_input_main */
        if (strlen(msg) < 4) {
            merror(IMSG_ERROR, msg);
            continue;
        }
        w_add_recv((unsigned long)n);
        w_inc_received_events();
        Eventinfo *lf;
        os_calloc(1, sizeof(Eventinfo), lf);
        os_calloc(Config.decoder_order_size, sizeof(DynamicField), lf->fields);
        Zero_Eventinfo(lf);
        if (OS_CleanMSG(msg, lf) < 0) {
            merror(IMSG_ERROR, msg);
            Free_Eventinfo(lf);
            continue;
        }
        if (msg[0] == SYSCHECK_MQ) {
            /* w_decode_syscheck_thread */
            int res;
            w_inc_modules_syscheck_decoded_events(lf->agent_id);
            lf->decoder_info = fim_decoder;
            if (*lf->log == '{') {
                res = decode_fim_event(&fim_sdb, lf);
            } else {
                res = DecodeSyscheck(lf, &fim_sdb);
            }
            if (res != 1) {
                w_free_event_info(lf);
                continue;
            }
        } else if (msg[0] == UPGRADE_MQ) {
            /* w_dispatch_upgrade_module_thread */
            w_inc_modules_upgrade_decoded_events(lf->agent_id);
            cJSON *message_obj = cJSON_Parse(lf->log);

            if (message_obj) {
                cJSON *message_params = cJSON_GetObjectItem(message_obj, "parameters");

                if (message_params) {
                    int sock = OS_ConnectUnixDomain(WM_UPGRADE_SOCK, SOCK_STREAM, OS_MAXSTR);

                    if (sock == OS_SOCKTERR) {
                        merror("Could not connect to upgrade module socket at '%s'. Error: %s", WM_UPGRADE_SOCK, strerror(errno));
                    } else {
                        int agent = atoi(lf->agent_id);
                        cJSON* agents = cJSON_CreateIntArray(&agent, 1);
                        cJSON_AddItemToObject(message_params, "agents", agents);

                        char *message = cJSON_PrintUnformatted(message_obj);
                        OS_SendSecureTCP(sock, strlen(message), message);
                        os_free(message);

                        close(sock);
                    }
                } else {
                    merror("Could not get parameters from upgrade message: %s", lf->log);
                }
                cJSON_Delete(message_obj);
            } else {
                merror("Could not parse upgrade message: %s", lf->log);
            }

            Free_Eventinfo(lf);
            continue;
        } else if (msg[0] == SYSCOLLECTOR_MQ) {
            /* w_decode_syscollector_thread */
            w_inc_modules_syscollector_decoded_events(lf->agent_id);
            if (!DecodeSyscollector(lf, &sock)) {
                w_free_event_info(lf);
                continue;
            }
        } else if (msg[0] == SCA_MQ) {
            /* w_decode_sca_thread */
            w_inc_modules_sca_decoded_events(lf->agent_id);
            int keep = DecodeSCA(lf, &sock);
            drain_sca();
            if (!keep) {
                w_free_event_info(lf);
                continue;
            }
        } else if (msg[0] == WIN_EVT_MQ) {
            /* w_decode_winevt_thread */
            w_inc_modules_logcollector_eventchannel_decoded_events(lf->agent_id);
            if (DecodeWinevt(lf)) {
                w_free_event_info(lf);
                continue;
            }
        } else if (msg[0] == DBSYNC_MQ) {
            /* w_dispatch_dbsync_thread */
            w_inc_dbsync_decoded_events(lf->agent_id);
            DispatchDBSync(&dbsync_ctx, lf);
            Free_Eventinfo(lf);
            continue;
        } else if (msg[0] == HOSTINFO_MQ) {
            /* w_decode_hostinfo_thread */
            w_inc_modules_logcollector_others_decoded_events(lf->agent_id);
            if (!DecodeHostinfo(lf)) {
                w_free_event_info(lf);
                continue;
            }
        } else if (msg[0] == ROOTCHECK_MQ) {
            /* w_decode_rootcheck_thread */
            w_inc_modules_rootcheck_decoded_events(lf->agent_id);
            if (!DecodeRootcheck(lf)) {
                w_free_event_info(lf);
                continue;
            }
        } else {
            /* w_decode_event_thread */
            if (msg[0] == CISCAT_MQ) {
                w_inc_modules_ciscat_decoded_events(lf->agent_id);
                if (!DecodeCiscat(lf, &sock)) {
                    w_free_event_info(lf);
                    continue;
                }
            } else {
            if (msg[0] == SYSLOG_MQ) {
                w_inc_syslog_decoded_events();
            } else if (msg[0] == LOCALFILE_MQ) {
                w_inc_decoded_by_component_events(extract_module_from_location(lf->location), lf->agent_id);
            }
            DecodeEvent(lf, Config.g_rules_hash, &decoder_match, OS_GetFirstOSDecoder(lf->program_name));
            }
        }

        /* ---- w_process_event_thread ---- */
        Eventinfo *lf_cpy = NULL, *lf_logall = NULL;
        RuleInfo *t_currently_rule = NULL;
        lf->size = strlen(lf->log);
        if (lf->decoder_info->accumulate == 1) {
            lf = Accumulate(lf, &os_analysisd_acm_store, &os_analysisd_acm_lookups, &os_analysisd_acm_purge_ts);
        }
        if (lf->decoder_info->type == FIREWALL) {
            if (Config.logfw) {
                if (!lf->action || !lf->srcip || !lf->dstip || !lf->srcport || !lf->dstport || !lf->protocol) {
                    w_free_event_info(lf);
                    continue;
                }
                os_calloc(1, sizeof(Eventinfo), lf_cpy);
                w_copy_event_for_log(lf, lf_cpy);
                w_inc_firewall_written(lf_cpy->agent_id);
                FW_Log(lf_cpy);
                Free_Eventinfo(lf_cpy);
            }
        }
        lf->labels = labels_find(lf->agent_id, &sock);
        w_inc_processed_events(lf->agent_id);
        RuleNode *rulenode_pt = OS_GetFirstRule();
        int skip = 0;
        do {
            if (lf->decoder_info->type == OSSEC_ALERT) {
                if (!lf->generated_rule) {
                    skip = 1;
                    break;
                }
                t_currently_rule = lf->generated_rule;
            } else if (rulenode_pt->ruleinfo->category != lf->decoder_info->type) {
                continue;
            } else if (t_currently_rule = OS_CheckIfRuleMatch(lf, os_analysisd_last_events, &os_analysisd_cdblists,
                       rulenode_pt, &rule_match, &os_analysisd_fts_list, &os_analysisd_fts_store, true, NULL),
                       !t_currently_rule) {
                continue;
            }
            if (t_currently_rule->level == 0) {
                break;
            }
            if (t_currently_rule->ignore_time) {
                if (t_currently_rule->time_ignored == 0) {
                    t_currently_rule->time_ignored = lf->generate_time;
                } else if ((lf->generate_time - t_currently_rule->time_ignored) < t_currently_rule->ignore_time) {
                    if (lf->prev_rule) {
                        t_currently_rule = (RuleInfo *)lf->prev_rule;
                        w_FreeArray(lf->last_events);
                    } else {
                        break;
                    }
                } else {
                    t_currently_rule->time_ignored = lf->generate_time;
                }
            }
            lf->generated_rule = t_currently_rule;
            if (t_currently_rule->ckignore && IGnore(lf, 0)) {
                lf->generated_rule = NULL;
                break;
            }
            if (t_currently_rule->ignore) {
                AddtoIGnore(lf, 0);
            }
            lf->comment = ParseRuleComment(lf);
            if (t_currently_rule->alert_opts & DO_LOGALERT) {
                os_calloc(1, sizeof(Eventinfo), lf_cpy);
                w_copy_event_for_log(lf, lf_cpy);
                w_inc_alerts_written(lf_cpy->agent_id);
                set_global_alert_second_id(ftell(_aflog));
                OS_Log(lf_cpy, _aflog);
                jsonout_output_event(lf_cpy);
                Free_Eventinfo(lf_cpy);
            }
            if (t_currently_rule->ar) {
                active_response **rule_ar = t_currently_rule->ar;
                while (*rule_ar) {
                    int do_ar = 1;
                    if (lf->dstuser && !OS_PRegex(lf->dstuser, "^[a-zA-Z._0-9@?-]*$")) {
                        mwarn(CRAFTED_USER, lf->dstuser);
                        do_ar = 0;
                    }
                    if (lf->srcip && !OS_PRegex(lf->srcip, "^[a-zA-Z.:_0-9-]*$")) {
                        mwarn(CRAFTED_IP, lf->srcip);
                        do_ar = 0;
                    }
                    if (do_ar) {
                        OS_Exec(&execdq, &arq, &sock, lf, *rule_ar);
                    }
                    rule_ar++;
                }
            }
            if (t_currently_rule->sid_prev_matched) {
                OSListNode *node;
                if (node = OSList_AddData(t_currently_rule->sid_prev_matched, lf), node) {
                    lf->sid_node_to_delete = node;
                }
            } else if (t_currently_rule->group_prev_matched) {
                unsigned int j = 0;
                OSListNode *node;
                os_calloc(t_currently_rule->group_prev_matched_sz, sizeof(OSListNode *), lf->group_node_to_delete);
                while (j < t_currently_rule->group_prev_matched_sz) {
                    if (node = OSList_AddData(t_currently_rule->group_prev_matched[j], lf), node) {
                        lf->group_node_to_delete[j] = node;
                    }
                    j++;
                }
            }
            lf->queue_added = 1;
            os_calloc(1, sizeof(Eventinfo), lf_logall);
            w_copy_event_for_log(lf, lf_logall);
            w_free_event_info(lf);
            OS_AddEvent(lf, os_analysisd_last_events);
            break;
        } while ((rulenode_pt = rulenode_pt->next) != NULL);

        if (!skip) {
            if (!lf_logall) {
                os_calloc(1, sizeof(Eventinfo), lf_logall);
                w_copy_event_for_log(lf, lf_logall);
            }
            w_inc_archives_written(lf_logall->agent_id);
            OS_Store(lf_logall);
            jsonout_output_archive(lf_logall);
            Free_Eventinfo(lf_logall);
        } else if (lf_logall) {
            Free_Eventinfo(lf_logall);
        }
        if (!lf->queue_added) {
            w_free_event_info(lf);
        }
    }
    fclose(_aflog);
    fclose(_jflog);
    fclose(_eflog);
    fclose(_ejflog);
    fclose(_fflog);
    fclose(ar_out);
    fclose(asys_out);
    fclose(local_out);
    fclose(mq_out);
    fclose(wdb_out);
    fclose(oracle_msgs);
    oracle_msgs = NULL;
    drain_fts();
    FTS_Flush();
    /* state reports */
    mkdir("var", 0770);
    mkdir("var/run", 0770);
    w_analysisd_write_state();
    {
        cJSON *j = asys_create_state_json();
        char *t = cJSON_PrintUnformatted(j);
        FILE *f = fopen("out/state.json", "w");
        fprintf(f, "%s\n", t);
        int ids[] = { 1, 2, 3, 4, 5, -1 };
        cJSON *a = asys_create_agents_state_json(ids);
        char *ta = cJSON_PrintUnformatted(a);
        fprintf(f, "%s\n", ta);
        fclose(f);
    }
    {
        /* getconfig sections, in asyscom_getconfig's order */
        cJSON *(*fns[])(void) = { getGlobalConfig, getARManagerConfig, getAlertsConfig, getDecodersConfig,
                                  getRulesConfig, getAnalysisInternalOptions, getARCommandsConfig,
                                  getManagerLabelsConfig, getRuleTestConfig };
        FILE *f = fopen("out/getconfig.json", "w");
        for (size_t i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
            cJSON *j = fns[i]();
            char *t = j ? cJSON_PrintUnformatted(j) : NULL;
            fprintf(f, "%s\n", t ? t : "null");
        }
        fclose(f);
    }
    fflush(NULL);
    dump("out/alerts.log");
    dump("out/alerts.json");
    dump("out/archives.log");
    dump("out/archives.json");
    dump("out/firewall.log");
    dump("out/ar.log");
    dump("out/messages.log");
    dump("etc/shared/ar.conf");
    dump("out/state.json");
    dump("var/run/wazuh-analysisd.state");
    dump("queue/fts/fts-queue");
    dump("out/getconfig.json");
    dump("out/asyscom.log");
    dump("out/wdb.log");
    dump("queue/fts/hostinfo");
    dump("out/local.log");
    dump("out/mq.log");
    return 0;
}
