/* wazuh-monitord oracle: drives the real monitord functions from commands on stdin.
 * Logs go to $MON_LOG as "LEVEL: msg". Run with the cwd set to a Wazuh home. */
#include "shared.h"
#include "config/config.h"
#include "monitord/monitord.h"

static FILE *logf_ = NULL;
static int dbg = 2;

static void vlog(const char *lvl, const char *msg, va_list ap) {
    if (!logf_) { logf_ = fopen(getenv("MON_LOG"), "a"); setvbuf(logf_, NULL, _IONBF, 0); }
    fprintf(logf_, "%s: ", lvl);
    vfprintf(logf_, msg, ap);
    fputc('\n', logf_);
}
#define DEF(name, lvl, cond) void name(const char *f, int l, const char *fn, const char *msg, ...) { \
    if (!(cond)) return; va_list ap; va_start(ap, msg); vlog(lvl, msg, ap); va_end(ap); }
DEF(_mdebug1, "DEBUG", dbg >= 1)
DEF(_mdebug2, "DEBUG", dbg >= 2)
DEF(_merror, "ERROR", 1)
DEF(_mwarn, "WARNING", 1)
DEF(_minfo, "INFO", 1)
DEF(_mferror, "ERROR", 1)
void _merror_exit(const char *f, int l, const char *fn, const char *msg, ...) {
    va_list ap; va_start(ap, msg); vlog("CRITICAL", msg, ap); va_end(ap); exit(1);
}
void _mverror(const char *f, int l, const char *fn, const char *msg, va_list a) { vlog("ERROR", msg, a); }
void _mvwarn(const char *f, int l, const char *fn, const char *msg, va_list a) { vlog("WARNING", msg, a); }
void _mvinfo(const char *f, int l, const char *fn, const char *msg, va_list a) { vlog("INFO", msg, a); }
int isDebug(void) { return dbg; }
void print_out(const char *msg, ...) {}

/* config.c's dispatcher, reduced to the two sections monitord reads. */
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) {
    OS_XML xml;
    if (OS_ReadXML(cfgfile, &xml) < 0) { merror(XML_ERROR, cfgfile, xml.err, xml.err_line); return OS_INVALID; }
    XML_NODE node = OS_GetElementsbyNode(&xml, NULL);
    for (int i = 0; node && node[i]; i++) {
        if (strcmp(node[i]->element, "ossec_config") != 0) continue;
        XML_NODE ch = OS_GetElementsbyNode(&xml, node[i]);
        for (int j = 0; ch && ch[j]; j++) {
            XML_NODE c = OS_GetElementsbyNode(&xml, ch[j]);
            int r = 0;
            if (strcmp(ch[j]->element, "global") == 0 && (modules & CGLOBAL)) r = Read_Global(&xml, c, d1, d2);
            else if (strcmp(ch[j]->element, "reports") == 0 && (modules & CREPORTS)) r = Read_CReports(c, d1, d2);
            OS_ClearNode(c);
            if (r < 0) { merror(CONFIG_ERROR, cfgfile); OS_ClearNode(ch); OS_ClearNode(node); OS_ClearXML(&xml); return OS_INVALID; }
        }
        OS_ClearNode(ch);
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    return 0;
}

/* generate_reports needs maild/reportd: not part of this oracle. */
void generate_reports(int cday, int cmon, int cyear, const struct tm *p) {}

static void out(const char *s) { printf("%s\n", s); fflush(stdout); }

int main(void) {
    char line[4096];
    mond.a_queue = -1;
    agents_to_alert_hash = OSHash_Create();
    while (fgets(line, sizeof(line), stdin)) {
        line[strcspn(line, "\n")] = 0;
        char *arg = strchr(line, ' ');
        if (arg) *arg++ = 0; else arg = "";
        if (!strcmp(line, "config")) {
            int no_agents = 0, day_wait = -1; char cfg[1024];
            sscanf(arg, "%1023s %d %d", cfg, &no_agents, &day_wait);
            MonitordConfig(cfg, &mond, no_agents, (short)day_wait);
            out("config ok");
        } else if (!strcmp(line, "moncom")) {
            char *o = NULL; char *cmd = strdup(arg);
            moncom_dispatch(cmd, &o); out(o); free(o); free(cmd);
        } else if (!strcmp(line, "queue")) {
            monitor_queue_connect(); printf("queue %s\n", mond.a_queue > 0 ? "up" : "down"); fflush(stdout);
        } else if (!strcmp(line, "disconnect")) {
            monitor_agents_disconnection(); out("disconnect done");
        } else if (!strcmp(line, "alert")) {
            monitor_agents_alert(); out("alert done");
        } else if (!strcmp(line, "delete")) {
            monitor_agents_deletion(); out("delete done");
        } else if (!strcmp(line, "rotate")) {
            int c, k, n, j, d; sscanf(arg, "%d %d %d %d %d", &n, &j, &c, &k, &d);
            w_rotate_log(c, k, n, j, d); out("rotate done");
        } else if (!strcmp(line, "manage")) {
            int d, m, y; sscanf(arg, "%d %d %d", &d, &m, &y);
            mond.compress = 1; manage_files(d, m, y); out("manage done");
        } else if (!strcmp(line, "logs")) {
            char p[PATH_MAX] = LOGFILE, pj[PATH_MAX] = LOGJSONFILE;
            mond.day_wait = 0; monitor_logs(atoi(arg), p, pj); out("logs done");
        } else if (!strcmp(line, "set")) {
            /* set <rotate_log> <size_rotate bytes> <compress> <keep_log_days> <daily_rotations> <monitor_agents> <delete_old_agents> <disc_time> <alert_time> */
            unsigned long sz; int a, b, c, d, e, f, g, h;
            sscanf(arg, "%d %lu %d %d %d %d %d %d %d", &a, &sz, &b, &c, &d, &e, &f, &g, &h);
            mond.rotate_log = a; mond.size_rotate = sz; mond.compress = b; mond.keep_log_days = c; mond.daily_rotations = d;
            mond.monitor_agents = e; mond.delete_old_agents = f; mond.global.agents_disconnection_time = g; mond.global.agents_disconnection_alert_time = h;
            out("set ok");
        } else if (!strcmp(line, "pending")) {
            unsigned int it = 0; int n = 0; OSHashNode *x = OSHash_Begin(agents_to_alert_hash, &it);
            while (x) { n++; x = OSHash_Next(agents_to_alert_hash, &it, x); }
            printf("pending %d\n", n); fflush(stdout);
        } else if (line[0]) {
            printf("unknown %s\n", line); fflush(stdout);
        }
    }
    return 0;
}

void nowChroot(void) {}
void nowDaemon(void) {}
int bzip2_uncompress(const char *file, const char *filebz2) { return -1; }
