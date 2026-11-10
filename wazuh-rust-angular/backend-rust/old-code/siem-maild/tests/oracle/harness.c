/* wazuh-maild oracle: drives the real maild / report functions from commands on stdin.
 * Logs go to $MON_LOG as "LEVEL: msg". Run with the cwd set to a Wazuh home. */
#include "shared.h"
#include "config/config.h"
#include "os_maild/maild.h"
#include "os_maild/mail_list.h"
#include "config/reports-config.h"

unsigned int mail_timeout;
unsigned int _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];
MailConfig mail;

static FILE *logf_ = NULL;
static int dbg = 2;
static void vlog(const char *lvl, const char *msg, va_list ap) {
    if (!logf_) { logf_ = fopen(getenv("MON_LOG"), "a"); setvbuf(logf_, NULL, _IONBF, 0); }
    fprintf(logf_, "%s: ", lvl); vfprintf(logf_, msg, ap); fputc('\n', logf_);
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
void nowChroot(void) {}
void nowDaemon(void) {}
int bzip2_uncompress(const char *file, const char *filebz2) { return -1; }

/* config.c's dispatcher, reduced to the sections maild reads. */
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
            if (strcmp(ch[j]->element, "global") == 0 && ((modules & CGLOBAL) || (modules & CMAIL))) r = Read_Global(&xml, c, d1, d2);
            else if (strcmp(ch[j]->element, "email_alerts") == 0 && (modules & CMAIL)) r = Read_EmailAlerts(c, d1, d2);
            OS_ClearNode(c);
            if (r < 0) { merror(CONFIG_ERROR, cfgfile); OS_ClearNode(ch); OS_ClearNode(node); OS_ClearXML(&xml); return OS_INVALID; }
        }
        OS_ClearNode(ch);
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    return 0;
}

static void outb(const char *tag, const char *s) {
    printf("%s ", tag);
    for (const unsigned char *p = (const unsigned char *)s; p && *p; p++) {
        if (*p == '\r') printf("\\r"); else if (*p == '\n') printf("\\n"); else if (*p == '\t') printf("\\t");
        else if (*p == '\\') printf("\\\\"); else putchar(*p);
    }
    putchar('\n');
}

static void show(MailMsg *m, MailMsg *sms) {
    outb("subject", m->subject); outb("body", m->body);
    if (sms) { outb("sms_subject", sms->subject); outb("sms_body", sms->body); }
    printf("priority %d g_level %u\n", mail.priority, _g_subject_level); outb("g_subject", _g_subject);
    printf("gran_set");
    for (int i = 0; mail.gran_to && mail.gran_to[i]; i++) printf(" %d", mail.gran_set[i]);
    printf("\n"); fflush(stdout);
}

int main(void) {
    char line[4096];
    file_queue jq, lq;
    int jopen = 0, lopen = 0;
    MailMsg *last_sms = NULL;
    struct tm tmr; time_t fixed = 1700000000; localtime_r(&fixed, &tmr);
    OS_CreateMailList(MAIL_LIST_SIZE);
    mail_timeout = 0; /* no waiting at the end of alerts.log */
    /* all commands first: forked children must not touch the shared stdin buffer */
    static char *lines[4096]; int nl = 0, li = 0;
    while (nl < 4096 && fgets(line, sizeof(line), stdin)) lines[nl++] = strdup(line);
    while (li < nl) {
        strcpy(line, lines[li++]);
        line[strcspn(line, "\n")] = 0;
        char *arg = strchr(line, ' ');
        if (arg) *arg++ = 0; else arg = "";
        if (!strcmp(line, "config")) {
            fflush(stdout); fflush(logf_ ? logf_ : stdout);
            pid_t p = fork();
            if (p == 0) { exit(MailConf(0, arg, &mail) < 0 ? 1 : 2); }
            int st; waitpid(p, &st, 0);
            printf("config child exit %d\n", WEXITSTATUS(st));
            if (WEXITSTATUS(st) == 2) {
                /* reread in-process (MailConf exit()s when mails are disabled) */
                FILE *devnull = logf_; logf_ = fopen("/dev/null", "w");
                MailConf(0, arg, &mail);
                fclose(logf_); logf_ = devnull;
                mail.strict_checking = getDefine_Int("maild", "strict_checking", 0, 1);
                mail.grouping = getDefine_Int("maild", "grouping", 0, 1);
                mail.subject_full = getDefine_Int("maild", "full_subject", 0, 1);
            }
            fflush(stdout);
        } else if (!strcmp(line, "getconfig")) {
            char *o = NULL; char c[4200]; snprintf(c, sizeof(c), "getconfig %s", arg); if (!*arg) strcpy(c, "getconfig"); mailcom_dispatch(c, &o); outb("getconfig", o); free(o); fflush(stdout);
        } else if (!strcmp(line, "set")) {
            sscanf(arg, "%d %d %d", &mail.strict_checking, &mail.grouping, &mail.subject_full);
        } else if (!strcmp(line, "json")) {
            if (!jopen) { jqueue_init(&jq); jqueue_open(&jq, 0); jopen = 1; }
            MailMsg *sms = NULL;
            MailMsg *m = OS_RecvMailQ_JSON(&jq, &mail, &sms);
            if (!m) { printf("json none\n"); fflush(stdout); continue; }
            show(m, sms);
            if (mail.priority == DONOTGROUP) {}
            OS_AddMailtoList(m);
            if (sms) { if (last_sms) FreeMailMsg(last_sms); last_sms = sms; }
        } else if (!strcmp(line, "log")) {
            if (!lopen) { Init_FileQueue(&lq, &tmr, CRALERT_MAIL_SET | CRALERT_READ_ALL); lopen = 1; }
            MailMsg *sms = NULL;
            MailMsg *m = OS_RecvMailQ(&lq, &tmr, &mail, &sms);
            if (!m) { printf("log none\n"); fflush(stdout); continue; }
            show(m, sms);
            OS_AddMailtoList(m);
            if (sms) { if (last_sms) FreeMailMsg(last_sms); last_sms = sms; }
        } else if (!strcmp(line, "sendmail")) {
            if (!OS_CheckLastMail()) { printf("sendmail empty\n"); fflush(stdout); continue; }
            fflush(stdout);
            pid_t p = fork();
            if (p == 0) { exit(OS_Sendmail(&mail, &tmr) < 0 ? 1 : 0); }
            int st; waitpid(p, &st, 0);
            MailNode *n; while ((n = OS_PopLastMail())) FreeMail(n);
            _g_subject[0] = '\0'; _g_subject_level = 0;
            printf("sendmail %d\n", WEXITSTATUS(st)); fflush(stdout);
        } else if (!strcmp(line, "sms")) {
            if (!last_sms) { printf("sms none\n"); fflush(stdout); continue; }
            printf("sms %d\n", OS_Sendsms(&mail, &tmr, last_sms) < 0 ? 1 : 0); fflush(stdout);
        } else if (!strcmp(line, "custom")) {
            FILE *fp = fopen(arg, "r");
            int r = OS_SendCustomEmail(mail.to, "Daily report: test", mail.smtpserver, mail.from, NULL, mail.idsname, fp, &tmr);
            fclose(fp); printf("custom %d\n", r < 0 ? 1 : 0); fflush(stdout);
        } else if (!strcmp(line, "report")) {
            /* report <alerts file> <name|-> [filter=value | rel:filter=value | showlogs] ... */
            char *file = strtok(arg, " "), *name = strtok(NULL, " "), *tok;
            report_filter f; memset(&f, 0, sizeof(f));
            f.report_type = REPORT_TYPE_DAILY;
            f.report_name = strcmp(name, "-") ? name : NULL;
            while ((tok = strtok(NULL, " "))) {
                if (!strcmp(tok, "showlogs")) { f.show_alerts = 1; continue; }
                char *eq = strchr(tok, '='); *eq = 0;
                if (!strncmp(tok, "rel:", 4)) os_report_configfilter(tok + 4, eq + 1, &f, REPORT_RELATED);
                else os_report_configfilter(tok, eq + 1, &f, REPORT_FILTER);
            }
            os_strdup(file, f.filename);
            static FILE *rep = NULL; if (!rep) rep = tmpfile();
            ftruncate(fileno(rep), 0); rewind(rep); f.fp = rep;
            os_ReportdStart(&f);
            fflush(f.fp); long n = ftell(f.fp); rewind(f.fp);
            char *buf = calloc(n + 1, 1); fread(buf, 1, n, f.fp); outb("report", buf); free(buf);
            fflush(stdout);
        } else if (line[0]) {
            printf("unknown %s\n", line); fflush(stdout);
        }
    }
    return 0;
}
