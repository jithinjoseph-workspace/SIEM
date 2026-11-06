/* wazuh-maild oracle: drives the real maild / report functions from commands on stdin.
 * Logs go to $MON_LOG as "LEVEL: msg". Run with the cwd set to a Wazuh home. */
#include "shared.h"
#include "config/config.h"


static FILE *logf_ = NULL;
static int dbg = 0;
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
            if (strcmp(ch[j]->element, "integration") == 0 && (modules & CINTEGRATORD)) r = Read_Integrator(c, d1, d2);
            OS_ClearNode(c);
            if (r < 0) { merror(CONFIG_ERROR, cfgfile); OS_ClearNode(ch); OS_ClearNode(node); OS_ClearXML(&xml); return OS_INVALID; }
        }
        OS_ClearNode(ch);
    }
    OS_ClearNode(node);
    OS_ClearXML(&xml);
    return 0;
}


/* the real daemon's ossec.log, as "LEVEL: msg" in $MON_LOG */
void nowDebug(void) { dbg++; }
void print_header(void) {}
void print_version(void) { exit(0); }
