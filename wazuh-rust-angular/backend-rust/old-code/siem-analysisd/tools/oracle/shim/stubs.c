/* Link stubs for the analysisd oracle: daemon-only symbols. */
#include "shared.h"
#include "analysisd.h"
#include "config.h"
#include "eventinfo.h"
#include "logtest.h"

#ifndef AD_ORACLE
/* (ad mode links analysisd/config.c and config/logtest-config.c) */
_Config Config;
w_logtest_conf_t w_logtest_conf;
#endif
char __shost[512];

#ifdef AD_ORACLE
/* runtime errors/warnings of the event path (set by ad_harness.c) */
FILE *oracle_msgs;
#endif
static void vlog(const char *lvl, const char *msg, va_list ap) {
#ifdef AD_ORACLE
    if (oracle_msgs && (!strcmp(lvl, "ERROR") || !strcmp(lvl, "WARNING"))) {
        va_list cp;
        va_copy(cp, ap);
        fprintf(oracle_msgs, "%s: ", lvl);
        vfprintf(oracle_msgs, msg, cp);
        fputc('\n', oracle_msgs);
        va_end(cp);
    }
#endif
    if (getenv("ORACLE_LOG")) {
        fprintf(stderr, "%s: ", lvl);
        vfprintf(stderr, msg, ap);
        fputc('\n', stderr);
    }
}
#define LOGFN(name, lvl) void name(const char *file, int line, const char *func, const char *msg, ...) { \
    va_list ap; va_start(ap, msg); vlog(lvl, msg, ap); va_end(ap); }
LOGFN(_mdebug1, "DEBUG")
LOGFN(_mdebug2, "DEBUG2")
LOGFN(_merror, "ERROR")
LOGFN(_mwarn, "WARNING")
void _mverror(const char *file, int line, const char *func, const char *msg, va_list args) { vlog("ERROR", msg, args); }
void _merror_exit(const char *file, int line, const char *func, const char *msg, ...) {
    va_list ap; va_start(ap, msg); fprintf(stderr, "CRITICAL: "); vfprintf(stderr, msg, ap); fputc('\n', stderr); va_end(ap); exit(1);
}
int isDebug(void) { return 0; }

time_t File_DateofChange(const char *file) {
    struct stat st;
    if (stat(file, &st) < 0) return -1;
    return st.st_mtime;
}
off_t FileSize(const char *path) {
    struct stat st;
    return stat(path, &st) ? -1 : st.st_size;
}
FILE *wfopen(const char *pathname, const char *mode) { return fopen(pathname, mode); }
#ifdef AD_ORACLE
/* ORACLE_TIME=<epoch> pins the clock */
static time_t oracle_now(void) {
    const char *t = getenv("ORACLE_TIME");
    if (t) {
        return (time_t)atoll(t);
    }
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return ts.tv_sec;
}
/* '-Dtime(t)=oracle_time(t)' */
time_t oracle_time(time_t *out) {
    time_t now = oracle_now();
    if (out) {
        *out = now;
    }
    return now;
}
time_t w_get_current_time(void) { return oracle_now(); }
void gettime(struct timespec *ts) { ts->tv_sec = oracle_now(); ts->tv_nsec = 0; }
/* -Dgettimeofday=oracle_gettimeofday (accumulator.c) */
int gettimeofday(struct timeval *tv, void *tz) {
    tv->tv_sec = oracle_now();
    tv->tv_usec = 0;
    return 0;
}
gid_t Privsep_GetGroup(const char *name) { return getgid(); }
/* shared/file_op.c, shared/regex_op.c (verbatim) */
int IsFile(const char *file) {
    struct stat buf;
    return (!stat(file, &buf) && S_ISREG(buf.st_mode)) ? 0 : -1;
}
#include <regex.h>
int OS_PRegex(const char *str, const char *regex)
{
    regex_t preg;

    if (!str || !regex) {
        return (0);
    }

    if (regcomp(&preg, regex, REG_EXTENDED | REG_NOSUB) != 0) {
        merror("Posix Regex compile error (%s).", regex);
        return (0);
    }

    if (regexec(&preg, str, 0, NULL, 0) != 0) {
        /* Didn't match */
        regfree(&preg);
        return (0);
    }

    regfree(&preg);
    return (1);
}
#else
time_t w_get_current_time(void) { return time(NULL); }
void gettime(struct timespec *ts) { clock_gettime(CLOCK_REALTIME, ts); }
gid_t Privsep_GetGroup(const char *name) { return (gid_t)-1; }
OSList *active_responses;
long get_global_alert_second_id(void) { return 0; }
#endif

/* Real behaviour (Linux branches of the Wazuh helpers). */
void w_file_cloexec(FILE *fp) { fcntl(fileno(fp), F_SETFD, FD_CLOEXEC); }
int IsDir(const char *file) {
    struct stat st;
    if (stat(file, &st) < 0) return -1;
    return S_ISDIR(st.st_mode) ? 0 : -1;
}
DIR *wopendir(const char *name) { return opendir(name); }
int get_ipv4_numeric(const char *address, struct in_addr *addr) { return inet_pton(AF_INET, address, addr) == 1 ? OS_SUCCESS : OS_INVALID; }
int get_ipv6_numeric(const char *address, struct in6_addr *addr6) { return inet_pton(AF_INET6, address, addr6) == 1 ? OS_SUCCESS : OS_INVALID; }

/* Daemon-only symbols. */
OSDecoderInfo *NULL_Decoder;
int __crt_wday;
#ifndef AD_ORACLE
void *mitre_get_attack(const char *mitre_id) { return NULL; }
#endif
uid_t Privsep_GetUser(const char *name) { return (uid_t)-1; }
void print_out(const char *msg, ...) { }
LOGFN(_minfo, "INFO")
void _mvwarn(const char *file, int line, const char *func, const char *msg, va_list args) { vlog("WARNING", msg, args); }
void _mvinfo(const char *file, int line, const char *func, const char *msg, va_list args) { vlog("INFO", msg, args); }
int OS_RecvSecureTCP(int sock, char *ret, uint32_t size) { return -1; }
#ifndef AD_ORACLE
int OS_SendSecureTCP(int sock, uint32_t size, const void *msg) { return -1; }
#endif
int OS_BindUnixDomain(const char *path, int type, int max_msg_size) { return -1; }
#ifndef AD_ORACLE
int OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) { return -1; }
#endif
int CreateThreadJoinable(pthread_t *lt, void *(*function_pointer)(void *), void *data) { return -1; }
#ifdef AD_ORACLE
/* success without running it (the harness drains the SCA queue itself) */
int CreateThread(void *(*function_pointer)(void *), void *data) { return 1; }
#else
int CreateThread(void *(*function_pointer)(void *), void *data) { return 0; }
#endif
int ReadConfig(int modules, const char *cfgfile, void *d1, void *d2) { return 0; }
char **wreaddir(const char *name) { return NULL; }
struct group *w_getgrgid(gid_t gid, struct group *grp, char *buf, int buflen) { return NULL; }
pthread_mutex_t hourly_alert_mutex = PTHREAD_MUTEX_INITIALIZER;
#ifndef AD_ORACLE
int queue_push_ex_block(w_queue_t *queue, void *data) { return -1; }
#endif
int rmdir_ex(const char *name) { return -1; }

/* Deterministic randomness: logtest tokens are "%08x" of successive
 * counter values (0x00001001, 0x00001002, ...). */
static uint32_t oracle_token = 0x1000;
void randombytes(void *ptr, size_t length) {
    memset(ptr, 0, length);
    oracle_token++;
    memcpy(ptr, &oracle_token, length < sizeof(oracle_token) ? length : sizeof(oracle_token));
}
void srandom_init(void) { }
int os_random(void) { return rand(); }
