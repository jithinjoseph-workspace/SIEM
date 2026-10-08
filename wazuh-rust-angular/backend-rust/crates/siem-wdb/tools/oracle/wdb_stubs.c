/* Link stubs for the wazuh-db oracle: logging, the pinned clock and the
 * daemon-only symbols the library refers to. */
#include "shared.h"

/* error/warning/info messages go to stdout as "M <level> <hex>" */
static void vlog(const char *lvl, const char *msg, va_list ap) {
    char buf[OS_MAXSTR * 2];
    va_list cp;
    va_copy(cp, ap);
    int n = vsnprintf(buf, sizeof(buf), msg, cp);
    va_end(cp);
    if (n < 0) {
        n = 0;
    }
    if ((size_t)n >= sizeof(buf)) {
        n = sizeof(buf) - 1;
    }
    if (strncmp(lvl, "DEBUG", 5) != 0) {
        printf("M %s ", lvl);
        for (int i = 0; i < n; i++) {
            printf("%02x", (unsigned char)buf[i]);
        }
        printf("\n");
    }
    if (getenv("ORACLE_LOG")) {
        fprintf(stderr, "%s: %s\n", lvl, buf);
    }
}
#define LOGFN(name, lvl) void name(const char *file, int line, const char *func, const char *msg, ...) { \
    va_list ap; va_start(ap, msg); vlog(lvl, msg, ap); va_end(ap); }
LOGFN(_mdebug1, "DEBUG")
LOGFN(_mdebug2, "DEBUG2")
LOGFN(_merror, "ERROR")
LOGFN(_mwarn, "WARNING")
LOGFN(_minfo, "INFO")
LOGFN(_mferror, "ERROR")
void _mverror(const char *file, int line, const char *func, const char *msg, va_list args) { vlog("ERROR", msg, args); }
void _mvwarn(const char *file, int line, const char *func, const char *msg, va_list args) { vlog("WARNING", msg, args); }
void _mvinfo(const char *file, int line, const char *func, const char *msg, va_list args) { vlog("INFO", msg, args); }
void _merror_exit(const char *file, int line, const char *func, const char *msg, ...) {
    va_list ap; va_start(ap, msg); fprintf(stderr, "CRITICAL: "); vfprintf(stderr, msg, ap); fputc('\n', stderr); va_end(ap); exit(1);
}
int isDebug(void) { return 0; }
void print_out(const char *msg, ...) { }

/* daemon-only symbols */
uid_t Privsep_GetUser(const char *name) { return (uid_t)-1; }
gid_t Privsep_GetGroup(const char *name) { return (gid_t)-1; }
struct group *w_getgrgid(gid_t gid, struct group *grp, char *buf, int buflen) { return NULL; }
void nowDaemon(void) { }
int bzip2_uncompress(const char *file, const char *filebz2) { return -1; }
int get_binary_path(const char *binary, char **validated_comm) { return -1; }
int os_random(void) { return rand(); }
int OS_ConnectUnixDomain(const char *path, int type, int max_msg_size) { return -1; }
int OS_RecvSecureTCP(int sock, char *ret, uint32_t size) { return -1; }
int get_ipv4_numeric(const char *address, struct in_addr *addr) { return inet_pton(AF_INET, address, addr) == 1 ? OS_SUCCESS : OS_INVALID; }
int get_ipv6_numeric(const char *address, struct in6_addr *addr6) { return inet_pton(AF_INET6, address, addr6) == 1 ? OS_SUCCESS : OS_INVALID; }
/* shared/os_utils.c (verbatim) */
int w_is_file(const char * const file) {
    FILE *fp = wfopen(file, "r");
    int is_exist = 0;
    if (fp != NULL) {
        is_exist = 1;
        fclose(fp);
    }
    return is_exist;
}

/* the pinned clock (set by the harness) */
time_t oracle_clock;
time_t oracle_time(time_t *out) {
    if (out) {
        *out = oracle_clock;
    }
    return oracle_clock;
}
time_t w_get_current_time(void) { return oracle_clock; }
void gettime(struct timespec *ts) { ts->tv_sec = oracle_clock; ts->tv_nsec = 0; }
int oracle_gettimeofday(struct timeval *tv, void *tz) {
    tv->tv_sec = oracle_clock;
    tv->tv_usec = 0;
    return 0;
}
/* sleep commands do not sleep */
void w_time_delay(unsigned long int ms) { }
