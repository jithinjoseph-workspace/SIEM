#ifndef SHIM_FILE_OP_H
#define SHIM_FILE_OP_H
#include <stdio.h>
static inline FILE *wfopen(const char *p, const char *m) { return fopen(p, m[0] == 'r' ? "rb" : "wb"); }
static inline void w_file_cloexec(FILE *fp) { (void)fp; }
#endif
