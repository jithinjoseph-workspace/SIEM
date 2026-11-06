#ifndef MD5_OP_H
#define MD5_OP_H
#include <sys/types.h>
typedef char os_md5[33];
int OS_MD5_Str(const char *str, ssize_t length, os_md5 output);
#endif
