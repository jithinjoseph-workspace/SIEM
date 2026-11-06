#ifndef SHIM_SHARED_H
#define SHIM_SHARED_H
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <stdbool.h>
#include "os_regex.h"
#include "os_regex_internal.h"
#define os_calloc(n,s,p) ((p) = (__typeof__(p))calloc((n),(s)))
#define os_realloc(x,s,p) ((p) = (__typeof__(p))realloc((x),(s)))
#define os_free(x) do { if (x) { free((void*)(x)); (x) = NULL; } } while (0)
#define w_mutex_init(m,a) pthread_mutex_init((m),(a))
#define w_mutex_lock(m) pthread_mutex_lock(m)
#define w_mutex_unlock(m) pthread_mutex_unlock(m)
#define w_mutex_destroy(m) pthread_mutex_destroy(m)
#define w_FreeArray(x) do { if (x) { char **_a = (char**)(x); for (int _i = 0; _a[_i]; _i++) { free(_a[_i]); _a[_i] = NULL; } } } while (0)
#endif
