#ifndef SHIM_SHARED_H
#define SHIM_SHARED_H
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
typedef uint16_t u_int16_t;
#define OS_SIZE_65536 65536
#define OS_MAXSTR OS_SIZE_65536
#define OS_HEADER_SIZE 128
#define OS_FLSIZE 256
#define OS_INVALID -1
#define OS_SUCCESS 0
#define FOPEN_ERROR "fopen %s %d %s"
#define ENCFORMAT_ERROR "Incorrect format from %s (%s)"
#define ENCKEY_ERROR "Bad key %s (%s)"
#define ENCSUM_ERROR "Bad checksum %s (%s)"
#define ENCTIME_ERROR "Bad counter %s"
#define ENCSIZE_ERROR "Bad size %s"
#define UNCOMPRESS_ERR "Uncompress error."
#define COMPRESS_ERR "Compress error %s"
#define merror(...) ((void)0)
#define mwarn(...) ((void)0)
#define mdebug1(...) ((void)0)
#define mdebug2(...) ((void)0)
#define merror_exit(...) exit(1)
#define w_mutex_lock(m) pthread_mutex_lock(m)
#define w_mutex_unlock(m) pthread_mutex_unlock(m)
typedef struct w_linked_queue_node_t { int dummy; } w_linked_queue_node_t;
typedef struct w_linked_queue_t { int dummy; } w_linked_queue_t;
typedef struct rb_tree rb_tree;
static inline w_linked_queue_t *linked_queue_init(void) { return calloc(1, sizeof(w_linked_queue_t)); }
static inline w_linked_queue_node_t *linked_queue_push_ex(w_linked_queue_t *q, void *d) { (void)q; (void)d; return calloc(1, sizeof(w_linked_queue_node_t)); }
static inline void linked_queue_unlink_and_push_node(w_linked_queue_t *q, w_linked_queue_node_t *n) { (void)q; (void)n; }
extern unsigned int shim_random;
static inline long os_random(void) { return (long)shim_random; }
extern int isAgent;
extern char shim_rids_dir[512];
static inline FILE *wfopen(const char *p, const char *m) { return fopen(p, m); }
static inline ino_t File_Inode(const char *p) { static ino_t c = 0; (void)p; return ++c; }
static inline int getDefine_Int(const char *a, const char *b, int min, int max) { (void)a; (void)min; (void)max;
  if (!strcmp(b, "verify_msg_id")) return 1; return 10; }
#include "headers/sec.h"
#endif
