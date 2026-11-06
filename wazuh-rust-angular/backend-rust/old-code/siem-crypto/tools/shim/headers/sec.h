#ifndef SHIM_SEC_H
#define SHIM_SEC_H
typedef enum _crypt_method { W_METH_BLOWFISH, W_METH_AES } crypt_method;
typedef enum _key_mode { W_RAW_KEY, W_ENCRYPTION_KEY, W_DUAL_KEY } key_mode_t;
typedef struct keystore_flags_t { unsigned int key_mode:2; unsigned int save_removed:1; } keystore_flags_t;
typedef struct _os_ipv4 { unsigned int ip_address; unsigned int netmask; } os_ipv4;
typedef struct _os_ip { char *ip; union { os_ipv4 *ipv4; void *ipv6; }; bool is_ipv6; } os_ip;
#define isSingleHost(x) ((x->is_ipv6) ? false : (x->ipv4->netmask == 0xFFFFFFFF))
typedef struct _keyentry {
    time_t rcvd; unsigned int local; unsigned int keyid; unsigned int global; time_t updating_time;
    char *id; char *raw_key; char *encryption_key; char *name; bool post_startup; ino_t inode;
    os_ip *ip; int sock; int net_protocol; time_t time_added; pthread_mutex_t mutex; FILE *fp;
    crypt_method crypto_method; w_linked_queue_node_t *rids_node;
} keyentry;
typedef struct _keystore {
    keyentry **keyentries; unsigned int keysize; keystore_flags_t flags; w_linked_queue_t *opened_fp_queue;
} keystore;
typedef enum key_states { KS_VALID, KS_RIDS, KS_CORRUPT, KS_ENCKEY } key_states;
#define RIDS_DIR shim_rids_dir
#define SENDER_COUNTER "sender_counter"
#endif
