/* Oracle for os_crypto/shared/msgs.c. stdin records (tab separated):
 *   C <method 0=bf 1=aes> <id> <name> <key> <global> <local> <rand> <dynamic 0/1> <hexmsg>
 *       -> "<hex of CreateSecMSG output>"
 *   R <id> <name> <key> <saved_global> <saved_local> <hex of wire buffer as remoted passes it>
 *       -> "<key_state> <hex payload>|-" */
#include "shared.h"
#include "os_crypto/md5/md5_op.h"
#include <openssl/evp.h>
#include <zlib.h>
unsigned int shim_random = 0;
int isAgent = 0;
char shim_rids_dir[512] = "rids";
size_t CreateSecMSG(const keystore *keys, const char *msg, size_t msg_length, char *msg_encrypted, unsigned int id);
int ReadSecMSG(keystore *keys, char *buffer, char *cleartext, int id, unsigned int buffer_size, size_t *final_size, const char *srcip, char **output);
void OS_StartCounter(keystore *keys);
/* os_md5 / os_zlib from Wazuh (copied: originals include unavailable headers) */
int OS_MD5_Str(const char *str, ssize_t length, os_md5 output) {
  EVP_MD_CTX *mdctx = EVP_MD_CTX_new(); unsigned char digest[EVP_MAX_MD_SIZE];
  EVP_DigestInit(mdctx, EVP_md5()); EVP_DigestUpdate(mdctx, str, length < 0 ? (size_t)strlen(str) : (size_t)length);
  EVP_DigestFinal(mdctx, digest, NULL); for (int n = 0; n < 16; n++) snprintf(output + n * 2, 3, "%02x", digest[n]);
  EVP_MD_CTX_free(mdctx); return 0; }
unsigned long int os_zlib_compress(const char *src, char *dst, unsigned long int src_size, unsigned long int dst_size) {
  if (compress2((Bytef *)dst, &dst_size, (const Bytef *)src, src_size, Z_BEST_COMPRESSION) == Z_OK) { dst[dst_size] = '\0'; return dst_size; } return 0; }
unsigned long int os_zlib_uncompress(const char *src, char *dst, unsigned long int src_size, unsigned long int dst_size) {
  if (uncompress((Bytef *)dst, &dst_size, (const Bytef *)src, src_size) == Z_OK) { dst[dst_size] = '\0'; return dst_size; } return 0; }
/* OS_AddKey's encryption-key derivation (keys.c) */
static char *derive(const char *id, const char *name, const char *key) {
  os_md5 f1, f2; char fin[128]; static char out[128];
  OS_MD5_Str(name, -1, f1); OS_MD5_Str(id, -1, f2); snprintf(fin, sizeof fin, "%s%s", f1, f2);
  OS_MD5_Str(fin, -1, f1); f1[15] = '\0'; f1[16] = '\0'; OS_MD5_Str(key, -1, f2);
  snprintf(out, sizeof out, "%s%s", f2, f1); return out; }
static size_t unhex(const char *h, char *o) { size_t n = strlen(h) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = (char)v; } o[n] = 0; return n; }
static void phex(const char *s, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", (unsigned char)s[i]); }
static keystore ks; static keyentry e0, e1; static os_ip ip; static os_ipv4 ip4;
static void setup(const char *id, const char *name, const char *key, int method, int dynamic) {
  static int init = 0;
  if (!init) { init = 1; mkdir("rids"); ks.keyentries = calloc(2, sizeof(keyentry*)); ks.keyentries[0] = &e0; ks.keyentries[1] = &e1;
    ks.keysize = 1; ks.flags.key_mode = W_ENCRYPTION_KEY; pthread_mutex_init(&e0.mutex, NULL); pthread_mutex_init(&e1.mutex, NULL);
    ks.opened_fp_queue = linked_queue_init(); e0.ip = &ip; ip.ipv4 = &ip4; }
  free(e0.id); free(e0.name); free(e0.encryption_key);
  e0.id = strdup(id); e0.name = strdup(name); e0.encryption_key = strdup(derive(id, name, key));
  e0.crypto_method = method; ip.is_ipv6 = false; ip4.netmask = dynamic ? 0 : 0xFFFFFFFF; ip.ip = dynamic ? "any" : "10.0.0.1";
  if (e0.fp) { fclose(e0.fp); e0.fp = NULL; } if (e1.fp) { fclose(e1.fp); e1.fp = NULL; }
}
static void write_counter(const char *name, unsigned g, unsigned l) { char p[600]; snprintf(p, sizeof p, "rids/%s", name); FILE *f = fopen(p, "w"); fprintf(f, "%u:%u:", g, l); fclose(f); }
int main(void) {
  static char line[300000]; static char msg[OS_MAXSTR + 2]; static char out[OS_MAXSTR + 64]; static char clear[OS_MAXSTR + 2]; static char buf[OS_MAXSTR + 64];
  while (fgets(line, sizeof line, stdin)) {
    char *nl = strchr(line, '\n'); if (nl) *nl = 0;
    char *f[12]; int n = 0; for (char *t = strtok(line, "\t"); t && n < 12; t = strtok(NULL, "\t")) f[n++] = t;
    if (f[0][0] == 'C' && n == 10) {
      setup(f[2], f[3], f[4], atoi(f[1]), atoi(f[8])); isAgent = 1;
      write_counter("sender_counter", (unsigned)strtoul(f[5], 0, 10), (unsigned)strtoul(f[6], 0, 10));
      shim_random = (unsigned)strtoul(f[7], 0, 10);
      size_t ml = unhex(f[9], msg);
      memset(out, 0, sizeof out);
      size_t r = CreateSecMSG(&ks, msg, ml, out, 0);
      phex(out, r); printf("\n");
    } else if (f[0][0] == 'R' && n == 7) {
      setup(f[1], f[2], f[3], 0, 0); isAgent = 0;
      write_counter(f[1], (unsigned)strtoul(f[4], 0, 10), (unsigned)strtoul(f[5], 0, 10));
      e0.inode = 0;
      size_t bl = unhex(f[6], buf);
      memset(clear, 0, sizeof clear);
      size_t final_size = 0; char *output = NULL;
      int st = ReadSecMSG(&ks, buf, clear, 0, (unsigned)(bl - 1), &final_size, "10.0.0.1", &output);
      printf("%d ", st); if (st == 0 && output) phex(output, final_size); else printf("-"); printf("\n");
    } else { printf("BAD\n"); }
    fflush(stdout);
  }
  return 0;
}
