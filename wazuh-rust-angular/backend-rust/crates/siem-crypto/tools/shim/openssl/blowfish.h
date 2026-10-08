#ifndef SHIM_BF_H
#define SHIM_BF_H
typedef unsigned int BF_LONG;
#define BF_ROUNDS 16
typedef struct bf_key_st { BF_LONG P[BF_ROUNDS + 2]; BF_LONG S[4 * 256]; } BF_KEY;
void BF_set_key(BF_KEY *key, int len, const unsigned char *data);
void BF_cbc_encrypt(const unsigned char *in, unsigned char *out, long length, const BF_KEY *schedule, unsigned char *ivec, int enc);
#endif
