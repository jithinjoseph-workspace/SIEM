#ifndef SHIM_ZLIB_H
#define SHIM_ZLIB_H
typedef unsigned char Bytef;
typedef unsigned long uLongf;
typedef unsigned long uLong;
#define Z_OK 0
#define Z_BEST_COMPRESSION 9
int compress2(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen, int level);
int uncompress(Bytef *dest, uLongf *destLen, const Bytef *source, uLong sourceLen);
#endif
