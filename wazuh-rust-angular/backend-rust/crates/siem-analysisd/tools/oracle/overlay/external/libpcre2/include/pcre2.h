/* Minimal PCRE2 10.x declarations for the oracle build (8-bit library). */
#ifndef PCRE2_H_IDEMPOTENT_GUARD
#define PCRE2_H_IDEMPOTENT_GUARD
#include <stddef.h>
#include <stdint.h>
typedef uint8_t PCRE2_UCHAR8;
typedef const PCRE2_UCHAR8 *PCRE2_SPTR8;
typedef size_t PCRE2_SIZE;
typedef struct pcre2_real_code_8 pcre2_code_8;
typedef struct pcre2_real_match_data_8 pcre2_match_data_8;
typedef struct pcre2_real_compile_context_8 pcre2_compile_context_8;
typedef struct pcre2_real_match_context_8 pcre2_match_context_8;
typedef struct pcre2_real_general_context_8 pcre2_general_context_8;
#define PCRE2_ZERO_TERMINATED (~(PCRE2_SIZE)0)
#define PCRE2_UNSET (~(PCRE2_SIZE)0)
pcre2_code_8 *pcre2_compile_8(PCRE2_SPTR8, PCRE2_SIZE, uint32_t, int *, PCRE2_SIZE *, pcre2_compile_context_8 *);
void pcre2_code_free_8(pcre2_code_8 *);
pcre2_match_data_8 *pcre2_match_data_create_from_pattern_8(const pcre2_code_8 *, pcre2_general_context_8 *);
int pcre2_match_8(const pcre2_code_8 *, PCRE2_SPTR8, PCRE2_SIZE, PCRE2_SIZE, uint32_t, pcre2_match_data_8 *, pcre2_match_context_8 *);
PCRE2_SIZE *pcre2_get_ovector_pointer_8(pcre2_match_data_8 *);
void pcre2_match_data_free_8(pcre2_match_data_8 *);
#define PCRE2_UCHAR PCRE2_UCHAR8
#define PCRE2_SPTR PCRE2_SPTR8
#define pcre2_code pcre2_code_8
#define pcre2_match_data pcre2_match_data_8
#define pcre2_compile pcre2_compile_8
#define pcre2_code_free pcre2_code_free_8
#define pcre2_match_data_create_from_pattern pcre2_match_data_create_from_pattern_8
#define pcre2_match pcre2_match_8
#define pcre2_get_ovector_pointer pcre2_get_ovector_pointer_8
#define pcre2_match_data_free pcre2_match_data_free_8
#endif
