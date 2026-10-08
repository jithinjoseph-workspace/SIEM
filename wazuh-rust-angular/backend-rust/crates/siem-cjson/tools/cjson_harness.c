/* For each hex line: parse with cJSON_ParseWithOpts(s, &end, 0); print
 *  "P <ok> <end_offset>" then "U <hex unformatted>" "F <hex formatted>" and
 *  for every number node "N <valueint> <hex of %f>". */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cJSON.h"
static void phex(const char *s) { if (!s) { printf("~"); return; } if (!*s) { printf("-"); return; } for (; *s; s++) printf("%02x", (unsigned char)*s); }
static void nums(cJSON *n) { for (; n; n = n->next) { if (cJSON_IsNumber(n)) { char b[512]; snprintf(b, sizeof b, "%f", n->valuedouble); printf("N %d ", n->valueint); phex(b); printf("\n"); } nums(n->child); } }
int main(void) {
  static char line[400000], buf[200000];
  while (fgets(line, sizeof line, stdin)) {
    char *nl = strchr(line, '\n'); if (nl) *nl = 0;
    size_t n = strlen(line) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(line + 2 * i, "%2x", &v); buf[i] = (char)v; } buf[n] = 0;
    const char *end = NULL; cJSON *j = cJSON_ParseWithOpts(buf, &end, 0);
    if (!j) { printf("P 0 %ld\nEND\n", (long)(end ? end - buf : -1)); fflush(stdout); continue; }
    printf("P 1 %ld\n", (long)(end - buf));
    char *u = cJSON_PrintUnformatted(j), *f = cJSON_Print(j);
    printf("U "); phex(u); printf("\nF "); phex(f); printf("\n"); nums(j);
    printf("END\n"); fflush(stdout); free(u); free(f); cJSON_Delete(j);
  }
  return 0;
}
