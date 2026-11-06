/* Oracle: reads records "<mode>\t<hexpattern>\t<hexlog>\n" and prints the C result.
 * mode R = OSRegex (OS_RETURN_SUBSTRING), r = OSRegex no flags, M = OSMatch, W = OS_WordMatch */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "os_regex.h"
static char *unhex(const char *h) { size_t n = strlen(h) / 2; char *o = malloc(n + 1);
  for (size_t i = 0; i < n; i++) { unsigned v; sscanf(h + 2 * i, "%2x", &v); o[i] = (char)v; } o[n] = 0; return o; }
static void phex(const char *s) { for (; *s; s++) printf("%02x", (unsigned char)*s); }
int main(void) {
  static char line[1 << 20];
  while (fgets(line, sizeof line, stdin)) {
    char *nl = strchr(line, '\n'); if (nl) *nl = 0;
    char mode = line[0]; char *hp = line + 2; char *tab = strchr(hp, '\t'); if (!tab) continue; *tab = 0;
    char *pat = unhex(hp), *log = unhex(tab + 1);
    if (mode == 'R' || mode == 'r') {
      OSRegex reg; memset(&reg, 0, sizeof reg);
      if (!OSRegex_Compile(pat, &reg, mode == 'R' ? OS_RETURN_SUBSTRING : 0)) { printf("E%d\n", reg.error); }
      else { const char *ret = OSRegex_Execute(log, &reg);
        if (!ret) printf("N\n");
        else { printf("Y %ld", (long)(ret - log));
          if (reg.d_sub_strings) for (int i = 0; reg.d_sub_strings[i]; i++) { printf(" "); if (!*reg.d_sub_strings[i]) printf("-"); else phex(reg.d_sub_strings[i]); }
          printf("\n"); }
        OSRegex_FreePattern(&reg); }
    } else if (mode == 'M') {
      OSMatch m; memset(&m, 0, sizeof m);
      if (!OSMatch_Compile(pat, &m, 0)) printf("E%d\n", m.error);
      else { printf(OSMatch_Execute(log, strlen(log), &m) ? "Y\n" : "N\n"); OSMatch_FreePattern(&m); }
    } else if (mode == 'W') {
      printf(OS_WordMatch(pat, log) ? "Y\n" : "N\n");
    }
    fflush(stdout); free(pat); free(log);
  }
  return 0;
}
