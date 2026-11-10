/* Oracle for os_xml. Usage: xml_harness <file>...   (or "-s" then hex strings on stdin)
 * Prints a canonical dump; tools/xml_dump in Rust prints the same format. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "os_xml.h"
static void phex(const char *s) { if (!s) { printf("~"); return; } if (!*s) { printf("-"); return; } for (; *s; s++) printf("%02x", (unsigned char)*s); }
static void dump_nodes(OS_XML *x, xml_node *parent, int depth) {
  xml_node **n = OS_GetElementsbyNode(x, parent);
  if (!n) return;
  for (int i = 0; n[i]; i++) {
    printf("N %d %u ", depth, n[i]->key); phex(n[i]->element); printf(" "); phex(n[i]->content);
    if (n[i]->attributes) for (int j = 0; n[i]->attributes[j]; j++) { printf(" "); phex(n[i]->attributes[j]); printf("="); phex(n[i]->values[j]); }
    printf("\n");
    if (depth < 12) dump_nodes(x, n[i], depth + 1);
  }
  OS_ClearNode(n);
}
static void dump(OS_XML *x) {
  for (unsigned i = 0; i < x->cur; i++) {
    printf("E %u %d %u %d %u ", i, (int)x->tp[i], x->rl[i], x->ck[i], x->ln[i]); phex(x->el[i]); printf(" "); phex(x->ct[i]); printf("\n");
  }
}
static void run(OS_XML *x, int rc) {
  printf("R %d %u ", rc, x->err_line); phex(x->err); printf("\n");
  if (rc != 0) return;
  dump(x);
  int v = OS_ApplyVariables(x);
  printf("V %d %u ", v, v ? x->err_line : 0); if (v) phex(x->err); else printf("-"); printf("\n");
  if (v == 0) dump(x);
  dump_nodes(x, NULL, 0);
  char **roots = OS_GetElements(x, NULL);
  printf("G"); if (roots) for (int i = 0; roots[i]; i++) { printf(" "); phex(roots[i]); free(roots[i]); } printf("\n"); free(roots);
  OS_ClearXML(x);
}
int main(int argc, char **argv) {
  if (argc > 5 && strcmp(argv[1], "-w") == 0) {
    /* -w infile outfile oldval('~' = NULL) newval node... */
    const char *nodes[64] = {0}; int k = 0;
    for (int a = 6; a < argc && k < 63; a++) nodes[k++] = argv[a];
    int r = OS_WriteXML(argv[2], argv[3], nodes, strcmp(argv[4], "~") ? argv[4] : NULL, argv[5]);
    printf("W %d\n", r);
    return 0;
  }
  if (argc > 1 && strcmp(argv[1], "-s") == 0) {
    static char line[400000]; static char buf[200000];
    while (fgets(line, sizeof line, stdin)) {
      char *nl = strchr(line, '\n'); if (nl) *nl = 0;
      size_t n = strlen(line) / 2; for (size_t i = 0; i < n; i++) { unsigned v; sscanf(line + 2 * i, "%2x", &v); buf[i] = (char)v; } buf[n] = 0;
      OS_XML x; int rc = OS_ReadXMLString(buf, &x); run(&x, rc); printf("END\n"); fflush(stdout);
    }
    return 0;
  }
  for (int a = 1; a < argc; a++) { OS_XML x; int rc = OS_ReadXML(argv[a], &x); run(&x, rc); printf("END\n"); }
  return 0;
}
