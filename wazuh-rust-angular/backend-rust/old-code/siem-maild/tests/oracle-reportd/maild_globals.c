/* The os_maild/maild.c globals the shared maild objects reference (reportd links them, never uses them). */
#include "shared.h"
#include "os_maild/maild.h"
MailConfig mail;
unsigned int mail_timeout;
unsigned int _g_subject_level;
char _g_subject[SUBJECT_SIZE + 2];
