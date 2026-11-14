/* oracle: the wazuh-db client calls analysisd makes (stubbed in
 * ad_harness.c). Installed over src/wazuh_db/helpers/ by build.sh ad: the
 * real header pulls the whole wazuh-db (sqlite, router, ...). */
#ifndef WDB_GLOBAL_HELPERS_H
#define WDB_GLOBAL_HELPERS_H
#include "syscheck_op.h"
#define AGENT_CS_ACTIVE "active"
int *wdb_get_agents_by_connection_status(const char *status, int *sock);
int *wdb_get_agents_ids_of_current_node(const char *connection_status, int *sock, int last_id, int limit);
cJSON *wdb_get_agent_info(int id, int *sock);
#endif
