/* oracle: the parts of wazuh_db/wdb.h used by the analysisd decoders
 * (the real header needs sqlite and the router). */
#ifndef WDB_H
#define WDB_H

#include <shared.h>
#include <pthread.h>
#include <openssl/evp.h>
#include "syscheck_op.h"
#include "rootcheck_op.h"
#include "wazuhdb_op.h"
#include "os_crypto/sha1/sha1_op.h"

#define WDB_NETADDR_IPV4 0

int wdbi_strings_hash(os_sha1 hexdigest, ...);

#endif
