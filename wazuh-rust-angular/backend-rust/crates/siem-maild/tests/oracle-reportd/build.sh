#!/bin/bash
# Builds the C wazuh-reportd (reportd/report.c + report_op.c, logs to $MON_LOG via the maild oracle stubs). WSL.
set -u
H="$(cd "$(dirname "$0")" && pwd)"
S=$HOME/wazuh-mon-src/src
mkdir -p ~/reportd_oracle && cd ~/reportd_oracle
cp "$H"/../oracle/daemon_stubs.c "$H"/maild_globals.c .
CFLAGS="-O1 -w -g -DOSSECHIDS -DARGV0=\"wazuh-reportd\" -DUSER=\"wazuh\" -DGROUPGLOBAL=\"wazuh\" -I$S -I$S/headers -I$S/external -I$S/external/cJSON -I$S/shared_modules/common -I$S/external/openssl/include -I$S/external/zlib -I$S/external/bzip2 -I$S/shared_modules/router/include -I$S/external/sqlite -I$S/shared_modules/dbsync/include -I$S/shared_modules/rsync/include -I$S/wazuh_modules -I$S/external/libyaml/include -I$S/external/msgpack/include"
FILES="$S/os_maild/os_maild_client.c $S/os_maild/sendmail.c $S/os_maild/sendcustomemail.c $S/os_maild/mail_list.c $S/os_maild/mailcom.c $S/os_maild/config.c $S/config/email-alerts-config.c $S/shared/json-queue.c
$S/shared/exec_op.c
$S/config/global-config.c $S/shared/report_op.c
$S/wazuh_db/helpers/wdb_global_helpers.c $S/shared/wazuhdb_op.c $S/shared/auth_client.c $S/shared/agent_op.c
$S/shared/mq_op.c $S/os_net/os_net.c $S/shared/file_op.c $S/shared/hash_op.c $S/shared/mem_op.c $S/shared/string_op.c
$S/shared/validate_op.c $S/shared/math_op.c $S/shared/list_op.c $S/shared/store_op.c $S/shared/time_op.c
$S/shared/wait_op.c $S/shared/privsep_op.c $S/shared/pthreads_op.c $S/shared/randombytes.c
$S/os_crypto/md5/md5_op.c $S/os_crypto/sha1/sha1_op.c $S/os_crypto/sha256/sha256_op.c
$S/os_regex/*.c $S/os_xml/*.c $S/shared/rbtree_op.c $S/shared/expression.c
$S/shared/read-alert.c $S/shared/file-queue.c $S/shared/regex_op.c $S/wazuh_db/wdb_shared.c $S/shared/atomic.c $S/shared/version_op.c $S/shared/cluster_utils.c $S/shared/labels_op.c $S/shared/log_builder.c $S/shared/b64.c $S/shared/binaries_op.c $S/shared/rwlock_op.c"
gcc $CFLAGS -o c_reportd daemon_stubs.c maild_globals.c $S/reportd/report.c $FILES $S/shared/sig_op.c -L$HOME/wazuh-server-src/src -lwazuhext -Wl,-rpath,$HOME/wazuh-server-src/src -lcrypto -lz -lpthread -lm -ldl > build.log 2>&1
grep -oE "(undefined reference to|multiple definition of) [^;]*" build.log | sort -u | head -40
ls -la c_reportd 2>/dev/null | cut -c1-60
