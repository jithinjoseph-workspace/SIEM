#!/bin/bash
# Build the C monitord oracle (run inside WSL).
set -u
H="$(cd "$(dirname "$0")" && pwd)"
S=$HOME/wazuh-mon-src/src
mkdir -p ~/mail_oracle && cp "$H"/harness.c ~/mail_oracle/ && cd ~/mail_oracle
CFLAGS="-O1 -w -g -DOSSECHIDS -DUSER=\"wazuh\" -DGROUPGLOBAL=\"wazuh\" -I$S -I$S/headers -I$S/external -I$S/external/cJSON -I$S/shared_modules/common -I$S/external/openssl/include -I$S/external/zlib -I$S/external/bzip2 -I$S/shared_modules/router/include -I$S/external/sqlite -I$S/shared_modules/dbsync/include -I$S/shared_modules/rsync/include -I$S/wazuh_modules -I$S/external/libyaml/include -I$S/external/msgpack/include"
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
gcc $CFLAGS -o mail_oracle harness.c $FILES -L$HOME/wazuh-server-src/src -lwazuhext -Wl,-rpath,$HOME/wazuh-server-src/src -lcrypto -lz -lpthread -lm -ldl > build.log 2>&1; grep -oE "(undefined reference to|multiple definition of) [^;]*" build.log | sort -u | head -80; grep -c . build.log
ls -la mail_oracle 2>/dev/null | cut -c1-60
cp "$H"/daemon_stubs.c ~/mail_oracle/
gcc $CFLAGS -o c_maild daemon_stubs.c $S/os_maild/maild.c $FILES $S/shared/sig_op.c -L$HOME/wazuh-server-src/src -lwazuhext -Wl,-rpath,$HOME/wazuh-server-src/src -lcrypto -lz -lpthread -lm -ldl > build2.log 2>&1; grep -oE "(undefined reference to|multiple definition of) [^;]*" build2.log | sort -u | head -40
ls -la c_maild 2>/dev/null | cut -c1-60
