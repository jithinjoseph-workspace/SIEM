#!/bin/bash
# Build the wazuh-db HTTP API oracle (run inside WSL from ~/wdb_oracle after
# setup.sh and build.sh). Needs the router sources of the Wazuh tree ($1)
# and Wazuh's deps/54 cpp-httplib and nlohmann (WAZUH_DEPS, default
# ~/wazuh_deps, see get_deps in the README).
set -u
cd "$(dirname "$0")"
W=${1:?usage: http_build.sh <wazuh src>}
DEPS=${WAZUH_DEPS:-$HOME/wazuh_deps}
S=src
mkdir -p $S/external/cpp-httplib $S/external/nlohmann $S/shared_modules/utils $S/shared_modules/router
cp $DEPS/cpp-httplib/cpp-httplib/httplib.h $S/external/cpp-httplib/
cp $DEPS/nlohmann/nlohmann/json.hpp $S/external/nlohmann/
cp $W/shared_modules/utils/reflectiveJson.hpp $W/shared_modules/utils/sqlite3Wrapper.hpp $W/shared_modules/utils/defer.hpp $S/shared_modules/utils/
rm -rf $S/shared_modules/router/src && cp -r $W/shared_modules/router/src $S/shared_modules/router/

CFLAGS=(-Iwdbshim -O1 -w -g -DOSSECHIDS '-DUSER="wazuh"' '-DGROUPGLOBAL="wazuh"' '-DARGV0="wazuh-db"'
  -I$S -I$S/headers -I$S/external -I$S/shared_modules/common -I$S/shared_modules/router/include -I$S/shared_modules -Icjson)
DEFS=(-Dgettimeofday=oracle_gettimeofday '-Dtime(t)=oracle_time(t)')
WDB=$(ls $S/wazuh_db/*.c | grep -v '/main.c$')
FILES="$WDB $S/config/wazuh_db-config.c
$S/shared/rbtree_op.c $S/shared/string_op.c $S/shared/file_op.c $S/shared/json_op.c
$S/shared/integrity_op.c $S/wazuh_modules/wm_task_general.c $S/shared/math_op.c $S/shared/cluster_utils.c $S/shared/expression.c
$S/os_crypto/sha1/sha1_op.c $S/os_crypto/sha256/sha256_op.c
$S/shared/hash_op.c $S/shared/list_op.c $S/shared/validate_op.c $S/shared/mem_op.c $S/shared/regex_op.c
$S/shared/syscheck_op.c $S/shared/rootcheck_op.c $S/shared/wazuhdb_op.c $S/shared/version_op.c
$S/os_regex/*.c $S/os_xml/*.c cjson/cJSON.c wdb_stubs.c schemas.c"
rm -rf hobj && mkdir hobj
for f in $FILES; do
  o=hobj/$(echo $f | tr '/.' '__').o
  gcc "${CFLAGS[@]}" "${DEFS[@]}" -c $f -o $o || exit 1
done
gcc "${CFLAGS[@]}" "${DEFS[@]}" -DWDB_HARNESS_NO_MAIN -c wdb_harness.c -o hobj/wdb_harness.o || exit 1
g++ -std=c++2a -O1 -w -g -I$S -I$S/headers -I$S/shared_modules/utils -I$S/shared_modules/router/src \
  -c http_harness.cpp -o hobj/http_harness.o || exit 1
rm -f http_oracle
g++ -o http_oracle hobj/*.o time_op.o sqlite3.o siem_fixed_time.o libz.a \
  /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 -lcrypto -lpthread -lm -ldl 2>&1 \
  | grep -E "error|undefined|multiple definition" | sort -u | head -40
ls -la http_oracle 2>/dev/null | tail -1
