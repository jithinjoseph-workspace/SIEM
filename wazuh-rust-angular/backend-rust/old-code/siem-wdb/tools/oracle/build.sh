#!/bin/bash
# Build the wazuh-db oracle (run inside WSL from ~/wdb_oracle, see setup.sh).
set -u
cd "$(dirname "$0")"
S=src
CFLAGS=(-Iwdbshim -O1 -w -g -DOSSECHIDS '-DUSER="wazuh"' '-DGROUPGLOBAL="wazuh"' '-DARGV0="wazuh-db"'
  -I$S -I$S/headers -I$S/external -I$S/shared_modules/common -I$S/shared_modules/router/include -I$S/shared_modules -Icjson)
DEFS=(-Dgettimeofday=oracle_gettimeofday '-Dtime(t)=oracle_time(t)')
# SQLite and zlib are compiled once (Wazuh's deps v54)
if [ ! -f sqlite3.o ] || [ $S/external/sqlite/sqlite3.c -nt sqlite3.o ]; then
  gcc -O2 -w -fPIC -DSQLITE_ENABLE_DBSTAT_VTAB=1 -c $S/external/sqlite/sqlite3.c -o sqlite3.o || exit 1
fi
if [ ! -f libz.a ]; then
  rm -rf zobj && mkdir zobj
  for f in adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback inffast inflate inftrees trees uncompr zutil; do
    gcc -O2 -w -fPIC -c $S/external/zlib/$f.c -o zobj/$f.o || exit 1
  done
  ar rcs libz.a zobj/*.o
fi
gcc -O2 -w -I$S/external/sqlite -c siem_fixed_time.c -o siem_fixed_time.o || exit 1
# the schemas, embedded like Wazuh's Makefile does (newlines removed)
: > schemas.c
for f in $S/wazuh_db/schema_*.sql; do
  n=$(basename $f .sql)_sql
  echo 'const char *'$n '= "'"`cat $f | tr -d \"\n\"`"'";' >> schemas.c
done
# shared/time_op.c without the clock functions the stubs pin
gcc "${CFLAGS[@]}" -Dgettime=real_gettime -Dw_time_delay=real_w_time_delay -c $S/shared/time_op.c -o time_op.o || exit 1
WDB=$(ls $S/wazuh_db/*.c | grep -v '/main.c$')
FILES="$WDB $S/config/wazuh_db-config.c
$S/shared/rbtree_op.c $S/shared/string_op.c $S/shared/file_op.c $S/shared/json_op.c time_op.o schemas.c
$S/shared/integrity_op.c $S/wazuh_modules/wm_task_general.c $S/shared/math_op.c $S/shared/cluster_utils.c $S/shared/expression.c
$S/os_crypto/sha1/sha1_op.c $S/os_crypto/sha256/sha256_op.c
$S/shared/hash_op.c $S/shared/list_op.c $S/shared/validate_op.c $S/shared/mem_op.c $S/shared/regex_op.c
$S/shared/syscheck_op.c $S/shared/rootcheck_op.c $S/shared/wazuhdb_op.c $S/shared/version_op.c
$S/os_regex/*.c $S/os_xml/*.c cjson/cJSON.c"
rm -f wdb_oracle
gcc "${CFLAGS[@]}" -Werror=implicit-function-declaration "${DEFS[@]}" ${EXTRA:-} -o wdb_oracle wdb_harness.c wdb_stubs.c $FILES \
  sqlite3.o siem_fixed_time.o libz.a /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 -lcrypto -lpthread -lm -ldl 2>&1 \
  | grep -E "error|undefined|multiple definition" | sed 's/.*\(undefined reference to\|multiple definition of\)/\1/' | sort -u | head -80
ls -la wdb_oracle 2>/dev/null | tail -1
