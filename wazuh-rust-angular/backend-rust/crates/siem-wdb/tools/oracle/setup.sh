#!/bin/bash
# Prepare ~/wdb_oracle in WSL: a copy of Wazuh's src (the oracle never writes
# into the original tree), SQLite 3.50.4 from deps v54, the shims and the
# harness. Usage: setup.sh <wazuh src> <sqlite dir with sqlite3.c/h> <cJSON dir> <zlib dir>
set -eu
W=$1
SQ=$2
CJ=$3
ZL=$4
T=${ORACLE_TOOLS:-$(cd "$(dirname "$0")" && pwd)}
D=~/wdb_oracle
mkdir -p $D
cd $D
if [ ! -d src/error_messages ]; then
  rm -rf src
  mkdir src
  for d in $W/*/; do
    case $(basename $d) in
      external|shared_modules|wazuh_modules|unit_tests|ci|data_provider|syscheckd|win32|wazuh_db) ;;
      *) cp -r $d src/ ;;
    esac
  done
fi
rm -rf src/wazuh_db && cp -r $W/wazuh_db src/
mkdir -p src/external/sqlite src/shared_modules/router/include src/shared_modules/common src/wazuh_modules src/shared_modules/utils/flatbuffers/include cjson
cp $SQ/sqlite3.c $SQ/sqlite3.h src/external/sqlite/
cp $CJ/cJSON.c $CJ/cJSON.h cjson/
[ -d src/external/zlib ] || cp -r $ZL src/external/zlib
mkdir -p src/external/cJSON && cp $CJ/cJSON.c $CJ/cJSON.h src/external/cJSON/
# curl, yaml, bzip2 and the C++ sync modules are not needed by wazuh-db
for h in url.h yaml2json.h bzip2_op.h ../shared_modules/rsync/include/rsync.h ../shared_modules/dbsync/include/dbsync.h; do
  sed -i "s@^#include \"$h\"@/* oracle: dropped $h */@" src/headers/shared.h
done
cp $W/shared_modules/router/include/*.h src/shared_modules/router/include/
cp -r $W/shared_modules/common/. src/shared_modules/common/ 2>/dev/null || true
cp $W/wazuh_modules/*.h $W/wazuh_modules/wm_task_general.c src/wazuh_modules/
mkdir -p src/syscheckd && cp -r $W/syscheckd/include src/syscheckd/
# PCRE2 headers (from the analysisd oracle tree, which has Wazuh's deps)
[ -d src/external/libpcre2 ] || cp -r ~/oracle_build/src/external/libpcre2 src/external/
: > src/shared_modules/utils/flatbuffers/include/syscollector_deltas_schema.h
rm -rf wdbshim && cp -r $T/wdbshim .
cp $T/wdb_harness.c $T/wdb_stubs.c $T/build.sh .
cp $T/../../../siem-sqlite/sqlite/siem_fixed_time.c .
sed -i 's/\r$//' build.sh
