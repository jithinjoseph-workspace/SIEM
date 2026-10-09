#!/bin/bash
# Builds ~/dbsync_oracle/dbsync_oracle from dbsync_harness.cpp over Wazuh's
# dbsync and rsync sources.
# usage: build.sh <wazuh src> <nlohmann dir with nlohmann/json.hpp> <dir with cJSON.c/.h> <dir with sqlite3.c/.h>
set -eu
W=$(realpath "$1")
NL=$(realpath "$2")
CJ=$(realpath "$3")
SQ=$(realpath "$4")
HERE=${HARNESS_DIR:-$(dirname "$(realpath "$0")")}
O=~/dbsync_oracle
mkdir -p $O/obj
SM=$W/shared_modules
INC=(-I$NL/nlohmann -I$CJ -I$SQ -I$SM/common -I$SM/utils -I$SM/dbsync/include -I$SM/dbsync/src -I$SM/rsync/include -I$SM/rsync/src -I$W/headers)
DEFS=(-DPROMISE_TYPE=PromiseType::NORMAL -DNDEBUG)
[ -f $O/obj/sqlite3.o ] || gcc -O2 -w -fPIC -DSQLITE_ENABLE_DBSTAT_VTAB=1 -c $SQ/sqlite3.c -o $O/obj/sqlite3.o
[ -f $O/obj/cJSON.o ] || gcc -O2 -w -c $CJ/cJSON.c -o $O/obj/cJSON.o
for f in dbsync/src/dbsync.cpp dbsync/src/dbsync_implementation.cpp dbsync/src/dbsyncPipelineFactory.cpp \
         dbsync/src/sqlite/sqlite_dbengine.cpp dbsync/src/sqlite/sqlite_wrapper.cpp \
         rsync/src/rsync.cpp rsync/src/rsyncImplementation.cpp; do
  o=$O/obj/$(basename $f .cpp).o
  [ $o -nt $SM/$f ] || g++ -std=c++17 -O2 -w -fPIC "${DEFS[@]}" "${INC[@]}" -c $SM/$f -o $o
done
g++ -std=c++17 -O2 -w "${DEFS[@]}" "${INC[@]}" -o $O/dbsync_oracle $HERE/dbsync_harness.cpp $O/obj/*.o -lcrypto -lpthread -ldl
echo built $O/dbsync_oracle
