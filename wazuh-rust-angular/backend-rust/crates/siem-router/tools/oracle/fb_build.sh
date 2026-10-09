#!/bin/bash
# Builds fb_oracle (tools/oracle/fb_harness.cpp) in ~/fb_oracle.
# usage: fb_build.sh <wazuh src> <flatbuffers 23.5.26 src> <simdjson 3.13.0 src>
# (Wazuh's deps/54: https://packages.wazuh.com/deps/54/libraries/sources/{flatbuffers,simdjson}.tar.gz)
set -eu
W=$(realpath "$1")
FB=$(realpath "$2")
SJ=$(realpath "$3")
HERE=${HARNESS_DIR:-$(dirname "$(realpath "$0")")}
O=~/fb_oracle
mkdir -p $O/obj $O/include
# the *_schema.h headers, made like utils/flatbuffers/schemas/CMakeLists.txt does
for schema in syscollector_deltas syscheck_deltas rsync; do
  FBS_FILE=$W/shared_modules/utils/flatbuffers/schemas/$schema.fbs
  (cd $W/shared_modules/utils/flatbuffers/schemas &&
   bash -c "echo -e '// This file was generated from ${FBS_FILE} , do not modify \\n#ifndef ${schema}_HEADER\\n#define ${schema}_HEADER\\n#define ${schema}_SCHEMA \"'\`cat ${FBS_FILE}\`'\" \\n#endif // ${schema}_HEADER\\n ' > $O/include/${schema}_schema.h")
done
# flatbuffers' library sources (FlatBuffers_Library_SRCS), Release flags
for f in idl_parser idl_gen_text reflection util; do
  [ $O/obj/$f.o -nt $FB/src/$f.cpp ] || g++ -std=c++17 -O3 -DNDEBUG -I$FB/include -c $FB/src/$f.cpp -o $O/obj/$f.o
done
[ -f $O/obj/simdjson.o ] || g++ -std=c++17 -O3 -DNDEBUG -I$SJ/singleheader -c $SJ/singleheader/simdjson.cpp -o $O/obj/simdjson.o
g++ -std=c++17 -O2 -DNDEBUG -I$O/include -I$FB/include -I$SJ/singleheader -I$W/headers -I$W/shared_modules/router/include \
  -I$W/shared_modules/router/src -o $O/fb_oracle $HERE/fb_harness.cpp $O/obj/*.o
echo built $O/fb_oracle
