#!/bin/bash
# Prepare the analysisd C oracle build tree (run on Linux / WSL).
#
#   setup.sh <wazuh-4.14.7-src-dir> <cJSON-1.7.18-dir> <work-dir>
#
# Copies the parts of Wazuh's src/ the logtest pipeline needs into
# <work-dir>/src, trims headers/shared.h of the includes that pull external
# libraries the pipeline does not use, renames analysisd/limits.h (it shadows
# the system <limits.h>), and adds the overlay headers and shims. Then run
# <work-dir>/build.sh.
set -eu
W=$1
CJ=$2
OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)

rm -rf "$OUT"
mkdir -p "$OUT/src" "$OUT/cjson" "$OUT/shim"
for d in headers analysisd shared os_regex os_xml config error_messages os_net os_crypto os_execd wazuh_db; do
    cp -r "$W/$d" "$OUT/src/"
done
mkdir -p "$OUT/src/syscheckd" "$OUT/src/shared_modules" "$OUT/src/external/cJSON" "$OUT/src/analysisd/external/cJSON"
cp -r "$W/syscheckd/include" "$OUT/src/syscheckd/"
mkdir -p "$OUT/src/remoted" && cp "$W"/remoted/*.h "$OUT/src/remoted/"
cp -r "$W/shared_modules/common" "$OUT/src/shared_modules/"
cp "$CJ/cJSON.c" "$CJ/cJSON.h" "$OUT/cjson/"
cp "$CJ/cJSON.c" "$CJ/cJSON.h" "$OUT/src/external/cJSON/"
cp "$CJ/cJSON.c" "$CJ/cJSON.h" "$OUT/src/analysisd/external/cJSON/"

cp -r "$HERE/overlay/." "$OUT/src/"
cp -r "$HERE/shim/." "$OUT/shim/"
cp -r "$HERE/adshim" "$OUT/"
cp "$HERE/harness.c" "$HERE/ad_harness.c" "$HERE/build.sh" "$OUT/"
chmod +x "$OUT/build.sh"

# analysisd/limits.h shadows <limits.h>
mv "$OUT/src/analysisd/limits.h" "$OUT/src/analysisd/eps_limits.h"
grep -rl '#include "limits.h"' "$OUT/src" | xargs -r sed -i 's/#include "limits.h"/#include "eps_limits.h"/'

# drop includes of headers that need curl/yaml/openssl/sqlite/rsync/dbsync
for h in custom_output_search.h url.h yaml2json.h auth_client.h schedule_scan.h bzip2_op.h \
         enrollment_op.h ../shared_modules/rsync/include/rsync.h ../shared_modules/dbsync/include/dbsync.h \
         regex_op.h logging_helper.h binaries_op.h os_utils.h ../unit_tests/wrappers/common.h; do
    sed -i "s|#include \"$h\"|/* oracle: dropped $h */|" "$OUT/src/headers/shared.h"
done
echo "oracle tree ready in $OUT; now run $OUT/build.sh"
