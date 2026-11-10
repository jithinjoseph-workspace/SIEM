#!/bin/bash
# Compile Wazuh's logtest pipeline into an oracle harness (run inside WSL).
set -u
cd "$(dirname "$0")"
S=src
CFLAGS="-O1 -w -g -DOSSECHIDS -DUSER=\"wazuh\" -DGROUPGLOBAL=\"wazuh\" -I$S -I$S/headers -iquote $S/analysisd -I$S/external -I$S/shared_modules/common -Icjson -Ishim"
FILES="
$S/analysisd/cleanevent.c $S/analysisd/eventinfo.c $S/analysisd/eventinfo_list.c
$S/analysisd/decoders/decoder.c $S/analysisd/decoders/decode-xml.c $S/analysisd/decoders/decoders_list.c
$S/analysisd/decoders/plugin_decoders.c $S/analysisd/decoders/plugins/json_decoder.c
$S/analysisd/decoders/plugins/pf_decoder.c $S/analysisd/decoders/plugins/sonicwall_decoder.c
$S/analysisd/decoders/plugins/symantecws_decoder.c $S/analysisd/decoders/plugins/ossecalert_decoder.c
$S/analysisd/rules.c $S/analysisd/rules_list.c $S/analysisd/lists.c $S/analysisd/lists_list.c $S/analysisd/lists_make.c
$S/analysisd/cdb/cdb.c $S/analysisd/cdb/cdb_make.c $S/analysisd/cdb/cdb_hash.c $S/analysisd/cdb/uint32_pack.c $S/analysisd/cdb/uint32_unpack.c
$S/analysisd/fts.c $S/analysisd/accumulator.c $S/analysisd/dodiff.c
$S/analysisd/format/to_json.c $S/analysisd/format/json_extended.c $S/analysisd/logmsg.c $S/analysisd/logtest.c
$S/analysisd/compiled_rules/generic_samples.c
$S/shared/expression.c $S/shared/list_op.c $S/shared/store_op.c $S/shared/hash_op.c $S/shared/string_op.c
$S/shared/validate_op.c $S/shared/mem_op.c $S/shared/labels_op.c $S/shared/syscheck_op.c
$S/config/rules-config.c $S/config/alerts-config.c
$S/shared/math_op.c $S/os_regex/*.c $S/os_xml/*.c cjson/cJSON.c
"
mode=${1:-link}
if [ "$mode" = "check" ]; then
  for f in $FILES; do
    out=$(gcc $CFLAGS -c "$f" -o /tmp/o.o 2>&1 | grep -E "error|fatal" | head -3)
    [ -n "$out" ] && echo "== $f" && echo "$out"
  done
  exit 0
fi
if [ "$mode" = "ad" ]; then
  rm -f ad_oracle
  cp adshim/wazuh_db/helpers/wdb_global_helpers.h $S/wazuh_db/helpers/
  # analysisd.c's ruleset hot reload (from w_hotreload_reload to the end)
  sed -n '/^bool w_hotreload_reload(OSList \* list_msg) {/,$p' $S/analysisd/analysisd.c > hotreload.inc
  [ -s hotreload.inc ] || { echo "error: hot reload code not found"; exit 1; }
  # analysisd event path: alert/archive/firewall writers and active responses
  ADFILES="$S/analysisd/alerts/log.c $S/analysisd/alerts/exec.c $S/analysisd/alerts/getloglocation.c
  $S/analysisd/output/jsonout.c $S/analysisd/ar_json.c $S/analysisd/active-response.c $S/config/active-response.c $S/config/global-config.c $S/shared/custom_output_search_replace.c
  $S/analysisd/limits.c $S/shared/queue_op.c $S/analysisd/mitre.c
  $S/analysisd/config.c $S/analysisd/config_json.c $S/config/logtest-config.c
  $S/analysisd/decoders/rootcheck.c $S/shared/rootcheck_op.c
  $S/analysisd/decoders/hostinfo.c $S/analysisd/decoders/ciscat.c $S/analysisd/decoders/dbsync.c $S/analysisd/decoders/winevtchannel.c
  $S/analysisd/decoders/syscheck.c $S/analysisd/decoders/syscollector.c"
  gcc -Iadshim $CFLAGS -Werror=implicit-function-declaration -DAD_ORACLE -Dgettimeofday=oracle_gettimeofday '-Dtime(t)=oracle_time(t)' ${EXTRA:-} -o ad_oracle ad_harness.c shim/stubs.c $FILES $ADFILES /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 -lcrypto -lpthread -lm 2>&1 | grep -E "error|undefined|multiple definition" | sort -u | head -80
  exit 0
fi
gcc $CFLAGS ${EXTRA:-} -o logtest_oracle harness.c shim/stubs.c $FILES /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0 -lpthread -lm 2>&1 | grep -E "error|undefined|multiple definition" | sort -u | head -80
