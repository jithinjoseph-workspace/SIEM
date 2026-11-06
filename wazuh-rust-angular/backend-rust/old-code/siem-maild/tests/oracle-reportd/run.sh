#!/bin/bash
# wazuh-reportd oracle: the C and Rust reportd on the same alerts (stdin) and options. WSL, as root.
# usage: run.sh <rust wazuh-reportd> <alerts.log>
set -u
RUST="$1"; ALERTS="$2"; C=/home/jithin/reportd_oracle/c_reportd
W=/root/reportd_oracle_work; rm -rf "$W"; mkdir -p "$W"
cp "$ALERTS" "$W/alerts.log"
scen=(
  ""
  "-f level 7"
  "-f group authentication"
  "-f group syscheck"
  "-f rule 503"
  "-f location ->"
  "-f group authentication -r user srcip"
  "-f level 3 -r group location"
  "-s -n daily-test -f level 10"
  "-r rule level"
  "-f bogus x"
  "-t"
)
fail=0
for i in "${!scen[@]}"; do
  for impl in c rust; do
    h="$W/$impl$i"; mkdir -p "$h/logs" "$h/var/run" "$h/out" "$h/bin" "$h/etc"
    echo "<ossec_config></ossec_config>" > "$h/etc/ossec.conf"
    : > "$h/logs/ossec.log"; chmod 666 "$h/logs/ossec.log"
    if [ $impl = c ]; then cp "$C" "$h/bin/wazuh-reportd"; else cp "$RUST" "$h/bin/wazuh-reportd"; fi
    ( cd "$h" && MON_LOG="$h/out/log" timeout 60 "$h/bin/wazuh-reportd" -d -d -u root -g root -D "$h" ${scen[$i]} < "$W/alerts.log" > "$h/out/stdout" 2> "$h/out/stderr"; echo $? > "$h/out/rc" )
    if [ $impl = rust ]; then
      sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-reportd(\[[0-9]+\] [^ ]+ at [^ ]+)?: ##' "$h/logs/ossec.log" | grep -v -e "Logging module auto-initialized" -e "Element 'log_format' without" > "$h/out/log"
      # Rust prints its CRITICAL lines to stderr too (before daemonizing): keep only the report in stderr
      grep -v -E "^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-reportd" "$h/out/stderr" > "$h/out/stderr.r"; mv "$h/out/stderr.r" "$h/out/stderr"
    fi
    touch "$h/out/log"; sed -i -E "s/pid: [0-9]+/pid: N/; /SIGNAL/d; s|$h|HOME|g" "$h/out/log"
  done
  c="$W/c$i/out"; r="$W/rust$i/out"; ok=1
  for f in rc stderr stdout log; do
    if ! cmp -s "$c/$f" "$r/$f"; then ok=0; echo "  [$i '${scen[$i]}'] $f differs:"; diff "$c/$f" "$r/$f" | head -8 | cut -c1-200; fi
  done
  [ $ok = 1 ] && echo "== [$i] '${scen[$i]}': identical (rc $(cat $c/rc), report $(wc -l < $c/stderr) lines, log $(wc -l < $c/log) lines)" || fail=1
done
exit $fail
