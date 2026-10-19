#!/bin/bash
# OS_IntegratorD oracle: the C and Rust wazuh-integratord on the same alerts (WSL, normal user:
# as root every script counts as writable and is refused).
# usage: loop.sh <rust wazuh-integratord> [debug|nodebug]
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"; MODE="${2:-debug}"
C=/home/jithin/intg_oracle/c_integratord
IOPT=/mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf
W=/tmp/intg_loop-$MODE; rm -rf "$W"
for impl in c rust; do
  home="$W/$impl"; mkdir -p "$home/etc" "$home/logs/alerts" "$home/out" "$home/var/run" "$home/queue/sockets" "$home/integrations"
  cp "$IOPT" "$home/etc/internal_options.conf"
  cat > "$home/etc/ossec.conf" <<'EOF'
<ossec_config>
  <integration>
    <name>custom-rec</name>
    <hook_url>https://hooks.example/x</hook_url>
    <api_key>KEY1</api_key>
    <level>7</level>
    <alert_format>json</alert_format>
    <options>{"channel": "#soc"}</options>
  </integration>
  <integration>
    <name>custom-rec2</name>
    <group>sshd,web,</group>
    <max_log>165</max_log>
    <timeout>5</timeout>
    <retries>1</retries>
  </integration>
  <integration>
    <name>custom-rec3</name>
    <rule_id>5712, 100,,x</rule_id>
    <event_location>web|auth</event_location>
    <alert_format>json</alert_format>
  </integration>
  <integration>
    <name>custom-fail</name>
    <level>12</level>
  </integration>
  <integration>
    <name>slack</name>
  </integration>
  <integration>
    <name>pagerduty</name>
    <api_key>K</api_key>
  </integration>
  <integration>
    <name>foo</name>
  </integration>
</ossec_config>
EOF
  cat > "$home/integrations/custom-rec" <<'EOF'
#!/bin/sh
d="$(dirname "$0")/.."
n=$(basename "$0")
{ echo "== $n"; for a in "$@"; do echo "arg=[$a]"; done; echo "-- alert"; cat "$1"; echo; echo "-- options"; [ -n "$5" ] && [ "$5" != "${5%options}" ] && cat "$5"; } >> "$d/out/rec.log"
echo "rec $n done"
EOF
  cp "$home/integrations/custom-rec" "$home/integrations/custom-rec2"; cp "$home/integrations/custom-rec" "$home/integrations/custom-rec3"
  printf '#!/bin/sh\necho "first line"\necho "boom: cannot reach service"\nexit 3\n' > "$home/integrations/custom-fail"
  printf '#!/bin/sh\nexit 0\n' > "$home/integrations/slack"; cp "$home/integrations/slack" "$home/integrations/foo"
  chmod 555 "$home"/integrations/*; chmod -R a+rX "$W"; chmod 777 "$home/out" "$home/logs" "$home/var/run" "$home/queue/sockets"
  : > "$home/logs/alerts/alerts.json"
  dflag=""; [ "$MODE" = debug ] && dflag="-d -d"
  # both daemons find their home from their own path (<home>/bin)
  mkdir -p "$home/bin"
  if [ $impl = c ]; then cp "$C" "$home/bin/wazuh-integratord"; else cp "$RUST" "$home/bin/wazuh-integratord"; fi
  MON_LOG="$home/out/log" "$home/bin/wazuh-integratord" -f $dflag -u nobody -g nogroup & dpid=$!
  sleep 2
  python3 "$H/intg_alerts.py" >> "$home/logs/alerts/alerts.json"
  sleep 6
  kill $dpid; wait $dpid 2>/dev/null
  if [ $impl = rust ]; then
    sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-integratord([[0-9]+] [^ ]+ at [^ ]+)?: ##' "$home/logs/ossec.log" | grep -v -e "Element 'log_format' without" -e 'Logging module auto-initialized' > "$home/out/log"
  fi
  # temp file names carry the time and a random number
  sed -i -E 's#/tmp/([a-z0-9-]+)-[0-9]+--?[0-9]+\.(alert|options)#/tmp/\1.\2#g; s/pid: [0-9]+/pid: N/; /SIGNAL/d; /Chrooted to directory/d; /home directory/d' "$home"/out/log "$home"/out/rec.log 2>/dev/null
done
diff "$W/c/out/rec.log" "$W/rust/out/rec.log" > /dev/null && echo "== loop $MODE: script calls identical ($(grep -c '^== ' "$W/c/out/rec.log") calls)" || { echo "== loop $MODE: script calls DIFFERENT"; diff "$W/c/out/rec.log" "$W/rust/out/rec.log" | head -40; }
diff "$W/c/out/log" "$W/rust/out/log" > /dev/null && echo "== loop $MODE: logs identical ($(wc -l < "$W/c/out/log") lines)" || { echo "== loop $MODE: logs DIFFERENT"; diff "$W/c/out/log" "$W/rust/out/log" | head -40; }
