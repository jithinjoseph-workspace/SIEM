#!/bin/bash
# OS_CSyslogD oracle: C and Rust wazuh-csyslogd on the same alerts (WSL, root -> nobody).
# usage: loop.sh <rust wazuh-csyslogd>
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"; C=/home/jithin/csys_oracle/c_csyslogd
W=/tmp/csys_loop; rm -rf "$W"
for impl in c rust; do
  home="$W/$impl"; base=$([ $impl = c ] && echo 15500 || echo 15600)
  mkdir -p "$home/etc" "$home/logs/alerts" "$home/out" "$home/var/run" "$home/queue/sockets" "$home/bin"
  cat > "$home/etc/ossec.conf" <<EOF
<ossec_config>
  <syslog_output><server>127.0.0.1</server><port>$((base+1))</port></syslog_output>
  <syslog_output><server>127.0.0.1</server><port>$((base+2))</port><format>cef</format><level>7</level></syslog_output>
  <syslog_output><server>127.0.0.1</server><port>$((base+3))</port><format>json</format><group>sshd|syscheck</group></syslog_output>
  <syslog_output><server>127.0.0.1</server><port>$((base+4))</port><format>splunk</format><rule_id>5716, 550,31101</rule_id><use_fqdn>yes</use_fqdn></syslog_output>
  <syslog_output><server>127.0.0.1</server><port>$((base+5))</port><format>json</format><location>auth.log</location><level>6</level></syslog_output>
  <syslog_output><server>localhost</server><port>$((base+6))</port><location>auth.log|secure</location></syslog_output>
  <syslog_output><server>127.0.0.1</server><port>$((base+7))</port><format>json</format><rule_id>31101</rule_id></syslog_output>
</ossec_config>
EOF
  cp /mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf "$home/etc/"
  : > "$home/logs/alerts/alerts.log"; : > "$home/logs/alerts/alerts.json"
  touch "$home/logs/ossec.log"; chmod 666 "$home/logs/ossec.log"
  chmod -R a+rX "$W"; chmod 777 "$home/out" "$home/logs" "$home/var/run" "$home/queue/sockets"
  python3 "$H/udp_recv.py" "$home/out" $(seq $((base+1)) $((base+7))) & upid=$!
  for _ in $(seq 50); do [ -e "$home/out/udp_ready" ] && break; sleep 0.1; done
  if [ $impl = c ]; then cp "$C" "$home/bin/wazuh-csyslogd"; else cp "$RUST" "$home/bin/wazuh-csyslogd"; fi
  MON_LOG="$home/out/log" "$home/bin/wazuh-csyslogd" -f -d -d -u nobody -g nogroup & dpid=$!
  sleep 3
  python3 "$H/csys_alerts.py" "$home"
  sleep 9
  kill $dpid; wait $dpid 2>/dev/null; kill $upid; wait $upid 2>/dev/null
  rm -f "$home/out/udp_ready"
  if [ $impl = rust ]; then
    sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-csyslogd([[0-9]+] [^ ]+ at [^ ]+)?: ##' "$home/logs/ossec.log" | grep -v -e "Element 'log_format' without" -e 'Logging module auto-initialized' > "$home/out/log"
  fi
  # ports differ between the runs; the same receiver order is compared
  for p in $(seq 1 7); do [ -f "$home/out/udp-$((base+p)).log" ] && mv "$home/out/udp-$((base+p)).log" "$home/out/server-$p.log"; done
  # an unparsable timestamp falls back to the current time
  sed -i -E '/bad-timestamp/s/^<([0-9]+)>[A-Z][a-z]{2} [ 0-9]{2} [0-9:]{8}/<>NOW/' "$home"/out/server-*.log "$home"/out/log
  sed -i -E "s/15[56]0([0-9])/PORT/g; s/pid: [0-9]+/pid: N/; /SIGNAL/d; /Chrooted to directory/d; /home directory/d; /Read_FileMon\(\)|jqueue_next\(\)/d" "$home"/out/log
done
for f in $(ls "$W/c/out" "$W/rust/out" | grep server- | sort -u); do
  if cmp -s "$W/c/out/$f" "$W/rust/out/$f"; then echo "== $f identical ($(wc -l < "$W/c/out/$f") messages)"; else echo "== $f DIFFERENT"; diff "$W/c/out/$f" "$W/rust/out/$f" | cut -c1-300 | head -10; fi
done
diff "$W/c/out/log" "$W/rust/out/log" > /dev/null && echo "== log identical ($(wc -l < "$W/c/out/log") lines)" || { echo "== log DIFFERENT"; diff "$W/c/out/log" "$W/rust/out/log" | cut -c1-300 | head -30; }
