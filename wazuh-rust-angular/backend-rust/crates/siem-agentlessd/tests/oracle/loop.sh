#!/bin/bash
# wazuh-agentlessd oracle: C and Rust daemons side by side on the same fake
# agentless scripts (WSL, as root; the daemons drop to nobody).
# usage: loop.sh <rust wazuh-agentlessd> [seconds, default 270]
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"; SECS="${2:-270}"; C=/home/jithin/lessd_oracle/c_agentlessd
W=/tmp/lessd_loop; rm -rf "$W"
OPTS=/mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf
mkhome() {  # <home> <bin>
  local home="$1"
  mkdir -p "$home/etc" "$home/agentless" "$home/out" "$home/var/run" "$home/queue/sockets" "$home/queue/agentless" "$home/queue/diff" "$home/bin" "$home/logs"
  cp "$OPTS" "$home/etc/"
  cp "$H"/scripts/* "$home/agentless/"; chmod 755 "$home"/agentless/*; chmod 777 "$home/agentless/fake_writable"
  cp "$2" "$home/bin/wazuh-agentlessd"
  touch "$home/logs/ossec.log"; chmod 666 "$home/logs/ossec.log"
  chmod -R a+rX "$home"; chmod 777 "$home/out" "$home/logs" "$home/var/run" "$home/queue/sockets" "$home/queue/agentless" "$home/queue/diff"
}
# Rust ossec.log -> "LEVEL: msg" like the C stub's MON_LOG
norm_rust_log() { sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-agentlessd(\[[0-9]+\] [^ ]+ at [^ ]+)?: ##' "$1" | grep -v -e 'Logging module auto-initialized' -e "Element 'log_format' without"; }

# 1. configuration errors (-t)
i=0
while IFS= read -r body; do
  i=$((i+1))
  for impl in c rust; do
    home="$W/cfg$i/$impl"; mkhome "$home" "$([ $impl = c ] && echo $C || echo $RUST)"
    echo "<ossec_config>$body</ossec_config>" > "$home/etc/ossec.conf"
    (cd "$home" && MON_LOG="$home/out/log" ./bin/wazuh-agentlessd -t -u nobody -g nogroup; echo "exit $?" >> "$home/out/log") 2>/dev/null
    [ $impl = rust ] && { norm_rust_log "$home/logs/ossec.log" > "$home/out/log.tmp"; grep '^exit' "$home/out/log" >> "$home/out/log.tmp"; mv "$home/out/log.tmp" "$home/out/log"; }
  done
  if cmp -s "$W/cfg$i/c/out/log" "$W/cfg$i/rust/out/log"; then echo "== config $i identical: $(tr '\n' '|' < "$W/cfg$i/c/out/log")"; else echo "== config $i DIFFERENT"; diff "$W/cfg$i/c/out/log" "$W/cfg$i/rust/out/log"; fi
done <<'CFGS'
<agentless><type>missing_script</type><host>a@b</host><state>periodic</state></agentless>
<agentless><type>../etc/ossec.conf</type><host>a@b</host><state>periodic</state></agentless>
<agentless><type>fake_check</type><host>a@b</host><state>sometimes</state></agentless>
<agentless><type>fake_check</type><host>a@b</host><state>periodic</state><frequency>1h</frequency></agentless>
<agentless><type>fake_check</type><host>a@b</host><state>periodic</state><bogus>1</bogus></agentless>
<agentless><type>fake_check</type><state>periodic</state></agentless>
<agentless><type>fake_check</type><host>a@b</host><state>periodic</state><frequency>0</frequency></agentless>
<agentless><type>fake_check</type><host>a@b</host><state>periodic_diff</state><frequency>0</frequency></agentless>
<agentless><type>fake_check</type><host>a@b</host><state>periodic</state><port>x</port></agentless>
<agentless><type>fake_check</type><host></host><state>periodic</state></agentless>
<global><x>1</x></global>
CFGS

# 2. the daemon loop
for impl in c rust; do
  home="$W/$impl"; mkhome "$home" "$([ $impl = c ] && echo $C || echo $RUST)"
  cat > "$home/etc/ossec.conf" <<'CONF'
<ossec_config>
  <agentless><type>fake_check</type><frequency>1</frequency><host>user@h1</host><host>root@h2</host><state>periodic</state><arguments>a  b /etc</arguments><port>22</port></agentless>
  <agentless><type>fake_diff</type><frequency>1</frequency><host>a@d1</host><host>b@d2</host><state>periodic_diff</state></agentless>
  <agentless><type>fake_err</type><frequency>1</frequency><host>e@x</host><state>periodic</state></agentless>
  <agentless><type>fake_testfail</type><host>t@x</host><state>periodic</state></agentless>
  <agentless><type>fake_writable</type><frequency>1</frequency><host>w@x</host><state>periodic</state></agentless>
  <agentless><type>fake_check</type><host>s@x</host><state>stay_connected</state><run_command>show run</run_command></agentless>
</ossec_config>
CONF
  (cd "$home" && exec python3 "$H/qrecv.py") & echo $! > "$home/out/qpid"
  for _ in $(seq 50); do [ -e "$home/out/queue_ready" ] && break; sleep 0.1; done
  (cd "$home" && MON_LOG="$home/out/log" exec ./bin/wazuh-agentlessd -f -d -u nobody -g nogroup 2>/dev/null) & echo $! > "$home/out/dpid"
done
sleep 8
for impl in c rust; do (cd "$W/$impl" && python3 "$H/lesscom.py" > out/lesscom.log); done
sleep "$SECS"
for impl in c rust; do
  home="$W/$impl"
  kill "$(cat "$home/out/dpid")" "$(cat "$home/out/qpid")" 2>/dev/null
done
wait 2>/dev/null
for impl in c rust; do
  home="$W/$impl"
  [ $impl = rust ] && norm_rust_log "$home/logs/ossec.log" > "$home/out/log"
  sed -i -E 's/pid: [0-9]+/pid: N/; /SIGNAL/d; /Chrooted to directory/d; /home directory/d; /Local requests thread ready/d; /Connected succesfully to/d; /Maximum send buffer set to/d' "$home/out/log"
  # the tree of state files; timestamps in the diff/state names differ between runs
  (cd "$home/queue" && find agentless diff -type f | sort | while read -r f; do echo "### $f" | sed -E 's/\.[0-9]{9,}/.TS/'; cat "$f"; done) > "$home/out/tree"
  rm -f "$home/out/qpid" "$home/out/dpid" "$home/out/queue_ready"
done
for f in queue.log argv.log lesscom.log tree log; do
  if cmp -s "$W/c/out/$f" "$W/rust/out/$f"; then echo "== $f identical ($(wc -l < "$W/c/out/$f") lines)"; else echo "== $f DIFFERENT"; diff "$W/c/out/$f" "$W/rust/out/$f" | cut -c1-300 | head -30; fi
done
# what the run exercised
q="$W/rust/out/queue.log"
echo "-- syscheck '8:' msgs: $(grep -c '^8:' "$q"), log '1:' msgs: $(grep -c '^1:(fake_check)' "$q"), diff alerts: $(grep -c 'Change detected' "$q"), truncated ('More changes...'): $(grep -c 'More changes\.\.\.' "$q"), longest datagram: $(awk '{print length}' "$q" | sort -n | tail -1)"
grep -E 'Test |Expect|write perm|Ignoring' "$W/rust/out/log" | sed 's/^/-- /'
