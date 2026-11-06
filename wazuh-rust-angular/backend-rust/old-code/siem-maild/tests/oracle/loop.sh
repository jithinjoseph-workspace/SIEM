#!/bin/bash
# OS_Run oracle: the real C and Rust wazuh-maild daemons on the same alert timeline (WSL, root).
# usage: loop.sh <rust wazuh-maild binary>
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"; C=/home/jithin/mail_oracle/c_maild
IOPT=/mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf
W=/home/jithin/mail_oracle/loop; rm -rf "$W"
for impl in c rust; do
  home="$W/$impl"; mkdir -p "$home/etc" "$home/logs/alerts" "$home/out" "$home/var/run" "$home/queue/sockets"
  cp "$IOPT" "$home/etc/internal_options.conf"
  cp "$H/scenarios/03_json/setup.sh" "$home/setup.sh"; ( cd "$home" && bash setup.sh ); : > "$home/logs/alerts/alerts.json"
  echo '{}' > "$home/script.json"
  python3 "$H/fake_smtp.py" "$home/script.json" "$home/out" & fpid=$!
  for _ in $(seq 50); do [ -e "$home/out/smtp_ready" ] && break; sleep 0.1; done
  if [ $impl = c ]; then MON_LOG="$home/out/log" "$C" -f -u root -g root -D "$home" & dpid=$!
  else "$RUST" -f -u root -g root -D "$home" & dpid=$!; fi
  sleep 3
  A="$home/logs/alerts/alerts.json"
  python3 "$H/timeline.py" "$A"
  sleep 8
  kill $dpid; wait $dpid 2>/dev/null; kill $fpid; wait $fpid 2>/dev/null
  if [ $impl = rust ]; then sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-maild([[0-9]+] [^ ]+ at [^ ]+)?: ##' "$home/logs/ossec.log" | grep -v -e "Element 'log_format' without" -e 'Logging module auto-initialized' > "$home/out/log"; fi
  # sessions in any order (C forks race): compare the sorted set
  ( cd "$home/out" && for f in smtp-*.log; do sha1sum < "$f" | cut -c1-12; done | sort > sessions; rm -f smtp_ready )
done
for f in sessions; do diff "$W/c/out/$f" "$W/rust/out/$f" && echo "== loop: $(wc -l < "$W/c/out/sessions") SMTP sessions identical" || { echo "== loop: DIFFERENT"; for i in c rust; do echo "-- $i"; for s in $W/$i/out/smtp-*.log; do echo "## $s"; head -c 400 "$s"; echo; done; done; }; done
grep -v "DEBUG" "$W/c/out/log" | sed -E 's/pid: [0-9]+/pid: N/' > "$W/c.loglines"; grep -v "DEBUG" "$W/rust/out/log" | sed -E 's/pid: [0-9]+/pid: N/' > "$W/rust.loglines"
diff "$W/c.loglines" "$W/rust.loglines" && echo "== loop: non-debug log identical" || true
