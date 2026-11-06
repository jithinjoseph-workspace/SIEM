#!/bin/bash
# Runs every scenario with the C oracle and the Rust port (as root: the fake SMTP server uses port 25), then diffs.
# usage (WSL, root): run.sh <rust mail_oracle binary> [scenario-filter]
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"; FILTER="${2:-}"
C=/home/jithin/mail_oracle/mail_oracle
IOPT=/mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf
W=/home/jithin/mail_oracle/work
rm -rf "$W"; mkdir -p "$W"
fail=0
for sc in "$H"/scenarios/*${FILTER}*/; do
  name=$(basename "$sc")
  for impl in c rust; do
    home="$W/$name/$impl"; mkdir -p "$home/etc" "$home/logs/alerts" "$home/out" "$home/queue/sockets"
    cp "$IOPT" "$home/etc/internal_options.conf"
    ( cd "$home" && bash "$sc/setup.sh" )
    python3 "$H/fake_smtp.py" "$sc/script.json" "$home/out" & fpid=$!
    for _ in $(seq 50); do [ -e "$home/out/smtp_ready" ] && break; sleep 0.1; done
    if [ $impl = c ]; then
      ( cd "$home" && MON_LOG="$home/out/c.log" timeout 120 "$C" < "$sc/cmds.txt" > out/stdout 2>&1; echo "exit $?" >> out/stdout )
      cp "$home/out/c.log" "$home/out/log" 2>/dev/null || touch "$home/out/log"
    else
      mkdir -p "$home/out/rlog/etc" "$home/out/rlog/logs"; echo "<ossec_config/>" > "$home/out/rlog/etc/ossec.conf"
      ( cd "$home" && MON_RLOG="$home/out/rlog" timeout 120 "$RUST" < "$sc/cmds.txt" > out/stdout 2>&1; echo "exit $?" >> out/stdout )
      sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-maild([[0-9]+] [^ ]+ at [^ ]+)?: ##' "$home/out/rlog/logs/ossec.log" 2>/dev/null | grep -v -e "Element 'log_format' without" -e 'Logging module auto-initialized' > "$home/out/log" || true
    fi
    sleep 0.5; kill $fpid 2>/dev/null; wait $fpid 2>/dev/null
    rm -f "$home/out/smtp_ready" "$home/out/c.log"; rm -rf "$home/out/rlog"
  done
  if diff -r "$W/$name/c/out" "$W/$name/rust/out" > "$W/$name.diff"; then
    echo "== $name: identical ($(wc -l < "$W/$name/c/out/stdout") output lines, $(wc -l < "$W/$name/c/out/log") log lines, $(ls "$W/$name/c/out" | grep -c smtp-) SMTP sessions)"
  else
    echo "== $name: DIFFERENT"; head -60 "$W/$name.diff"; fail=1
  fi
done
exit $fail
