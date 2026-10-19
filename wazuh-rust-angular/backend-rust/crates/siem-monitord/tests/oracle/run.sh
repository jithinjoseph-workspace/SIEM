#!/bin/bash
# Runs every scenario in scenarios/ with the C oracle and the Rust port, then diffs.
# usage (WSL): run.sh <rust mon_oracle binary>
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"
C=~/mon_oracle/mon_oracle
IOPT=/mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf
W=~/mon_oracle/work
rm -rf "$W"; mkdir -p "$W"
fail=0
for sc in "$H"/scenarios/*/; do
  name=$(basename "$sc")
  for impl in c rust; do
    home="$W/$name/$impl"; mkdir -p "$home/etc" "$home/logs" "$home/out"
    cp "$IOPT" "$home/etc/internal_options.conf"
    ( cd "$home" && bash "$sc/setup.sh" )
    ( cd "$home" && exec python3 "$H/fake.py" "$sc/script.json" ) & fpid=$!
    for _ in $(seq 50); do [ -e "$home/out/ready" ] && break; sleep 0.1; done
    if [ $impl = c ]; then
      ( cd "$home" && MON_LOG="$home/out/c.log" timeout 60 "$C" < <(sed "s/@ARGS@/$(date +%d) $(( $(date +%-m) - 1 )) $(date +%Y)/" "$sc/cmds.txt") > out/stdout 2>&1; echo "exit $?" >> out/stdout )
      sed -E 's/^/x /; s/^x //' "$home/out/c.log" > "$home/out/log" 2>/dev/null || true
    else
      mkdir -p "$home/out/rlog/etc" "$home/out/rlog/logs"; echo "<ossec_config/>" > "$home/out/rlog/etc/ossec.conf"
      ( cd "$home" && MON_RLOG="$home/out/rlog" timeout 60 "$RUST" < <(sed "s/@ARGS@/$(date +%d) $(( $(date +%-m) - 1 )) $(date +%Y)/" "$sc/cmds.txt") > out/stdout 2>&1; echo "exit $?" >> out/stdout )
      sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-monitord([[0-9]+] [^ ]+ at [^ ]+)?: ##' "$home/out/rlog/logs/ossec.log" | grep -v -e "Element 'log_format' without" -e 'Logging module auto-initialized' > "$home/out/log" 2>/dev/null || true
    fi
    kill $fpid 2>/dev/null; wait $fpid 2>/dev/null
    ( cd "$home" && find . -type f ! -path './out/*' ! -path './queue/*' ! -path './etc/*' | sort | while read -r f; do
        case "$f" in
          *.gz) echo "$f gz $(zcat "$f" | sha1sum | cut -c1-12)";;
          *.sum) echo "$f sum"; cat "$f";;
          *) echo "$f $(sha1sum < "$f" | cut -c1-12)";;
        esac
      done > out/tree )
    for f in wdb.log queue.log auth.log; do
      [ -f "$home/out/$f" ] && sed -E 's/[0-9]{10}/T/g' "$home/out/$f" | sort > "$home/out/$f.sorted" && rm "$home/out/$f"
    done
    rm -f "$home/out/ready" "$home/out/c.log"; rm -rf "$home/out/rlog"
  done
  if diff -r "$W/$name/c/out" "$W/$name/rust/out" > "$W/$name.diff"; then
    echo "== $name: identical ($(wc -l < "$W/$name/c/out/log") log lines, $(cat "$W/$name/c/out"/*.sorted 2>/dev/null | wc -l) socket records, $(wc -l < "$W/$name/c/out/tree") tree lines)"
  else
    echo "== $name: DIFFERENT"; head -40 "$W/$name.diff"; fail=1
  fi
done
exit $fail
