#!/bin/bash
# The Python integration scripts vs the Rust `integrations` program (WSL).
# usage: run_scripts.sh <rust integrations binary>
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"
SRC=/mnt/e/wazhu-Siem-code/wazuh/wazuh-4.14.7/integrations
W=$HOME/intg_oracle/scripts; rm -rf "$W"; mkdir -p "$W/cases"
python3 "$H/scenarios.py" "$W/cases" >/dev/null
port=18600; fail=0
for case in "$W"/cases/*/; do
  name=$(basename "$case"); script=$(python3 -c "import json;print(json.load(open('$case/case.json'))['script'])")
  for impl in py rust; do
    port=$((port+1)); home="$W/run/$name/$impl"; mkdir -p "$home/integrations" "$home/logs" "$home/out" "$home/queue/sockets"
    cp "$case"/alert.json "$case"/x.options "$home/" 2>/dev/null
    sed "s#PORT#$port#g" "$case/case.json" > "$home/case.json"
    python3 "$H/fake_http.py" $port "$home/case.json" "$home" & fpid=$!
    for _ in $(seq 50); do [ -e "$home/out/ready" ] && break; sleep 0.1; done
    mapfile -t ARGS < <(python3 -c "import json;[print(a) for a in json.load(open('$home/case.json'))['args']]")
    if [ $impl = py ]; then
      # oracle copy: vendor URLs to the fake server; Python 3.8 needs deferred annotations
      { echo "from __future__ import annotations"; sed -e "s#https://events.pagerduty.com#http://127.0.0.1:$port#; s#https://www.virustotal.com#http://127.0.0.1:$port#" "$SRC/$script.py"; } > "$home/integrations/$script.py"
      ( cd "$home" && timeout 60 python3 "integrations/$script.py" "${ARGS[@]}" > out/stdout 2> out/stderr; echo "exit $?" >> out/stdout )
    else
      cp "$RUST" "$home/integrations/$script"
      ( cd "$home" && SIEM_INTEGRATIONS_URL_OVERRIDE="$( [ $script = pagerduty ] && echo https://events.pagerduty.com=http://127.0.0.1:$port || echo https://www.virustotal.com=http://127.0.0.1:$port )" \
          timeout 60 "integrations/$script" "${ARGS[@]}" > out/stdout 2> out/stderr; echo "exit $?" >> out/stdout )
    fi
    sleep 0.3; kill $fpid 2>/dev/null; wait $fpid 2>/dev/null
    tail -n 1 "$home/out/stderr" > "$home/out/stderr.last"; rm -f "$home/out/stderr" "$home/out/ready"
    cp "$home/logs/integrations.log" "$home/out/" 2>/dev/null
    # the port differs between the two runs
    sed -i "s#127.0.0.1:$port#127.0.0.1:PORT#g" "$home"/out/* 2>/dev/null
  done
  if diff -r "$W/run/$name/py/out" "$W/run/$name/rust/out" > "$W/$name.diff"; then
    echo "== $name: identical ($(cat "$W/run/$name/py/out/http.log" 2>/dev/null | wc -l) HTTP, $(cat "$W/run/$name/py/out/queue.log" 2>/dev/null | wc -l) queue, $(tail -1 "$W/run/$name/py/out/stdout"))"
  else
    echo "== $name: DIFFERENT"; head -30 "$W/$name.diff"; fail=1
  fi
done
exit $fail
