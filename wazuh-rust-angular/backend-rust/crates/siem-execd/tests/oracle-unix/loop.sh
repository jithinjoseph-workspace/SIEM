#!/bin/bash
# ExecdStart oracle: the C and Rust wazuh-execd on the same exec-queue messages (WSL, root).
# usage: loop.sh <rust wazuh-execd>
set -u
H="$(cd "$(dirname "$0")" && pwd)"
RUST="$1"; C=/home/jithin/execd_oracle/c_execd
W=/tmp/execd_loop; rm -rf "$W"
for impl in c rust; do
  home="$W/$impl"
  mkdir -p "$home/etc/shared" "$home/logs" "$home/out" "$home/var/run" "$home/queue/alerts" "$home/queue/sockets" "$home/bin" "$home/active-response/bin"
  cp /mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust/data/manager/etc/internal_options.conf "$home/etc/"
  cat > "$home/etc/ossec.conf" <<'EOF'
<ossec_config>
  <active-response>
    <disabled>no</disabled>
    <repeated_offenders>1,2</repeated_offenders>
  </active-response>
</ossec_config>
EOF
  printf 'reckeys3 - rec-keys - 3\nrec0 - rec-plain - 0\nnoscript5 - missing-script - 5\n' > "$home/etc/shared/ar.conf"
  cat > "$home/active-response/bin/rec-keys" <<'EOF'
#!/bin/sh
d="$(dirname "$0")/../.."
n=$(basename "$0")
read -r line
echo "== $n args=[$*] in=$line" >> "$d/out/ar.log"
case "$line" in
  *'"command":"add"'*)
    ip=$(echo "$line" | sed -n 's/.*"srcip":"\([^"]*\)".*/\1/p')
    echo "{\"version\":1,\"origin\":{\"name\":\"$n\",\"module\":\"active-response\"},\"command\":\"check_keys\",\"parameters\":{\"keys\":[\"$ip\"]}}"
    read -r resp
    echo "   resp=$resp" >> "$d/out/ar.log";;
esac
EOF
  cp "$home/active-response/bin/rec-keys" "$home/active-response/bin/rec-plain"
  sed -i 's/\*.\x27"command":"add"\x27\*)/*NEVERMATCH*)/' "$home/active-response/bin/rec-plain"
  chmod 755 "$home"/active-response/bin/*
  : > "$home/logs/ossec.log"; chmod 666 "$home/logs/ossec.log"
  if [ $impl = c ]; then cp "$C" "$home/bin/wazuh-execd"; else cp "$RUST" "$home/bin/wazuh-execd"; fi
  MON_LOG="$home/out/log" "$home/bin/wazuh-execd" -f -d -d -g root & dpid=$!
  for _ in $(seq 50); do [ -S "$home/queue/alerts/execq" ] && break; sleep 0.1; done
  python3 "$H/execq_msgs.py" "$home/queue/alerts/execq"
  sleep 8
  kill $dpid; wait $dpid 2>/dev/null
  if [ $impl = rust ]; then
    sed -E 's#^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9:]{8} wazuh-execd([[0-9]+] [^ ]+ at [^ ]+)?: ##' "$home/logs/ossec.log" | grep -v -e "Element 'log_format' without" -e 'Logging module auto-initialized' > "$home/out/log"
  fi
  sed -i -E 's/pid: [0-9]+/pid: N/; /SIGNAL/d; /home directory/d; /Chrooted/d' "$home/out/log"
done
diff "$W/c/out/ar.log" "$W/rust/out/ar.log" > /dev/null && echo "== script calls identical ($(grep -c '^== ' "$W/c/out/ar.log") calls)" || { echo "== script calls DIFFERENT"; diff "$W/c/out/ar.log" "$W/rust/out/ar.log" | cut -c1-300 | head -30; }
diff "$W/c/out/log" "$W/rust/out/log" > /dev/null && echo "== log identical ($(wc -l < "$W/c/out/log") lines)" || { echo "== log DIFFERENT"; diff "$W/c/out/log" "$W/rust/out/log" | cut -c1-300 | head -40; }
