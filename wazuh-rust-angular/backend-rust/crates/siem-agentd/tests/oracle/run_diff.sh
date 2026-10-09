#!/bin/bash
# Differential test: the C wazuh-agentd (Wazuh 4.14.7 build) against the
# Rust port, each connected to its own fake manager playing the same
# script. Run as root in WSL (the agents drop to USER/GROUP):
#
#   wsl -d Ubuntu-20.04 -u root -- bash run_diff.sh
#
# Output: $D/{c,rs}/logs/ossec.log, $D/{c,rs}.manager.log and the
# normalised versions *.norm, then a diff of each pair.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
USER_NAME=${USER_NAME:-jithin}
CSRC=${CSRC:-/home/$USER_NAME/wazuh-agent-src}
RSBIN=${RSBIN:-/home/$USER_NAME/rs-target/debug}
D=${D:-/home/$USER_NAME/agentd-diff}
DURATION=${DURATION:-45}
KEY=7f1a9b4c2d3e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8

pkill -f "$D/" 2>/dev/null
sleep 1
rm -rf "$D"
mkdir -p "$D"

mk_home() {
    local h=$1 port=$2
    mkdir -p "$h"/{bin,etc/shared,logs,queue/sockets,queue/rids,queue/alerts,var/run,tmp}
    cp "$CSRC/etc/internal_options.conf" "$h/etc/"
    cat > "$h/etc/local_internal_options.conf" <<EOF
agent.debug=2
agent.state_interval=2
EOF
    echo "001 agent-diff any $KEY" > "$h/etc/client.keys"
    cat > "$h/etc/ossec.conf" <<EOF
<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
      <port>$port</port>
      <protocol>tcp</protocol>
      <max_retries>2</max_retries>
      <retry_interval>2</retry_interval>
    </server>
    <config-profile>diffprofile</config-profile>
    <notify_time>4</notify_time>
    <time-reconnect>30</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    <enrollment><enabled>no</enabled></enrollment>
  </client>
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>
  <labels>
    <label key="aws.instance-id">i-0123</label>
    <label key="secret" hidden="yes">s3cr3t</label>
  </labels>
  <logging><log_format>plain</log_format></logging>
</ossec_config>
EOF
    chown -R "$USER_NAME:$USER_NAME" "$h"
}

mk_home "$D/c" 15140
mk_home "$D/rs" 15141
cp "$CSRC/src/wazuh-agentd" "$D/c/bin/wazuh-agentd"
cp "$RSBIN/wazuh-agentd" "$D/rs/bin/wazuh-agentd"

# merged.mg with one agent.conf
cat > "$D/agent.conf" <<'EOF'
<agent_config>
  <labels>
    <label key="team">blue</label>
  </labels>
</agent_config>
EOF
printf '!%d agent.conf\n' "$(stat -c %s "$D/agent.conf")" > "$D/merged.mg"
cat "$D/agent.conf" >> "$D/merged.mg"

sed "s#@MERGED@#$D/merged.mg#" "$HERE/script.txt" > "$D/script.txt"

"$RSBIN/examples/fake_manager" 15140 "$D/c/etc/client.keys" "$D/c.manager.log" "$D/script.txt" &
"$RSBIN/examples/fake_manager" 15141 "$D/rs/etc/client.keys" "$D/rs.manager.log" "$D/script.txt" &
sleep 0.5

(cd "$D/c" && LD_LIBRARY_PATH="$CSRC/src" ./bin/wazuh-agentd -f -u "$USER_NAME" -g "$USER_NAME" > "$D/c.stderr" 2>&1) &
(cd "$D/rs" && ./bin/wazuh-agentd -f -u "$USER_NAME" -g "$USER_NAME" > "$D/rs.stderr" 2>&1) &

# local events through queue/sockets/queue
sleep 6
for h in c rs; do
    python3 - "$D/$h/queue/sockets/queue" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
for i in range(20):
    s.sendto(b"1:/var/log/diff.log:event number %d" % i, sys.argv[1])
s.sendto(b"1:/var/log/diff.log:" + b"x" * 70000, sys.argv[1])
EOF
done

sleep 10
pkill -USR1 -f "$D/c/bin/wazuh-agentd"
pkill -USR1 -f "$D/rs/bin/wazuh-agentd"

sleep $((DURATION - 16))
pkill -TERM -f "$D/c/bin/wazuh-agentd"
pkill -TERM -f "$D/rs/bin/wazuh-agentd"
sleep 2
pkill -f "examples/fake_manager" 2>/dev/null

for h in c rs; do
    cp "$D/$h/var/run/wazuh-agentd.state" "$D/$h.state" 2>/dev/null
    # timestamps, pids, debug locations, run-dependent values
    sed -E \
        -e 's/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9:]{8} //' \
        -e 's/^wazuh-agentd\[[0-9]+\] [^ ]+ at [^ ]+\(\): /wazuh-agentd: /' \
        -e 's/\(pid: [0-9]+\)/(pid: N)/' \
        -e 's/(ptr: 0x[0-9a-f]+)/(ptr: P)/' \
        "$D/$h/logs/ossec.log" > "$D/$h.ossec.norm"
    sed -E \
        -e 's/^ *[0-9.]+ //' \
        -e 's/\[[0-9]+:[0-9]+\] /[G:L] /' \
        -e 's/"(last_keepalive|last_ack)":"[^"]*"/"\1":"T"/g' \
        "$D/$h.manager.log" > "$D/$h.manager.norm"
done
echo "=== ossec.log (C <, Rust >)"
diff "$D/c.ossec.norm" "$D/rs.ossec.norm"
echo "=== manager view (C <, Rust >)"
diff "$D/c.manager.norm" "$D/rs.manager.norm"
echo "=== state file"
diff <(grep -v "^last_" "$D/c.state") <(grep -v "^last_" "$D/rs.state")
echo "=== stderr"
diff "$D/c.stderr" "$D/rs.stderr"
