#!/bin/bash
# Differential test: the C wazuh-agentd (Wazuh 4.14.7 build) against the
# Rust port, each connected to its own fake manager playing the same
# script. Run as root in WSL (the agents drop to USER_NAME):
#
#   wsl -d Ubuntu-20.04 -u root -- bash run_diff.sh [scenario]
#
# Scenarios (scenarios/<name>.env set the knobs below): default, udp,
# flood, verify, enroll, enroll_error, enroll_ca.
#
# Output in $D: {c,rs}/logs/ossec.log, {c,rs}.manager.log, the normalised
# *.norm files, and a diff of each pair.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
SCENARIO=${1:-default}
USER_NAME=${USER_NAME:-jithin}
CSRC=${CSRC:-/home/$USER_NAME/wazuh-agent-src}
RSBIN=${RSBIN:-/home/$USER_NAME/rs-target/debug}
D=${D:-/home/$USER_NAME/agentd-diff}
KEY=7f1a9b4c2d3e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8

# Knobs (overridden by the scenario file)
DURATION=45          # seconds the agents run
PROTO=tcp
QUEUE_SIZE=5000
EPS=500
EXTRA_OPTS=""        # extra local_internal_options lines
EVENTS=20            # local events sent through queue/sockets/queue
EVENT_BURSTS=1       # how many times the events are sent (1 s apart)
RELOAD_QUEUE=""      # queue_size written to ossec.conf before SIGUSR1
SCRIPT=script.txt    # manager script
ENROLL=no            # yes: empty client.keys, key from the fake authd
AUTHD_MODE=ok        # ok | error  (fake authd reply)
AUTHD_CA=no          # yes: verify the authd certificate (server_ca_path)
PREFILL_MB=0         # MB of filler written to logs/ossec.log (size rotation)
# shellcheck disable=SC1090
[ -f "$HERE/scenarios/$SCENARIO.env" ] && . "$HERE/scenarios/$SCENARIO.env"

pkill -f "$D/" 2>/dev/null
pkill -f "examples/fake_manager" 2>/dev/null
pkill -f "fake_authd.py" 2>/dev/null
sleep 1
rm -rf "$D"
mkdir -p "$D"

# TLS material for the fake authd
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout "$D/authd.key" -out "$D/authd.crt" >/dev/null 2>&1

mk_home() {
    local h=$1 port=$2 aport=$3
    mkdir -p "$h"/{bin,etc/shared,logs/wazuh,queue/sockets,queue/rids,queue/alerts,var/run,tmp}
    cp "$CSRC/etc/internal_options.conf" "$h/etc/"
    printf 'agent.debug=2\nagent.state_interval=2\n%b' "$EXTRA_OPTS" > "$h/etc/local_internal_options.conf"
    local enroll_block="<enrollment><enabled>no</enabled></enrollment>"
    if [ "$ENROLL" = yes ]; then
        : > "$h/etc/client.keys"
        echo "s3cr3tpass" > "$h/etc/authd.pass"
        local ca=""
        [ "$AUTHD_CA" = yes ] && ca="<server_ca_path>$D/authd.crt</server_ca_path>"
        enroll_block="<enrollment><enabled>yes</enabled><manager_address>localhost</manager_address><port>$aport</port><agent_name>agent-diff</agent_name><groups>default,linux</groups><delay_after_enrollment>1</delay_after_enrollment>$ca</enrollment>"
    else
        echo "001 agent-diff any $KEY" > "$h/etc/client.keys"
    fi
    cat > "$h/etc/ossec.conf" <<EOF
<ossec_config>
  <client>
    <server>
      <address>127.0.0.1</address>
      <port>$port</port>
      <protocol>$PROTO</protocol>
      <max_retries>2</max_retries>
      <retry_interval>2</retry_interval>
    </server>
    <config-profile>diffprofile</config-profile>
    <notify_time>4</notify_time>
    <time-reconnect>30</time-reconnect>
    <auto_restart>yes</auto_restart>
    <crypto_method>aes</crypto_method>
    $enroll_block
  </client>
  <client_buffer>
    <disabled>no</disabled>
    <queue_size>$QUEUE_SIZE</queue_size>
    <events_per_second>$EPS</events_per_second>
  </client_buffer>
  <labels>
    <label key="aws.instance-id">i-0123</label>
    <label key="secret" hidden="yes">s3cr3t</label>
  </labels>
  <logging><log_format>plain</log_format></logging>
</ossec_config>
EOF
    # created before the agent drops privileges, so it can keep writing them
    touch "$h/logs/ossec.log" "$h/logs/ossec.json"
    if [ "$PREFILL_MB" -gt 0 ]; then
        python3 -c "import sys; sys.stdout.write(('filler line ' + 'z' * 100 + '\n') * ($PREFILL_MB * 9800))" > "$h/logs/ossec.log"
    fi
    chown -R "$USER_NAME:$USER_NAME" "$h"
}

mk_home "$D/c" 15140 15150
mk_home "$D/rs" 15141 15151
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
sed "s#@MERGED@#$D/merged.mg#" "$HERE/$SCRIPT" > "$D/script.txt"

# the key the managers use (the enrolled one has the same content)
echo "001 agent-diff any $KEY" > "$D/manager.keys"

if [ "$ENROLL" = yes ]; then
    for p in 15150 15151; do
        python3 "$HERE/fake_authd.py" $p "$D/authd.crt" "$D/authd.key" "$AUTHD_MODE" \
            "001 agent-diff any $KEY" "$D/authd.$p.log" &
    done
fi

FAKE_PROTO=$PROTO "$RSBIN/examples/fake_manager" 15140 "$D/manager.keys" "$D/c.manager.log" "$D/script.txt" &
FAKE_PROTO=$PROTO "$RSBIN/examples/fake_manager" 15141 "$D/manager.keys" "$D/rs.manager.log" "$D/script.txt" &
sleep 0.5

(cd "$D/c" && LD_LIBRARY_PATH="$CSRC/src" "$D/c/bin/wazuh-agentd" -f -u "$USER_NAME" -g "$USER_NAME" > "$D/c.stderr" 2>&1) &
(cd "$D/rs" && "$D/rs/bin/wazuh-agentd" -f -u "$USER_NAME" -g "$USER_NAME" > "$D/rs.stderr" 2>&1) &

# local events through queue/sockets/queue
sleep 6
for b in $(seq 1 "$EVENT_BURSTS"); do
    for h in c rs; do
        python3 - "$D/$h/queue/sockets/queue" "$EVENTS" "$b" <<'EOF'
import socket, sys
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
n, b = int(sys.argv[2]), int(sys.argv[3])
try:
    for i in range(n):
        s.sendto(b"1:/var/log/diff.log:burst %d event %d" % (b, i), sys.argv[1])
    if b == 1:
        s.sendto(b"1:/var/log/diff.log:" + b"x" * 70000, sys.argv[1])
except OSError:
    pass
EOF
    done
    sleep 1
done

sleep 10
if [ -n "$RELOAD_QUEUE" ]; then
    for h in c rs; do
        sed -i "s#<queue_size>[0-9]*</queue_size>#<queue_size>$RELOAD_QUEUE</queue_size>#" "$D/$h/etc/ossec.conf"
    done
fi
pkill -USR1 -f "$D/c/bin/wazuh-agentd"
pkill -USR1 -f "$D/rs/bin/wazuh-agentd"

sleep $((DURATION - 16 - EVENT_BURSTS))
for h in c rs; do cp "$D/$h/var/run/wazuh-agentd.state" "$D/$h.state" 2>/dev/null; done
pkill -TERM -f "$D/c/bin/wazuh-agentd"
pkill -TERM -f "$D/rs/bin/wazuh-agentd"
sleep 2
pkill -KILL -f "$D/c/bin/wazuh-agentd"; pkill -KILL -f "$D/rs/bin/wazuh-agentd"
pkill -f "examples/fake_manager" 2>/dev/null
pkill -f "fake_authd.py" 2>/dev/null

for h in c rs; do
    # timestamps, pids, debug locations, run-dependent values
    sed -E \
        -e 's/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9:]{8} //' \
        -e 's/^wazuh-agentd\[[0-9]+\] [^ ]+ at [^ ]+\(\): /wazuh-agentd: /' \
        -e 's/\(pid: [0-9]+\)/(pid: N)/' \
        -e 's/\(ptr: 0x[0-9a-f]+\)/(ptr: P)/' \
        -e 's#agentd-diff/(c|rs)#agentd-diff/H#g' \
        -e 's/151[45][01]/PORT/g' \
        "$D/$h/logs/ossec.log" > "$D/$h.ossec.norm"
    sed -E \
        -e 's/^ *[0-9.]+ //' \
        -e 's/\[[0-9]+:[0-9]+\] /[G:L] /' \
        -e 's/151[45][01]/PORT/g' \
        -e 's/"(last_keepalive|last_ack)":"[^"]*"/"\1":"T"/g' \
        "$D/$h.manager.log" > "$D/$h.manager.norm"
done
echo "=== [$SCENARIO] ossec.log (C <, Rust >)"
diff "$D/c.ossec.norm" "$D/rs.ossec.norm"
echo "=== [$SCENARIO] manager view (C <, Rust >)"
diff "$D/c.manager.norm" "$D/rs.manager.norm"
if [ "$ENROLL" = yes ]; then
    echo "=== [$SCENARIO] authd view (C <, Rust >)"
    diff "$D/authd.15150.log" "$D/authd.15151.log"
    echo "=== [$SCENARIO] client.keys"
    diff "$D/c/etc/client.keys" "$D/rs/etc/client.keys" && stat -c '%a %U' "$D/c/etc/client.keys" "$D/rs/etc/client.keys"
fi
if [ "$PREFILL_MB" -gt 0 ]; then
    echo "=== [$SCENARIO] rotated logs (C <, Rust >)"
    diff <(cd "$D/c/logs" && find wazuh -type f | sort) <(cd "$D/rs/logs" && find wazuh -type f | sort)
    for h in c rs; do
        f=$(cd "$D/$h/logs" && find wazuh -name '*.gz' | sort | head -1)
        [ -n "$f" ] && echo "$h: $f $(zcat "$D/$h/logs/$f" | grep -c '^filler line') filler lines, gzip ok: $(gzip -t "$D/$h/logs/$f" && echo yes)"
    done
fi
echo "=== [$SCENARIO] state file"
diff <(grep -v "^last_" "$D/c.state") <(grep -v "^last_" "$D/rs.state")
