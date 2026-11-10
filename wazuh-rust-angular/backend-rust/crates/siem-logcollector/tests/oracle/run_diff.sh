#!/bin/bash
# Differential test: the C wazuh-logcollector (Wazuh 4.14.7 agent build)
# against the Rust port. Each runs in its own home with the same
# configuration and the same file operations; a fake agentd queue and a
# fake <socket> target record what they send.
#
#   wsl -d Ubuntu-20.04 -u root -- bash run_diff.sh
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
USER_NAME=${USER_NAME:-jithin}
CSRC=${CSRC:-/home/$USER_NAME/wazuh-agent-src}
RSBIN=${RSBIN:-/home/$USER_NAME/rs-target/debug}
D=${D:-/home/$USER_NAME/lc-diff}
SCENARIO=${1:-default}
# Scenario knobs (scenarios/<name>.env)
INPUT_THREADS=1      # logcollector.input_threads
EXTRA_OPTS=""        # more local_internal_options lines
SORT_QUEUE=no        # yes: compare the queue as a sorted list (several input threads)
JOURNAL_ROTATE=no    # yes: rotate the journal between the two journal messages
[ -f "$HERE/scenarios/$SCENARIO.env" ] && . "$HERE/scenarios/$SCENARIO.env"

pkill -f "$D/" 2>/dev/null
sleep 1
rm -rf "$D"
mkdir -p "$D"

mk_home() {
    local h=$1
    mkdir -p "$h"/{bin,etc/shared,logs,queue/sockets,queue/logcollector,var/run,data/glob,data/svc}
    cp "$CSRC/etc/internal_options.conf" "$h/etc/"
    cat > "$h/etc/local_internal_options.conf" <<EOF
logcollector.debug=2
logcollector.loop_timeout=1
logcollector.vcheck_files=2
logcollector.state_interval=3
logcollector.input_threads=$INPUT_THREADS
EOF
    printf '%b' "$EXTRA_OPTS" >> "$h/etc/local_internal_options.conf"
    cat > "$h/etc/ossec.conf" <<EOF
<ossec_config>
  <localfile><location>$h/data/syslog.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>$h/data/old.log</location><log_format>syslog</log_format><only-future-events>no</only-future-events>
    <ignore>DROPME</ignore><restrict type="osregex">keep|KEEP</restrict></localfile>
  <localfile><location>$h/data/app.json</location><log_format>json</log_format>
    <label key="env">prod</label><label key="host.dc">eu-1</label><label key="tags">["a","b"]</label></localfile>
  <localfile><location>$h/data/ml3.log</location><log_format>multi-line: 3</log_format></localfile>
  <localfile><location>$h/data/mlre.log</location><log_format>multi-line-regex</log_format>
    <multiline_regex match="start" replace="wspace" timeout="2">^\d\d\d\d-</multiline_regex></localfile>
  <localfile><location>$h/data/audit.log</location><log_format>audit</log_format></localfile>
  <localfile><location>$h/data/mysql.log</location><log_format>mysql_log</log_format></localfile>
  <localfile><location>$h/data/mssql.log</location><log_format>mssql_log</log_format></localfile>
  <localfile><location>$h/data/pg.log</location><log_format>postgresql_log</log_format></localfile>
  <localfile><location>$h/data/svc/current</location><log_format>djb-multilog</log_format></localfile>
  <localfile><location>$h/data/nmap.gnmap</location><log_format>nmapg</log_format></localfile>
  <localfile><location>$h/data/alerts.log</location><log_format>ossecalert</log_format></localfile>
  <localfile><location>$h/data/snort.log</location><log_format>snort-full</log_format></localfile>
  <localfile><location>$h/data/glob/*.log</location><log_format>syslog</log_format><exclude>$h/data/glob/skip*.log</exclude><ignore_binaries>yes</ignore_binaries></localfile>
  <localfile><location>$h/data/date-%Y%m%d.log</location><log_format>syslog</log_format></localfile>
  <localfile><command>echo hello; echo; echo world</command><log_format>command</log_format><frequency>4</frequency><alias>greeting</alias></localfile>
  <localfile><command>printf 'a\\r\\nb\\n\\nc\\n'</command><log_format>full_command</log_format><frequency>4</frequency></localfile>
  <localfile><location>$h/data/out.log</location><log_format>syslog</log_format><target>agent,mysock</target>
    <out_format target="mysock">\$(timestamp %Y) \$(hostname) X:\$(log) L:\$(location) J:\$(json_escaped_log) B:\$(base64_log) \$(bogus) end</out_format></localfile>
  <localfile><location>$h/data/syslog.log</location><log_format>syslog</log_format></localfile>
  <localfile><location>$h/data/aged.log</location><log_format>syslog</log_format><only-future-events>no</only-future-events><age>1h</age></localfile>
  <localfile><location>$h/data/fresh.log</location><log_format>syslog</log_format><age>1h</age></localfile>
  <localfile><location>journald</location><log_format>journald</log_format>
    <filter field="SYSLOG_IDENTIFIER">^lcdifftest$</filter></localfile>
  <socket><name>mysock</name><location>$h/queue/sockets/mysock</location><mode>udp</mode><prefix>PFX: </prefix></socket>
  <logging><log_format>plain</log_format></logging>
</ossec_config>
EOF
    echo "old keep 1" > "$h/data/old.log"
    echo "old DROPME keep 2" >> "$h/data/old.log"
    echo "old other 3" >> "$h/data/old.log"
    echo "old KEEP 4" >> "$h/data/old.log"
    for f in syslog.log app.json ml3.log mlre.log audit.log mysql.log mssql.log pg.log nmap.gnmap alerts.log snort.log out.log; do
        echo "preexisting line in $f" > "$h/data/$f"
    done
    echo "@400000004632460200000000 preexisting" > "$h/data/svc/current"
    echo "first glob line" > "$h/data/glob/a.log"
    echo "excluded" > "$h/data/glob/skip1.log"
    printf 'bin\x00\x01\x02\xff\xfe\n' > "$h/data/glob/bin.log"
    echo "dated" > "$h/data/date-$(date +%Y%m%d).log"
    touch "$h/logs/ossec.log" "$h/data/fresh.log"
    # read from the start, but last modified two hours ago: ignored
    echo "aged line" > "$h/data/aged.log"; touch -d "2 hours ago" "$h/data/aged.log"
}

mk_home "$D/c"
mk_home "$D/rs"
cp "$CSRC/src/wazuh-logcollector" "$D/c/bin/"
cp "$RSBIN/wazuh-logcollector" "$D/rs/bin/"

# fake agentd queue + fake <socket> target
for h in c rs; do
    python3 "$HERE/sink.py" "$D/$h/queue/sockets/queue" "$D/$h.queue.log" &
    python3 "$HERE/sink.py" "$D/$h/queue/sockets/mysock" "$D/$h.mysock.log" &
done
sleep 1

(cd "$D/c" && LD_LIBRARY_PATH="$CSRC/src" "$D/c/bin/wazuh-logcollector" -f > "$D/c.stderr" 2>&1) &
(cd "$D/rs" && "$D/rs/bin/wazuh-logcollector" -f > "$D/rs.stderr" 2>&1) &
sleep 4

# The same operations on both homes
ops() {
    local h=$1
    printf 'Oct  9 10:00:01 host sshd[1]: line one\nOct  9 10:00:02 host sshd[2]: line two\n' >> "$h/data/syslog.log"
    printf 'partial line without newline' >> "$h/data/syslog.log"
    printf 'zero\x00byte line\n' >> "$h/data/syslog.log"
    printf '{"a":1,"env":"dev"}\nnot json\n{"b":{"c":2}}\n[1,2]\n' >> "$h/data/app.json"
    printf 'm1\nm2\nm3\nm4\nm5\n' >> "$h/data/ml3.log"
    printf '2024-01-01 first\n  cont a\r\n  cont b\n2024-01-02 second\n' >> "$h/data/mlre.log"
    printf 'type=SYSCALL msg=audit(1700000000.123:42): a\ntype=PATH msg=audit(1700000000.123:42): b\ntype=EOE msg=audit(1700000000.124:43): c\n' >> "$h/data/audit.log"
    printf '070823 21:01:30 Query select 1\n\t\t      second same ts\n2024-01-01T10:00:00.123456Z 5 [Note] utc\n' >> "$h/data/mysql.log"
    printf '2009-03-25 04:47:30.01 Server first\n\tcontinued\n2009-03-25 04:47:31.01 Server second\n' >> "$h/data/mssql.log"
    printf '[2007-08-31 19:17:32.186 ADT] 192.168.2.99:db LOG: one\n\tmore\n[2007-08-31 19:17:33.186 ADT] 192.168.2.99:db LOG: two\n' >> "$h/data/pg.log"
    printf '@400000004632460c2ca16c00 Apr 27 14:50:32 already syslog\n@400000004632460c2ca16c00 plain message\nbad djb\n' >> "$h/data/svc/current"
    printf '# Nmap\nHost: 10.0.0.1 (srv)\tPorts: 22/open/tcp//ssh///, 80/closed/tcp//http///, 443/open/tcp//https///\nHost: 10.0.0.2 ()\tStatus: Up\n' >> "$h/data/nmap.gnmap"
    printf '** Alert 1700000000.1: mail  - syslog,sshd,\n2024 Jan 01 10:00:00 host->/var/log/auth.log\nRule: 5715 (level 3) -> '"'"'sshd: authentication success.'"'"'\nSrc IP: 1.2.3.4\nUser: root\nAccepted password\n\n** Alert 1700000001.2: - syslog,\n2024 Jan 01 10:00:01 host->/var/log/x\nRule: 1 (level 2) -> '"'"'two'"'"'\nlog a\nlog b\n\n** Alert 1700000002.3: - x,\n' >> "$h/data/alerts.log"
    printf 'out line one\nout "quoted" \\back\n' >> "$h/data/out.log"
    printf 'new glob file\n' > "$h/data/glob/b.log"
    printf 'excluded again\n' > "$h/data/glob/skip2.log"
    printf 'more a\n' >> "$h/data/glob/a.log"
    printf 'dated more\n' >> "$h/data/date-$(date +%Y%m%d).log"
}
ops "$D/c"; ops "$D/rs"
for h in c rs; do
    # 'age': a file last modified two hours ago is ignored, a fresh one is read
    printf 'fresh line\n' >> "$D/$h/data/fresh.log"
done
sleep 3
# rotation (inode change) and truncation
for h in c rs; do
    mv "$D/$h/data/syslog.log" "$D/$h/data/syslog.log.1"
    echo "after rotation" > "$D/$h/data/syslog.log"
    : > "$D/$h/data/out.log"
    echo "after truncate" >> "$D/$h/data/out.log"
    printf '2024-01-03 third\n' >> "$D/$h/data/mlre.log"
done
logger -t lcdifftest "journal message one"
logger -t othertag "journal message filtered out"
sleep 6
for h in c rs; do
    printf 'line after rotation\n' >> "$D/$h/data/syslog.log"
    rm -f "$D/$h/data/glob/b.log"
done
if [ "$JOURNAL_ROTATE" = yes ]; then journalctl --rotate >/dev/null 2>&1; sleep 3; fi
logger -t lcdifftest "journal message two"
sleep 6

# lccom requests
for h in c rs; do
    for q in "getconfig localfile" "getconfig socket" "getconfig internal" "getconfig bogus" "getstate" "nothing"; do
        python3 "$HERE/lccom.py" "$D/$h/queue/sockets/logcollector" "$q" >> "$D/$h.lccom.log"
    done
    cp "$D/$h/var/run/wazuh-logcollector.state" "$D/$h.state" 2>/dev/null
done

pkill -TERM -f "$D/c/bin/wazuh-logcollector"
pkill -TERM -f "$D/rs/bin/wazuh-logcollector"
sleep 2
pkill -KILL -f "$D/c/bin/" ; pkill -KILL -f "$D/rs/bin/"
pkill -f "$HERE/sink.py"

norm() {
    sed -E \
        -e 's/^[0-9]{4}\/[0-9]{2}\/[0-9]{2} [0-9:]{8} //' \
        -e 's/^wazuh-logcollector\[[0-9]+\] [^ ]+ at [^ ]+\(\): /wazuh-logcollector: /' \
        -e 's/\(pid: [0-9]+\)/(pid: N)/' \
        -e "s#$D/(c|rs)#H#g" \
        -e 's/"(start|end)":"[^"]*"/"\1":"T"/g' \
        -e 's/[0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}/TS/g' \
        -e 's/[A-Z][a-z]{2} [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2} [^ ]+ lcdifftest\[[0-9]+\]/JTS lcdifftest[P]/g'
}
for h in c rs; do
    norm < "$D/$h/logs/ossec.log" > "$D/$h.ossec.norm"
    if [ "$SORT_QUEUE" = yes ]; then norm < "$D/$h.queue.log" | sort > "$D/$h.queue.norm"; else norm < "$D/$h.queue.log" > "$D/$h.queue.norm"; fi
    norm < "$D/$h.mysock.log" > "$D/$h.mysock.norm"
    # getstate: the C hash table order is random, sort the files
    python3 - "$D/$h.lccom.log" <<'PY' | norm > "$D/$h.lccom.norm"
import json, sys
for line in open(sys.argv[1]):
    line = line.rstrip()
    if line.startswith("getstate => "):
        d = json.loads(line[12:])
        for k in ("global", "interval"):
            if k in d.get("data", {}):
                d["data"][k]["files"] = sorted(d["data"][k]["files"], key=lambda f: f["location"])
                for f in d["data"][k]["files"]:
                    # rotation notices carry the home path, whose length differs
                    if f["location"] == "logcollector":
                        f["bytes"] = "N"
        line = "getstate => " + json.dumps(d, sort_keys=True)
    print(line)
PY
    python3 -c "import json,sys; d=json.load(open(sys.argv[1])); d['files']=sorted(d.get('files',[]),key=lambda x:x['path']); print(json.dumps(d,sort_keys=True,indent=1))" \
        "$D/$h/queue/logcollector/file_status.json" 2>&1 | norm > "$D/$h.status.norm"
done
echo "=== queue (C <, Rust >)"; diff "$D/c.queue.norm" "$D/rs.queue.norm"
echo "=== socket target"; diff "$D/c.mysock.norm" "$D/rs.mysock.norm"
echo "=== lccom"; diff "$D/c.lccom.norm" "$D/rs.lccom.norm"
echo "=== file_status.json"; diff "$D/c.status.norm" "$D/rs.status.norm"
echo "=== ossec.log (sorted)"; diff <(sort "$D/c.ossec.norm") <(sort "$D/rs.ossec.norm")
