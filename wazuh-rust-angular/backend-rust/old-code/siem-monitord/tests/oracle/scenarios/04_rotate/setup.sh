Y=$(date +%Y); M=$(LC_ALL=C date +%b); D=$(date +%d); PY=$(date -d yesterday +%Y); PM=$(LC_ALL=C date -d yesterday +%b); PD=$(date -d yesterday +%d)
gz() { mkdir -p "$(dirname "$1")"; printf "%s" "$2" | gzip -c > "$1"; }
printf 'line A\n' > logs/ossec.log; printf '{"b":1}\n' > logs/ossec.json
gz logs/wazuh/$Y/$M/ossec-$D.log.gz r0; gz logs/wazuh/$Y/$M/ossec-$D-001.log.gz r1
gz logs/wazuh/2020/Jan/ossec-01.log.gz old1; gz logs/wazuh/2020/Jan/ossec-02-001.json.gz old2; gz logs/wazuh/2020/Jan/other.txt.gz keep
mkdir -p logs/wazuh/2020/Foo logs/wazuh/notayear
gz logs/wazuh/$Y/$M/ossec-$D.json.gz j0
