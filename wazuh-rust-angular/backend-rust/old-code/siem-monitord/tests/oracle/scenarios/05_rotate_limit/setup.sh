Y=$(date +%Y); M=$(LC_ALL=C date +%b); D=$(date +%d); PY=$(date -d yesterday +%Y); PM=$(LC_ALL=C date -d yesterday +%b); PD=$(date -d yesterday +%d)
gz() { mkdir -p "$(dirname "$1")"; printf "%s" "$2" | gzip -c > "$1"; }
printf 'new\n' > logs/ossec.log; printf '{"n":1}\n' > logs/ossec.json
gz logs/wazuh/$Y/$M/ossec-$D.log.gz r0; gz logs/wazuh/$Y/$M/ossec-$D-001.log.gz r1; gz logs/wazuh/$Y/$M/ossec-$D-002.log.gz r2
gz logs/wazuh/$Y/$M/ossec-$D.json.gz j0
