Y=$(date +%Y); M=$(LC_ALL=C date +%b); D=$(date +%d); PY=$(date -d yesterday +%Y); PM=$(LC_ALL=C date -d yesterday +%b); PD=$(date -d yesterday +%d)
gz() { mkdir -p "$(dirname "$1")"; printf "%s" "$2" | gzip -c > "$1"; }
OY=$(date -d @$(( $(date +%s) - 93500 )) +%Y); OM=$(LC_ALL=C date -d @$(( $(date +%s) - 93500 )) +%b); OD=$(date -d @$(( $(date +%s) - 93500 )) +%d)
mkdir -p logs/alerts/$Y/$M logs/archives/$Y/$M logs/firewall/$Y/$M logs/alerts/$OY/$OM
printf 'alert one\n' > logs/alerts/$Y/$M/ossec-alerts-$D.log
printf 'alert two\n' > logs/alerts/$Y/$M/ossec-alerts-$D-001.log
printf 'alert three\n' > logs/alerts/$Y/$M/ossec-alerts-$D-002.log
printf '{"a":1}\n' > logs/alerts/$Y/$M/ossec-alerts-$D.json
printf 'previous sum\n' > logs/alerts/$OY/$OM/ossec-alerts-$OD.log.sum
printf 'arch\n' > logs/archives/$Y/$M/ossec-archive-$D.log
