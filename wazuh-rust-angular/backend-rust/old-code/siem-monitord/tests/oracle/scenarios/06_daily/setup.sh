Y=$(date +%Y); M=$(LC_ALL=C date +%b); D=$(date +%d); PY=$(date -d yesterday +%Y); PM=$(LC_ALL=C date -d yesterday +%b); PD=$(date -d yesterday +%d)
gz() { mkdir -p "$(dirname "$1")"; printf "%s" "$2" | gzip -c > "$1"; }
printf 'day log\n' > logs/ossec.log; printf '{"d":1}\n' > logs/ossec.json
gz logs/wazuh/$PY/$PM/ossec-$PD.log.gz y0
