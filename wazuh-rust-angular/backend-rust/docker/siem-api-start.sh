#!/bin/bash
# siem-api, and with the SIEM manager on, the agents' gateway beside it on the same host (as on
# the Windows master: they talk over 127.0.0.1). When either ends the container ends, and Docker
# starts it again (restart: unless-stopped).
case "${PROVIGIL_MANAGER:-1}" in
    0|false|no) exec siem-api ;;
esac
# the manager's home: group provigil for what the root programs make there (see the Dockerfile);
# also fixes a volume made before
umask 002
H=${PROVIGIL_MANAGER_HOME:-/app/data/manager}
mkdir -p "$H"
chgrp -R provigil "$H"
chmod -R g+rwX "$H"
find "$H" -type d -exec chmod g+s {} +
siem-api &
# the gateway reads the agents' CA, which siem-api makes on its first start
for _ in $(seq 1 300); do
    [ -s data/tls/ca.key.pem ] && [ -s data/tls/ca.crt.pem ] && break
    kill -0 %1 2>/dev/null || break
    sleep 1
done
provigil-gateway &
wait -n
code=$?
echo "siem-api-start: a program ended (exit $code); stopping the container so Docker restarts it" >&2
kill $(jobs -p) 2>/dev/null
exit $(( code == 0 ? 1 : code ))
