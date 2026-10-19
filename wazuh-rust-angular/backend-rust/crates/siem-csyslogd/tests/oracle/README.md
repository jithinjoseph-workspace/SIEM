# wazuh-csyslogd oracle

The real C daemon (`build.sh`, needs `-D_GNU_SOURCE` or `strptime` returns a truncated
pointer) and the Rust one forward the same alerts.log and alerts.json lines
(`csys_alerts.py`) to seven `<syslog_output>` blocks (all four formats, level, rule_id,
group, location, use_fqdn, a host name to resolve); `udp_recv.py` records every datagram.
Run in WSL as root (the daemons drop to nobody): `bash loop.sh <wazuh-csyslogd>`.

2026-10-17: 14/14 datagrams identical on 6 servers (the 7th correctly gets nothing);
the logs differ only in socket-thread timing and the "now" used for an unparsable timestamp.
