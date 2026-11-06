#!/usr/bin/env python3
"""Appends the same alerts to logs/alerts/alerts.log and alerts.json: csys_alerts.py <home>."""
import json, sys

home = sys.argv[1]
log = """** Alert 1700000000.1: mail  - syslog,sshd,authentication_failed,
2023 Nov 04 22:13:20 (web1) 10.0.0.5->/var/log/auth.log
Rule: 5716 (level 5) -> 'sshd: authentication failed.'
Src IP: 1.2.3.4
Src Port: 2222
Dst IP: 10.0.0.5
Dst Port: 22
User: root
Nov  4 22:13:20 web1 sshd[1]: Failed password for root from 1.2.3.4 port 2222 ssh2

** Alert 1700000001.2: - ossec,syscheck,
2023 Nov 14 22:13:21 (win1) any->syscheck
Rule: 550 (level 7) -> 'Integrity checksum changed.'
Integrity checksum changed for: '/etc/hosts'
Size changed from '3' to '4'

** Alert 1700000002.3: - web,accesslog,
2023 Nov 14 22:13:22 (web2) 10.0.0.9->/var/log/nginx/access.log
Rule: 31101 (level 12) -> 'Web error (none)'
Src IP: (none)
User: unknown
LONGLINE

** Alert 1700000003.4: - pam,
2023 Nov 14 22:13:23 manager->/var/log/secure
Rule: 5501 (level 3) -> 'PAM: Login session opened.'
pam_unix(sshd:session): session opened

""".replace("LONGLINE", "GET /" + "a" * 3000 + " HTTP/1.1")
r = lambda level, rid, groups, desc: {"level": level, "description": desc, "id": rid, "groups": groups}
base = {"agent": {"id": "001", "name": "web1", "ip": "10.0.0.5"}, "manager": {"name": "mgr"}, "location": "/var/log/auth.log"}
js = [
    dict(base, timestamp="2023-11-04T22:13:20.123+0000", rule=r(5, "5716", ["syslog", "sshd"], "sshd: authentication failed."), full_log="Failed password"),
    dict(base, timestamp="2023-11-14T22:13:21.000+0000", rule=r(7, "550", ["ossec", "syscheck"], "Integrity checksum changed."), location="syscheck"),
    dict(base, timestamp="bad-timestamp", rule=r(12, "31101", ["web"], "web"), location="/var/log/nginx/access.log"),
    dict(base, rule=r(12, "1", ["x"], "no timestamp")),
    {"timestamp": "2023-11-14T22:13:23.000+0000", "full_log": "no rule"},
]
with open(home + "/logs/alerts/alerts.log", "a") as f:
    f.write(log)
with open(home + "/logs/alerts/alerts.json", "a") as f:
    for a in js:
        f.write(json.dumps(a, separators=(",", ":")) + "\n")
