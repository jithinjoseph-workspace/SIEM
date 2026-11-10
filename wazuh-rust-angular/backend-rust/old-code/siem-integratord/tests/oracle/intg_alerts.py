#!/usr/bin/env python3
"""The alerts appended to alerts.json for the integratord loop oracle (cJSON-style compact lines)."""
import json

c = lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False)
base = lambda **kw: dict({"timestamp": "2026-10-16T10:00:00.000+0000", "agent": {"id": "001", "name": "web1", "ip": "10.0.0.5"}, "id": "1.1", "location": "/var/log/auth.log",
                          "full_log": "Oct 16 sshd[9]: Failed password for root from 1.2.3.4"}, **kw)
rule = lambda level, rid, groups, desc="d": {"level": level, "description": desc, "id": rid, "groups": groups}
long_log = "x'y\\z`q\"w;e!r$t\ttab é" + "A" * 200
alerts = [
    base(rule=rule(10, "5712", ["syslog", "sshd", "authentication_failures"], "sshd: brute force"), data={"srcip": "1.2.3.4"}),
    base(rule=rule(3, "31101", ["web", "accesslog"]), location="/var/log/nginx/access.log", full_log=long_log, data={"srcip": "5.6.7.8';rm -rf"}),
    {"timestamp": "x", "full_log": "no rule block"},
    base(rule=rule(12, "100", ["ossec"], "level 12"), location="syscheck"),
    base(rule=rule(13, "100", ["sshd"], "web 13"), location="webserver"),
    base(rule={"level": 8}, full_log=None),
]
for a in alerts:
    print(c(a))
