#!/usr/bin/env python3
"""Appends alerts to alerts.json on a fixed timeline (seconds after start)."""
import json, sys, time
sys.path.insert(0, __import__("os").path.dirname(__file__))
from gen_scenarios import alert_json
A = sys.argv[1]
r = lambda lvl, desc, rid, groups: {"level": lvl, "description": desc, "id": rid, "mail": True, "groups": groups}
timeline = [
    (0, [alert_json(), alert_json(rule=r(4, "second", "1003", ["syslog"]), agent={"id": "004", "name": "app1", "ip": "10.0.0.8"})]),
    (6, [alert_json(rule=r(10, "sshd: brute force", "5720", ["sshd"]), agent={"id": "000", "name": "mgr"}, location="/var/log/secure")]),
    (12, [alert_json(rule=r(4, "web event", "31101", ["web"]), agent={"id": "002", "name": "web1", "ip": "10.0.0.9"})]),
    (18, [alert_json(rule=r(5, "sshd: authentication failed.", "5716", ["sshd"]), agent={"id": "003", "name": "db1", "ip": "10.0.0.7"}),
          alert_json(rule=r(2, "not mailed", "1002", ["syslog"]))]),
    (24, [alert_json(rule=r(12, "PAM", "5501", ["pam"]), agent={"id": "005", "name": "app2", "ip": "10.0.0.10"}), alert_json(rule=r(6, "x", "40101", ["x"]), agent={"id": "005", "name": "app2", "ip": "10.0.0.10"})]),
]
t0 = time.time()
for at, alerts in timeline:
    time.sleep(max(0, t0 + at - time.time()))
    with open(A, "a") as f:
        f.write("".join(a + "\n" for a in alerts))
