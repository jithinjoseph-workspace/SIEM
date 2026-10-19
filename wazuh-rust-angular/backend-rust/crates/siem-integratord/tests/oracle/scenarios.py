#!/usr/bin/env python3
"""Integration script scenarios: (name, script, args, alert text, options text, routes)."""
import json

c = lambda o: json.dumps(o, separators=(",", ":"), ensure_ascii=False)

BASE = {"timestamp": "2026-10-16T10:00:00.000+0000", "rule": {"level": 10, "description": "sshd: brute force \"root\" é", "id": "5712", "firedtimes": 3, "mail": False,
        "groups": ["syslog", "sshd", "authentication_failures"], "mitre": {"id": ["T1110"], "tactic": ["Credential Access"]}},
        "agent": {"id": "001", "name": "web:1", "ip": "10.0.0.5"}, "manager": {"name": "mgr"}, "id": "1792150000.12345",
        "full_log": "Oct 16 sshd[9]: Failed password for root from 45.33.32.156 'x' 😀", "decoder": {"name": "sshd"},
        "data": {"srcip": "45.33.32.156", "dstuser": "root", "ratio": 0.5, "big": 12345678901234567890}, "location": "/var/log/auth.log"}


def alert(**kw):
    a = json.loads(json.dumps(BASE))
    for k, v in kw.items():
        if v is None:
            a.pop(k, None)
        else:
            a[k] = v
    return c(a)


SK = {"path": "/usr/bin/evil", "md5_after": "44d88612fea8a8f36de82e1278abb02f", "sha1_after": "3395856ce81f2b7382dee72602f798b642f14140", "event": "modified"}
VT_FOUND = json.dumps({"response_code": 1, "sha1": "3395856ce81f2b7382dee72602f798b642f14140", "scan_date": "2026-10-01 10:00:00", "positives": 58, "total": 64, "permalink": "https://vt/x", "extra": [1, 2.5]})
MALT_IOC = json.dumps({"type": "sample", "classification": "malicious", "creation_time": "2020-01-01 00:00:00", "modification_time": "2026-01-01 00:00:00",
                       "blacklist": [{"description": "EICAR", "source": "Hybrid", "external_references": [{"source_name": "mitre-attack", "external_id": "S0001", "url": "https://attack/S0001", "description": "Soft"}]},
                                     {"description": "Test file", "source": "Abuse"}, {"description": "EICAR", "source": "Abuse"}]})
MALT_IP = json.dumps({"type": "ip", "ip_version": 4, "classification": "suspicious", "blacklist": [{"description": "Scanner", "source": "Blocklist"}]})
MALT_HOST = json.dumps({"type": "hostname", "classification": "neutral", "blacklist": []})

# args after argv[0]: alert, api_key, hook_url, debug, options, timeout, retries, rest
def A(api="", hook="", debug=True, opt=False, rest="> /dev/null 2>&1"):
    return ["alert.json", api, hook, "debug" if debug else "", "x.options" if opt else "", "10", "3"] + ([rest] if not debug and rest else [])


H = "http://127.0.0.1:PORT"
S = [
    ("slack_debug_options", "slack", A(hook=H + "/services/T1", opt=True), alert(), '{"pretext": "SIEM", "channel": "#soc"}', []),
    ("slack_plain", "slack", A(hook=H + "/hook", debug=False), alert(agent=None, agentless={"host": "fw1"}, full_log=None, rule={"level": 6, "id": "100", "groups": []}), None, []),
    ("slack_low_level", "slack", A(hook=H + "/hook"), alert(rule={"level": 3, "description": "ok", "id": "5715", "groups": ["x"]}), None, [["/hook", 500, "oops"]]),
    ("slack_keyerror", "slack", A(hook=H + "/hook"), alert(rule={"id": "1"}), None, []),
    ("slack_bad_json", "slack", A(hook=H + "/hook"), '{"rule": {"level": 3,}', None, []),
    ("slack_bad_options", "slack", A(hook=H + "/hook", opt=True), alert(), "{not json", []),
    ("slack_no_alert_file", "slack", ["missing.json", "", H + "/hook", "debug", "", "10", "3"], None, None, []),
    ("slack_bad_args", "slack", ["alert.json", "k"], alert(), None, []),
    ("pagerduty_warning", "pagerduty", A(api="ROUTINGKEY123", opt=True), alert(rule={"level": 13, "description": "crit", "id": "9", "groups": ["a", "b"]}), '{"client": "Custom"}', []),
    ("pagerduty_info", "pagerduty", A(api="K", debug=False), alert(rule={"level": 3, "id": "9", "groups": ["a"]}), None, []),
    ("pagerduty_bad_groups", "pagerduty", A(api="K"), alert(rule={"level": 3, "id": "9", "groups": ["a", 5]}), None, []),
    ("shuffle_send", "shuffle", A(hook=H + "/api/v1/hooks/webhook_x", opt=True), alert(rule={"level": 6, "description": "d", "id": "1234", "groups": []}), '{"severity": 9}', []),
    ("shuffle_skip", "shuffle", A(hook=H + "/hook"), alert(rule={"level": 6, "id": "5710", "groups": []}), None, []),
    ("vt_found", "virustotal", A(api="VTKEY"), alert(syscheck=SK, location="syscheck"), None, [["/vtapi/v2/file/report", 200, VT_FOUND]]),
    ("vt_not_found_manager", "virustotal", A(api="VTKEY", debug=False), alert(syscheck=SK, agent={"id": "000", "name": "mgr"}), None, [["/vtapi", 200, '{"response_code": 0}']]),
    ("vt_rate_limit", "virustotal", A(api="VTKEY"), alert(syscheck=SK), None, [["/vtapi", 204, ""]]),
    ("vt_forbidden", "virustotal", A(api="VTKEY"), alert(syscheck=SK, agent={"id": "002", "name": "db|1"}), None, [["/vtapi", 403, "{}"]]),
    ("vt_no_syscheck", "virustotal", A(api="VTKEY"), alert(), None, []),
    ("vt_bad_md5", "virustotal", A(api="VTKEY"), alert(syscheck=dict(SK, md5_after="44d88612fea8a8f36de82e1278abb02f 44d88612fea8a8f36de82e1278abb02f")), None, []),
    ("malt_all", "maltiverse", A(api="MALTKEY", hook=H),
     alert(syscheck=SK, data={"srcip": "45.33.32.156", "hostname": "evil.example", "url": "http://evil.example/x?a=1"}),
     None, [["/sample/md5/", 200, MALT_IOC], ["/sample/sha1/", 200, "{}"], ["/ip/", 200, MALT_IP], ["/hostname/", 200, MALT_HOST], ["/url/", 200, MALT_IOC]]),
    ("malt_private_ip", "maltiverse", A(api="K", hook=H + "/"), alert(data={"srcip": "192.168.1.9"}), None, []),
    ("malt_bad_ip", "maltiverse", A(api="K", hook=H), alert(data={"srcip": "999.1.1.1"}), None, []),
    ("malt_invalid_hook", "maltiverse", A(api="K", hook="ftp://x"), alert(), None, []),
    ("malt_no_agent", "maltiverse", A(api="K", hook=H), alert(agent=None, data={"srcip": "8.8.8.8"}), None, [["/ip/", 200, MALT_IP]]),
]

if __name__ == "__main__":
    import os, sys
    d = sys.argv[1]
    for name, script, args, al, opt, routes in S:
        p = os.path.join(d, name)
        os.makedirs(p, exist_ok=True)
        json.dump({"script": script, "args": args, "routes": routes}, open(os.path.join(p, "case.json"), "w"))
        if al is not None:
            open(os.path.join(p, "alert.json"), "w", encoding="utf-8").write(al + "\n")
        if opt is not None:
            open(os.path.join(p, "x.options"), "w", encoding="utf-8").write(opt + "\n")
    print(len(S), "scenarios")
