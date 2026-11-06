#!/usr/bin/env python3
"""Writes the maild oracle scenarios (setup.sh, cmds.txt, script.json)."""
import json, os, shutil

H = os.path.dirname(os.path.abspath(__file__))
S = os.path.join(H, "scenarios")
shutil.rmtree(S, ignore_errors=True)


def conf(global_extra="", alerts="", base=True, server="127.0.0.1"):
    g = ""
    if base:
        g = f"""    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <email_notification>yes</email_notification>
    <smtp_server>{server}</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>soc@example.com</email_to>
    <email_to>admin@example.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_idsname>prod-manager</email_idsname>
    <email_reply_to>noreply@example.com</email_reply_to>
"""
    return f"<ossec_config>\n  <global>\n{g}{global_extra}  </global>\n{alerts}</ossec_config>\n"


GRAN = """  <email_alerts>
    <email_to>a@x.com</email_to>
    <email_to>b@x.com</email_to>
    <level>10</level>
    <rule_id>0,5501, 5502,,x</rule_id>
    <do_not_delay/>
  </email_alerts>
  <email_alerts>
    <email_to>sms@x.com</email_to>
    <format>sms</format>
    <rule_id>5715, 550</rule_id>
  </email_alerts>
  <email_alerts>
    <email_to>g@x.com</email_to>
    <event_location>web1</event_location>
    <do_not_group/>
  </email_alerts>
  <email_alerts>
    <email_to>grp@x.com</email_to>
    <group>authentication_failed|sshd</group>
  </email_alerts>
  <email_alerts>
    <email_to>r@x.com</email_to>
    <rule_id>5716</rule_id>
    <level>3</level>
  </email_alerts>
"""


def alert_json(**kw):
    a = {"timestamp": "2023-11-14T22:13:20.000+0000", "rule": {"level": 3, "description": "sshd: authentication success.", "id": "5715", "mail": True, "groups": ["syslog", "sshd", "authentication_success"]},
         "agent": {"id": "001", "name": "web1", "ip": "10.0.0.5"}, "manager": {"name": "mgr"}, "id": "1700000000.1", "full_log": "Nov 14 22:13:20 web1 sshd[1]: Accepted password for root", "location": "/var/log/auth.log"}
    for k, v in kw.items():
        if v is None:
            a.pop(k, None)
        else:
            a[k] = v
    return json.dumps(a, separators=(",", ":"))


JSON_ALERTS = [
    alert_json(),
    alert_json(rule={"level": 10, "description": "sshd: brute force", "id": "5720", "mail": True, "groups": ["sshd", "authentication_failures"]}, agent={"id": "000", "name": "mgr"}, location="/var/log/secure"),
    alert_json(rule={"level": 2, "description": "not mailed", "id": "1002", "mail": False, "groups": ["syslog"]}),
    '{"broken": ',
    alert_json(rule={"level": 7, "description": "Integrity checksum changed.", "id": "550", "mail": True, "groups": ["ossec", "syscheck"]}, full_log="ignored for syscheck", location="syscheck",
               syscheck={"path": "/etc/passwd", "event": "modified", "mode": "whodata", "changed_attributes": ["size", "md5", 7], "size_before": "10", "size_after": "20", "md5_before": "aa", "md5_after": "bb",
                         "perm_after": "rw-r--r--", "mtime_after": 1700000000, "inode_after": 123, "uname_after": "root", "uid_after": "0", "gname_after": "root", "gid_after": "0", "sha1_after": "cc",
                         "audit": {"user": {"name": "root"}, "login_user": {"name": "admin"}, "process": {"id": "42", "name": "/usr/bin/vi", "ppid": 1, "cwd": "/root"}}, "diff": "1c1\n< a\n---\n> b", "tags": ["pci", "critical"]}),
    alert_json(full_log=None, rule={"level": 12, "description": "Custom table alert", "id": "100200", "mail": True, "groups": ["custom"]},
               data={"srcip": "1.2.3.4", "list": [1, "two", True, None, {"x": 1}], "nested": {"l1": {"l2": {"l3": {"l4": {"l5": {"l6": {"deep": "v"}}}}}}, "after": "x"}, "nothing": None, "flag": False, "num": 3.5}),
    alert_json(rule={"level": 4, "description": "web event", "id": "31101", "mail": True, "groups": ["web", "accesslog"]}, agent={"id": "002", "name": "web1", "ip": "10.0.0.9"}, location="/var/log/nginx/access.log"),
    alert_json(rule={"level": 5, "description": "sshd: authentication failed.", "id": "5716", "mail": True, "groups": ["syslog", "sshd", "authentication_failed"]}, agent={"id": "003", "name": "db1", "ip": "10.0.0.7"}),
]

LOG_ALERTS = """** Alert 1700000000.1: mail  - syslog,sshd,authentication_failed,
2023 Nov 14 22:13:20 (web1) 10.0.0.5->/var/log/auth.log
Rule: 5716 (level 5) -> 'sshd: authentication failed.'
Src IP: 1.2.3.4
Src Port: 2222
User: root
Nov 14 22:13:20 web1 sshd[1]: Failed password for root from 1.2.3.4 port 2222 ssh2

** Alert 1700000001.2: - syslog,
2023 Nov 14 22:13:21 manager->/var/log/messages
Rule: 1002 (level 2) -> 'Unknown problem somewhere in the system.'
x

** Alert 1700000002.3: mail  - ossec,syscheck,
2023 Nov 14 22:13:22 (win1) any->syscheck
Rule: 550 (level 7) -> 'Integrity checksum changed.'
Integrity checksum changed for: 'c:\\test\\a.txt'
Size changed from '1' to '2'

** Alert 1700000003.4: mail  - pam,
2023 Nov 14 22:13:23 a>b
Rule: 5501 (level 12) -> 'PAM: Login session opened.'
Dst IP: 5.6.7.8
line1

** Alert 1700000004.5: mail  - syslog,sshd,authentication_failed,
2023 Nov 14 22:14:00 (db1) 10.0.0.7->/var/log/auth.log
Rule: 5716 (level 5) -> 'sshd: authentication failed.'
Src IP: 1.2.3.9
User: admin
Nov 14 22:14:00 db1 sshd[2]: Failed password for admin

** Alert 1700000005.6: mail  - syslog,sshd,authentication_success,
2023 Nov 14 22:15:00 (web1) 10.0.0.5->/var/log/auth.log
Rule: 5715 (level 3) -> 'sshd: authentication success.'
Src IP: 1.2.3.4
User: root
Nov 14 22:15:00 web1 sshd[3]: Accepted password for root

** Alert 1700000006.7: mail  - ossec,syscheck,
2023 Nov 14 22:16:00 (win1) any->syscheck
Rule: 550 (level 7) -> 'Integrity checksum changed.'
Integrity checksum changed for: '/etc/hosts'
Size changed from '3' to '4'

"""


def write(name, setup, cmds, script=None):
    d = os.path.join(S, name)
    os.makedirs(d)
    open(os.path.join(d, "setup.sh"), "w", newline="\n").write(setup)
    open(os.path.join(d, "cmds.txt"), "w", newline="\n").write("\n".join(cmds) + "\n")
    json.dump(script or {}, open(os.path.join(d, "script.json"), "w"))


def files(**f):
    out = []
    for path, text in f.items():
        path = path.replace("__", "/").replace("_DOT_", ".")
        out.append(f"mkdir -p \"$(dirname {path})\"\ncat > {path} <<'XEOF'\n{text}XEOF\n")
    return "".join(out)


ALERTS_JSON = "\n".join(JSON_ALERTS) + "\n"

write("01_config", files(etc__ossec_DOT_conf=conf(alerts=GRAN)),
      ["config etc/ossec.conf", "getconfig global", "getconfig alerts", "getconfig internal", "getconfig", "getconfig x", "foo bar"])

bad = {
    "c1": conf(alerts="  <email_alerts>\n    <email_to>only@x.com</email_to>\n  </email_alerts>\n"),
    "c2": conf(alerts="  <email_alerts>\n    <email_to>f@x.com</email_to>\n    <format>pdf</format>\n  </email_alerts>\n"),
    "c3": conf(base=False, global_extra="    <email_notification>no</email_notification>\n"),
    "c4": conf(global_extra="    <jsonout_output>no</jsonout_output>\n"),
    "c5": conf(global_extra="    <email_log_source>alerts.log</email_log_source>\n    <alerts_log>no</alerts_log>\n"),
    "c6": "<ossec_config>\n  <global>\n    <email_notification>yes</email_notification>\n    <jsonout_output>yes</jsonout_output>\n  </global>\n  <email_alerts>\n    <level>5</level>\n  </email_alerts>\n</ossec_config>\n",
    "c7": conf(global_extra="    <email_maxperhour>0</email_maxperhour>\n"),
    "c8": conf(global_extra="    <email_to>notanemail</email_to>\n"),
    "c9": conf(alerts="  <email_alerts>\n    <email_to>z@x.com</email_to>\n    <bogus>1</bogus>\n  </email_alerts>\n"),
    "c10": conf(alerts="  <email_alerts>\n    <level>x</level>\n    <email_to>z@x.com</email_to>\n  </email_alerts>\n"),
    "c11": "<ossec_config>\n  <email_alerts>\n    <email_to>early@x.com</email_to>\n    <rule_id>1</rule_id>\n  </email_alerts>\n" + conf(alerts=GRAN)[len("<ossec_config>\n"):],
}
write("02_config_errors", files(**{f"etc__{k}_DOT_conf": v for k, v in bad.items()}),
      sum([[f"config etc/{k}.conf", "getconfig alerts", "getconfig global"] for k in bad], []))

write("03_json", files(etc__ossec_DOT_conf=conf(alerts=GRAN), logs__alerts__alerts_DOT_json=ALERTS_JSON, report_DOT_txt="Report line 1\n.hidden line\nlast\n"),
      ["config etc/ossec.conf"] + ["json"] * (len(JSON_ALERTS) + 1) + ["sendmail", "sms", "json", "sendmail", "custom report.txt"])

write("04_log", files(etc__ossec_DOT_conf=conf(global_extra="    <email_log_source>alerts.log</email_log_source>\n", alerts=GRAN), logs__alerts__alerts_DOT_log=LOG_ALERTS),
      ["config etc/ossec.conf", "set 1 1 1"] + ["log"] * 8 + ["sendmail", "sms"])

one = alert_json()
write("05_rcpt_fail", files(etc__ossec_DOT_conf=conf(alerts=GRAN), logs__alerts__alerts_DOT_json=one + "\n" + alert_json(rule={"level": 12, "description": "x", "id": "5501", "mail": True, "groups": ["a"]}) + "\n"),
      ["config etc/ossec.conf", "json", "sendmail", "json", "sendmail"], {"smtp": {"rcpt_fail": ["admin@example.com"]}})
write("06_gran_rcpt_fail", files(etc__ossec_DOT_conf=conf(alerts=GRAN), logs__alerts__alerts_DOT_json=alert_json(rule={"level": 12, "description": "x", "id": "5501", "mail": True, "groups": ["a"]}) + "\n"),
      ["config etc/ossec.conf", "json", "sendmail"], {"smtp": {"rcpt_fail": ["a@x.com"]}})
write("07_data_refused", files(etc__ossec_DOT_conf=conf(), logs__alerts__alerts_DOT_json=one + "\n"),
      ["config etc/ossec.conf", "json", "sendmail"], {"smtp": {"data_reply": "554 5.7.1 rejected\r\n"}})
write("08_end_refused", files(etc__ossec_DOT_conf=conf(), logs__alerts__alerts_DOT_json=one + "\n" + one + "\n"),
      ["config etc/ossec.conf", "json", "sendmail", "set 0 1 0", "json", "sendmail"], {"smtp": {"end_reply": "554 5.7.1 spam\r\n"}})
write("09_two_banners", files(etc__ossec_DOT_conf=conf(), logs__alerts__alerts_DOT_json=one + "\n"),
      ["config etc/ossec.conf", "json", "sendmail"], {"smtp": {"helo_reply": ["220 second banner\r\n", "250 fake.local\r\n"]}})
write("10_bad_banner", files(etc__ossec_DOT_conf=conf(), logs__alerts__alerts_DOT_json=one + "\n"),
      ["config etc/ossec.conf", "json", "sendmail"], {"smtp": {"banner": "554 go away\r\n"}})

pipe = "#!/bin/sh\ncat >> \"$(dirname \"$0\")/out/pipe.log\"\necho ---- >> \"$(dirname \"$0\")/out/pipe.log\"\n"
write("11_sendmail_pipe",
      files(fake_sendmail_DOT_sh=pipe, logs__alerts__alerts_DOT_json=ALERTS_JSON, report_DOT_txt="r1\nr2\n") + "chmod +x fake_sendmail.sh\n" +
      "cat > etc/ossec.conf <<XEOF\n" + conf(alerts=GRAN, server="$PWD/fake_sendmail.sh") + "XEOF\n",
      ["config etc/ossec.conf"] + ["json"] * 3 + ["sendmail", "sms", "custom report.txt"])

R = "report logs/alerts/alerts.log"
write("12_reports", files(logs__alerts__alerts_DOT_log=LOG_ALERTS),
      [f"{R} -", f"{R} Daily", f"{R} SSH group=sshd rel:srcip=user rel:user=srcip showlogs", f"{R} Rules rule=5716,5501 level=5",
       f"{R} Loc location=web1", f"{R} Src srcip=1.2.3", f"{R} Usr user=root rel:level=location rel:rule=group rel:group=rule rel:location=srcip rel:filename=level",
       f"{R} Files filename=a.txt rel:level=filename showlogs", f"{R} None group=nomatch", f"{R} Bad rel:level=bogus", f"{R} BadRule rule=55x"])
print("scenarios:", sorted(os.listdir(S)))
