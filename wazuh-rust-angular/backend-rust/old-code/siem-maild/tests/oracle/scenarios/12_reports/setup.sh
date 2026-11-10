mkdir -p "$(dirname logs/alerts/alerts.log)"
cat > logs/alerts/alerts.log <<'XEOF'
** Alert 1700000000.1: mail  - syslog,sshd,authentication_failed,
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
Integrity checksum changed for: 'c:\test\a.txt'
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

XEOF
