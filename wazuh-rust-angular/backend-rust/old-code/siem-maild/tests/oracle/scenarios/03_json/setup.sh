mkdir -p "$(dirname etc/ossec.conf)"
cat > etc/ossec.conf <<'XEOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <email_notification>yes</email_notification>
    <smtp_server>127.0.0.1</smtp_server>
    <email_from>wazuh@example.com</email_from>
    <email_to>soc@example.com</email_to>
    <email_to>admin@example.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_idsname>prod-manager</email_idsname>
    <email_reply_to>noreply@example.com</email_reply_to>
  </global>
  <email_alerts>
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
</ossec_config>
XEOF
mkdir -p "$(dirname logs/alerts/alerts.json)"
cat > logs/alerts/alerts.json <<'XEOF'
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":3,"description":"sshd: authentication success.","id":"5715","mail":true,"groups":["syslog","sshd","authentication_success"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/auth.log"}
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":10,"description":"sshd: brute force","id":"5720","mail":true,"groups":["sshd","authentication_failures"]},"agent":{"id":"000","name":"mgr"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/secure"}
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":2,"description":"not mailed","id":"1002","mail":false,"groups":["syslog"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/auth.log"}
{"broken": 
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":7,"description":"Integrity checksum changed.","id":"550","mail":true,"groups":["ossec","syscheck"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"ignored for syscheck","location":"syscheck","syscheck":{"path":"/etc/passwd","event":"modified","mode":"whodata","changed_attributes":["size","md5",7],"size_before":"10","size_after":"20","md5_before":"aa","md5_after":"bb","perm_after":"rw-r--r--","mtime_after":1700000000,"inode_after":123,"uname_after":"root","uid_after":"0","gname_after":"root","gid_after":"0","sha1_after":"cc","audit":{"user":{"name":"root"},"login_user":{"name":"admin"},"process":{"id":"42","name":"/usr/bin/vi","ppid":1,"cwd":"/root"}},"diff":"1c1\n< a\n---\n> b","tags":["pci","critical"]}}
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":12,"description":"Custom table alert","id":"100200","mail":true,"groups":["custom"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"manager":{"name":"mgr"},"id":"1700000000.1","location":"/var/log/auth.log","data":{"srcip":"1.2.3.4","list":[1,"two",true,null,{"x":1}],"nested":{"l1":{"l2":{"l3":{"l4":{"l5":{"l6":{"deep":"v"}}}}}},"after":"x"},"nothing":null,"flag":false,"num":3.5}}
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":4,"description":"web event","id":"31101","mail":true,"groups":["web","accesslog"]},"agent":{"id":"002","name":"web1","ip":"10.0.0.9"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/nginx/access.log"}
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":5,"description":"sshd: authentication failed.","id":"5716","mail":true,"groups":["syslog","sshd","authentication_failed"]},"agent":{"id":"003","name":"db1","ip":"10.0.0.7"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/auth.log"}
XEOF
mkdir -p "$(dirname report.txt)"
cat > report.txt <<'XEOF'
Report line 1
.hidden line
last
XEOF
