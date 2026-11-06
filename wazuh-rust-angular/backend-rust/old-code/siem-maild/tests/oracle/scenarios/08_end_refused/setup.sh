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
</ossec_config>
XEOF
mkdir -p "$(dirname logs/alerts/alerts.json)"
cat > logs/alerts/alerts.json <<'XEOF'
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":3,"description":"sshd: authentication success.","id":"5715","mail":true,"groups":["syslog","sshd","authentication_success"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/auth.log"}
{"timestamp":"2023-11-14T22:13:20.000+0000","rule":{"level":3,"description":"sshd: authentication success.","id":"5715","mail":true,"groups":["syslog","sshd","authentication_success"]},"agent":{"id":"001","name":"web1","ip":"10.0.0.5"},"manager":{"name":"mgr"},"id":"1700000000.1","full_log":"Nov 14 22:13:20 web1 sshd[1]: Accepted password for root","location":"/var/log/auth.log"}
XEOF
