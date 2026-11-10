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
