mkdir -p "$(dirname etc/c1.conf)"
cat > etc/c1.conf <<'XEOF'
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
    <email_to>only@x.com</email_to>
  </email_alerts>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c2.conf)"
cat > etc/c2.conf <<'XEOF'
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
    <email_to>f@x.com</email_to>
    <format>pdf</format>
  </email_alerts>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c3.conf)"
cat > etc/c3.conf <<'XEOF'
<ossec_config>
  <global>
    <email_notification>no</email_notification>
  </global>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c4.conf)"
cat > etc/c4.conf <<'XEOF'
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
    <jsonout_output>no</jsonout_output>
  </global>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c5.conf)"
cat > etc/c5.conf <<'XEOF'
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
    <email_log_source>alerts.log</email_log_source>
    <alerts_log>no</alerts_log>
  </global>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c6.conf)"
cat > etc/c6.conf <<'XEOF'
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <jsonout_output>yes</jsonout_output>
  </global>
  <email_alerts>
    <level>5</level>
  </email_alerts>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c7.conf)"
cat > etc/c7.conf <<'XEOF'
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
    <email_maxperhour>0</email_maxperhour>
  </global>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c8.conf)"
cat > etc/c8.conf <<'XEOF'
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
    <email_to>notanemail</email_to>
  </global>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c9.conf)"
cat > etc/c9.conf <<'XEOF'
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
    <email_to>z@x.com</email_to>
    <bogus>1</bogus>
  </email_alerts>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c10.conf)"
cat > etc/c10.conf <<'XEOF'
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
    <level>x</level>
    <email_to>z@x.com</email_to>
  </email_alerts>
</ossec_config>
XEOF
mkdir -p "$(dirname etc/c11.conf)"
cat > etc/c11.conf <<'XEOF'
<ossec_config>
  <email_alerts>
    <email_to>early@x.com</email_to>
    <rule_id>1</rule_id>
  </email_alerts>
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
