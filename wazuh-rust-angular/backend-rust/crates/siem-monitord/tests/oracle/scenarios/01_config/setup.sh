cat > etc/ossec.conf <<'X'
<ossec_config>
  <global>
    <email_notification>no</email_notification>
    <agents_disconnection_time>20m</agents_disconnection_time>
    <agents_disconnection_alert_time>30</agents_disconnection_alert_time>
  </global>
  <reports>
    <category>syscheck</category>
    <title>Daily report: File changes</title>
    <email_to>a@b.c</email_to>
    <email_to>d@e.f</email_to>
    <showlogs>yes</showlogs>
  </reports>
  <reports>
    <level type="relation">srcip</level>
    <user type="bad">x</user>
    <srcip type="relation">wrong</srcip>
    <group>web acc;x</group>
    <rule>5501</rule>
    <type>pdf</type>
    <frequency>daily</frequency>
  </reports>
</ossec_config>
X
