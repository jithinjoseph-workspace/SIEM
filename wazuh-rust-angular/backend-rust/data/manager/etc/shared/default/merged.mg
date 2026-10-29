#default
!555 ar.conf
restart-ossec0 - restart-ossec.sh - 0
restart-ossec0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-ossec.sh - 0
restart-wazuh0 - restart-ossec.cmd - 0
restart-wazuh0 - restart-wazuh - 0
restart-wazuh0 - restart-wazuh.exe - 0
firewall-drop600 - firewall-drop - 600
firewall-drop3600 - firewall-drop - 3600
firewall-drop86400 - firewall-drop - 86400
netsh600 - netsh.exe - 600
netsh3600 - netsh.exe - 3600
netsh86400 - netsh.exe - 86400
route-null600 - route-null.exe - 600
route-null3600 - route-null.exe - 3600
route-null86400 - route-null.exe - 86400
!880 agent.conf
<agent_config>

</agent_config>

<!-- Windows logs the Sigma rules read (siem-api sigma.rs). A host without Sysmon just has no such channel. -->
<agent_config os="Windows">
  <localfile>
    <location>Microsoft-Windows-Sysmon/Operational</location>
    <log_format>eventchannel</log_format>
  </localfile>
  <!-- 4103 module and 4104 script block logging (enabled by the host's PowerShell logging policy) -->
  <localfile>
    <location>Microsoft-Windows-PowerShell/Operational</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=4103 or EventID=4104]</query>
  </localfile>
  <!-- classic engine / provider start and pipeline execution -->
  <localfile>
    <location>Windows PowerShell</location>
    <log_format>eventchannel</log_format>
    <query>Event/System[EventID=400 or EventID=600 or EventID=800]</query>
  </localfile>
</agent_config>
