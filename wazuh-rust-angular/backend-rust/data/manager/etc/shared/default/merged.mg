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
!35 agent.conf
<agent_config>

</agent_config>
