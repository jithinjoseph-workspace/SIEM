# ==============================================================================
# Wazuh Next-Gen Endpoint Agent - RPM Package Specification
# Mirrors official Wazuh packaging (packages/rpms/SPECS/wazuh-agent.spec)
# ==============================================================================
Name:           wazuh-agent
Version:        4.14.7
Release:        1%{?dist}
Summary:        Wazuh Next-Gen Endpoint Telemetry & Threat Defense Agent in Rust

License:        GPL-2.0
URL:            https://wazuh.com
Source0:        siem-agent-linux
Source1:        wazuh-rust-agent.service

Requires:       systemd
Requires:       procps-ng
Requires:       iptables
AutoReqProv:    no

%description
Wazuh helps you to gain security visibility into your infrastructure by
monitoring hosts at an operating system and application level.
This next-gen agent is compiled in high-performance Rust, offering
ultra-low CPU/memory footprint, sub-millisecond event ingestion,
real-time File Integrity Monitoring, Linux CIS benchmark assessments,
and active response remediation.

%prep
# No unpack required for pre-built binaries

%build
# Pre-compiled via cargo

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/var/ossec/bin
mkdir -p %{buildroot}/var/ossec/etc
mkdir -p %{buildroot}/var/ossec/logs
mkdir -p %{buildroot}/var/ossec/queue
mkdir -p %{buildroot}/var/ossec/quarantine
mkdir -p %{buildroot}/usr/lib/systemd/system

install -m 750 %{SOURCE0} %{buildroot}/var/ossec/bin/siem-agent-linux
install -m 644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/wazuh-rust-agent.service

%pre
if ! getent group wazuh >/dev/null 2>&1; then
    groupadd -r wazuh >/dev/null 2>&1 || true
fi
if ! getent passwd wazuh >/dev/null 2>&1; then
    useradd -r -g wazuh -d /var/ossec -s /sbin/nologin -c "Wazuh Agent" wazuh >/dev/null 2>&1 || true
fi

%post
DIR="/var/ossec"
if [ ! -f "${DIR}/etc/agent-config.json" ]; then
    cat <<EOF > "${DIR}/etc/agent-config.json"
{
  "manager_url": "http://127.0.0.1:8088",
  "agent_id": "002",
  "agent_name": "wazuh-rhel-endpoint",
  "buffer_capacity": 5000,
  "events_per_second": 500
}
EOF
    chmod 640 "${DIR}/etc/agent-config.json"
    chown root:wazuh "${DIR}/etc/agent-config.json"
fi

ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/wazuh-agentd
ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/wazuh-control

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
    systemctl enable wazuh-rust-agent.service > /dev/null 2>&1 || true
    systemctl restart wazuh-rust-agent.service > /dev/null 2>&1 || true
fi

%preun
if [ "$1" = "0" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop wazuh-rust-agent.service > /dev/null 2>&1 || true
        systemctl disable wazuh-rust-agent.service > /dev/null 2>&1 || true
    fi
    rm -f /usr/local/bin/wazuh-agentd
    rm -f /usr/local/bin/wazuh-control
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi

%files
%defattr(-,root,root,-)
%dir %attr(750,root,wazuh) /var/ossec
%dir %attr(750,root,wazuh) /var/ossec/bin
%attr(750,root,wazuh) /var/ossec/bin/siem-agent-linux
%dir %attr(750,root,wazuh) /var/ossec/etc
%dir %attr(750,wazuh,wazuh) /var/ossec/logs
%dir %attr(750,wazuh,wazuh) /var/ossec/queue
%dir %attr(700,root,wazuh) /var/ossec/quarantine
/usr/lib/systemd/system/wazuh-rust-agent.service
