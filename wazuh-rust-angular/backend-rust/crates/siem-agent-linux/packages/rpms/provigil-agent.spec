# ProVigil Endpoint Agent - RPM Package Specification
Name:           provigil-agent
Version:        1.0.0
Release:        1%{?dist}
Summary:        ProVigil Endpoint Telemetry & Threat Defense Agent

License:        Proprietary
Source0:        siem-agent-linux
Source1:        provigil-agent.service

Requires:       systemd
Requires:       procps-ng
Requires:       iptables
AutoReqProv:    no

%description
ProVigil provides security visibility across Linux infrastructure with
low CPU/memory footprint, real-time File Integrity Monitoring, Linux CIS
benchmark assessments, and active response remediation.

%prep

%build

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/opt/provigil-agent/bin
mkdir -p %{buildroot}/opt/provigil-agent/etc
mkdir -p %{buildroot}/opt/provigil-agent/logs
mkdir -p %{buildroot}/opt/provigil-agent/queue
mkdir -p %{buildroot}/opt/provigil-agent/quarantine
mkdir -p %{buildroot}/usr/lib/systemd/system

install -m 750 %{SOURCE0} %{buildroot}/opt/provigil-agent/bin/siem-agent-linux
install -m 644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/provigil-agent.service

%pre
if ! getent group provigil >/dev/null 2>&1; then
    groupadd -r provigil >/dev/null 2>&1 || true
fi
if ! getent passwd provigil >/dev/null 2>&1; then
    useradd -r -g provigil -d /opt/provigil-agent -s /sbin/nologin -c "ProVigil Agent" provigil >/dev/null 2>&1 || true
fi

%post
DIR="/opt/provigil-agent"
if [ ! -f "${DIR}/etc/agent-config.json" ]; then
    cat <<EOF > "${DIR}/etc/agent-config.json"
{
  "manager_url": "https://127.0.0.1:8443",
  "agent_name": "provigil-rhel-endpoint",
  "buffer_capacity": 5000,
  "events_per_second": 500
}
EOF
    chmod 640 "${DIR}/etc/agent-config.json"
    chown root:provigil "${DIR}/etc/agent-config.json"
fi

ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/provigil-agentd
ln -sf "${DIR}/bin/siem-agent-linux" /usr/local/bin/provigil-control

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
    systemctl enable provigil-agent.service > /dev/null 2>&1 || true
    systemctl restart provigil-agent.service > /dev/null 2>&1 || true
fi

%preun
if [ "$1" = "0" ]; then
    if [ -d /run/systemd/system ]; then
        systemctl stop provigil-agent.service > /dev/null 2>&1 || true
        systemctl disable provigil-agent.service > /dev/null 2>&1 || true
    fi
    rm -f /usr/local/bin/provigil-agentd
    rm -f /usr/local/bin/provigil-control
fi

%postun
if [ -d /run/systemd/system ]; then
    systemctl daemon-reload > /dev/null 2>&1 || true
fi

%files
%defattr(-,root,root,-)
%dir %attr(750,root,provigil) /opt/provigil-agent
%dir %attr(750,root,provigil) /opt/provigil-agent/bin
%attr(750,root,provigil) /opt/provigil-agent/bin/siem-agent-linux
%dir %attr(750,root,provigil) /opt/provigil-agent/etc
%dir %attr(750,provigil,provigil) /opt/provigil-agent/logs
%dir %attr(750,provigil,provigil) /opt/provigil-agent/queue
%dir %attr(700,root,provigil) /opt/provigil-agent/quarantine
/usr/lib/systemd/system/provigil-agent.service

