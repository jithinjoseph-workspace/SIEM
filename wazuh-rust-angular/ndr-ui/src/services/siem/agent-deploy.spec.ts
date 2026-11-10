import { DeployParams, canDeploy, installCommand, linuxDeployScript, windowsBatScript, windowsInstallScript } from './agent-deploy';

const CA = '-----BEGIN CERTIFICATE-----\nMIIBtest$`"\n-----END CERTIFICATE-----\n';

const params = (over: Partial<DeployParams> = {}): DeployParams => ({
  os: 'windows',
  server: {
    https_url: 'https://10.0.0.1:8443',
    grpc_url: 'grpcs://10.0.0.1:8089',
    ca_pem: CA,
    agent_files: { 'provigil-agent.exe': 'aa11', 'netsh.exe': 'bb22' },
  },
  managerUrl: 'http://manager.corp:4200',
  agentName: 'win-node-1',
  group: 'default',
  tenantKey: 'tk_abc',
  winMode: 'admin-ps',
  ...over,
});

describe('agent install commands', () => {
  it('Windows: writes the CA, pins it in the settings, and uses the console host', () => {
    const s = windowsInstallScript(params());
    expect(s).toContain('WriteAllText("$d\\ca.pem", "-----BEGIN CERTIFICATE-----`nMIIBtest`$```"`n-----END CERTIFICATE-----`n")');
    expect(s).toContain('ca_file = "$d\\ca.pem"');
    expect(s).toContain('$m = "https://manager.corp:8443"');
    expect(s).toContain('grpc_url = "grpcs://manager.corp:8089"');
    expect(s).toContain('force_enroll = $true');
    expect(s).not.toMatch(/ca\.pem", "[^"]*\n/);
  });

  it('Windows: checks every published file before the service stops', () => {
    const s = windowsInstallScript(params());
    expect(s).toContain(`'provigil-agent.exe' = 'aa11'; 'netsh.exe' = 'bb22'`);
    expect(s).not.toContain('restart-wazuh.exe');
    expect(s).toContain('Get-FileHash -Algorithm SHA256');
    expect(s.indexOf('Get-FileHash')).toBeLessThan(s.indexOf('Stop-Service'));
    expect(s).toMatch(/-ne \$hash\[\$f\]\) \{ Remove-Item -Recurse -Force \$t; throw/);
  });

  it('Windows: does not enroll and handles no agent key', () => {
    const s = windowsInstallScript(params());
    expect(s).not.toContain('/api/v1/agents/enroll');
    expect(s).not.toContain('raw_key');
    expect(s).not.toContain('Invoke-RestMethod');
    expect(s).not.toContain('PRIVATE KEY');
    expect(s).not.toMatch(/WriteAllText\("\$d\\\\client\.keys"/);
    // the old enrollment goes, or the agent would load it instead of enrolling
    expect(s).toMatch(/Remove-Item[^;]*\$id[^;]*client\.keys/);
    expect(s).toContain("$cfg['tenant_key'] = \"tk_abc\"");
  });

  it('Windows: waits for the agent to enroll and fails clearly', () => {
    const s = windowsInstallScript(params());
    expect(s).toContain('$w -lt 60');
    expect(s).toContain('did not enroll');
    expect(s.indexOf('Start-Service -Name')).toBeLessThan(s.indexOf('$w -lt 60'));
  });

  it('Linux: enrolls and downloads over TLS with the CA', () => {
    for (const s of [installCommand(params({ os: 'linux' })), linuxDeployScript(params({ os: 'linux' }))]) {
      expect(s).toContain(btoa(CA));
      expect(s).toContain(`curl -fsSL --cacert "$t/ca.pem" 'https://manager.corp:8443/downloads/install.sh'`);
      expect(s).toContain(`SIEM_MANAGER_URL='https://manager.corp:8443'`);
      expect(s).toContain('SIEM_CA_FILE="$t/ca.pem"');
      expect(s).not.toContain('http://');
    }
  });

  it('gives no command without the TLS details or the agent program', () => {
    expect(installCommand(params({ server: null }))).toBe('');
    expect(installCommand(params({ os: 'linux', server: null }))).toBe('');
    const noAgent = params({ server: { ...params().server!, agent_files: {} } });
    expect(canDeploy(noAgent)).toBe(false);
    expect(installCommand(noAgent)).toBe('');
    expect(canDeploy({ ...noAgent, os: 'linux' })).toBe(true);
  });

  it('the .bat carries the script', () => {
    expect(windowsBatScript(params())).toContain('-EncodedCommand');
  });
});
