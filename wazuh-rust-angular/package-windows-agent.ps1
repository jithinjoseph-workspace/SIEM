# Next-Gen Wazuh Rust Agent Windows Packaging Script
param(
    [string]$OutputDir = ".\dist\windows-agent",
    [string]$ManagerUrl = "http://127.0.0.1:8088",
    [string]$AgentId = "win-agent-for-laptop"
)

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host "Building and Packaging Next-Gen Wazuh Rust Windows Agent" -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Ensure MinGW toolchain is in path
$mingwBin = "C:\Users\josep\AppData\Local\Microsoft\WinGet\Packages\MartinStorsjo.LLVM-MinGW.UCRT_Microsoft.Winget.Source_8wekyb3d8bbwe\llvm-mingw-20260616-ucrt-x86_64\bin"
if (Test-Path $mingwBin) {
    $env:Path = "$mingwBin;" + $env:Path
}

# 2. Build Release Binary
Write-Host "Compiling siem-agent release binary..." -ForegroundColor Yellow
Set-Location -Path "$PSScriptRoot\backend-rust"
cargo build --release --bin siem-agent

if ($LASTEXITCODE -ne 0) {
    Write-Host "Compilation failed! Check toolchain errors." -ForegroundColor Red
    Exit 1
}

# 3. Create Package Directory
Set-Location -Path $PSScriptRoot
if (Test-Path $OutputDir) {
    Remove-Item -Path $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# 4. Copy Executable
$srcBin = ".\backend-rust\target\release\siem-agent.exe"
if (-not (Test-Path $srcBin)) {
    $srcBin = ".\backend-rust\target\x86_64-pc-windows-gnu\release\siem-agent.exe"
}
Copy-Item -Path $srcBin -Destination "$OutputDir\siem-agent.exe"


# 5. Generate official Wazuh ossec.conf
@"
<ossec_config>
  <client>
    <server>
      <address>$ManagerUrl</address>
      <port>8088</port>
      <protocol>tcp</protocol>
    </server>
    <config-profile>windows</config-profile>
    <crypto_method>aes</crypto_method>
  </client>

  <client_buffer>
    <disabled>no</disabled>
    <queue_size>5000</queue_size>
    <events_per_second>500</events_per_second>
  </client_buffer>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>C:\Windows\System32,C:\Program Files</directories>
    <ignore>C:\Windows\System32\LogFiles</ignore>
  </syscheck>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports>yes</ports>
    <processes>yes</processes>
  </wodle>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>Security</location>
  </localfile>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>System</location>
  </localfile>

  <localfile>
    <log_format>eventchannel</log_format>
    <location>Microsoft-Windows-Sysmon/Operational</location>
  </localfile>

  <active-response>
    <disabled>no</disabled>
    <command>netsh-block</command>
    <location>local</location>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
"@ | Set-Content -Path "$OutputDir\ossec.conf"

# 6. Generate Environment Configuration Script (run-agent.bat)
@"
@echo off
set SIEM_MANAGER_URL=$ManagerUrl
set SIEM_AGENT_ID=$AgentId
echo Starting Next-Gen Wazuh Windows Agent...
siem-agent.exe
pause
"@ | Set-Content -Path "$OutputDir\run-agent.bat"

# 6. Generate Windows Service Installer (install-service.ps1)
@"
param([string]`$ManagerUrl = "$ManagerUrl", [string]`$AgentId = "$AgentId")
Write-Host "Installing Wazuh Rust Agent as Windows Service..." -ForegroundColor Cyan
`$binPath = "`$PSScriptRoot\siem-agent.exe"
New-Service -Name "WazuhRustAgent" -BinaryPathName "`"`$binPath`"" -DisplayName "Wazuh Rust Endpoint Agent" -StartupType Automatic -Description "Next-Gen SIEM & FIM telemetry collector"
Write-Host "Configuring service environment variables..."
[System.Environment]::SetEnvironmentVariable("SIEM_MANAGER_URL", `$ManagerUrl, "Machine")
[System.Environment]::SetEnvironmentVariable("SIEM_AGENT_ID", `$AgentId, "Machine")
Start-Service -Name "WazuhRustAgent"
Write-Host "Wazuh Rust Agent service installed and started successfully!" -ForegroundColor Green
"@ | Set-Content -Path "$OutputDir\install-service.ps1"

# 7. Create ZIP Distribution
$zipPath = ".\dist\wazuh-agent-windows-x64.zip"
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
Compress-Archive -Path "$OutputDir\*" -DestinationPath $zipPath -Force

Write-Host "========================================================" -ForegroundColor Green
Write-Host "Agent package generated successfully!" -ForegroundColor Green
Write-Host "Folder: $OutputDir" -ForegroundColor Green
Write-Host "ZIP:    $zipPath" -ForegroundColor Green
Write-Host "========================================================" -ForegroundColor Green
