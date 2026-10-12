# PROVIGIL AETHER - local Windows launcher
$ErrorActionPreference = 'Stop'
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $ScriptDir 'wazuh-rust-angular\backend-rust'
$FrontendDir = Join-Path $ScriptDir 'wazuh-rust-angular\ndr-ui'
function Test-ListeningPort([int]$Port) { $null -ne (Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue) }
function Wait-ListeningPort([int]$Port, [string]$Name, [int]$Seconds = 25) {
  for ($i = 0; $i -lt $Seconds; $i++) { if (Test-ListeningPort $Port) { Write-Host "[OK] $Name is listening on :$Port" -ForegroundColor Green; return $true }; Start-Sleep 1 }
  Write-Host "[FAIL] $Name did not start on :$Port. Check its terminal window." -ForegroundColor Red; return $false
}
function Start-Backend([string]$Title, [string]$Binary, [string]$Fallback) {
  if (Test-Path $Binary) { Start-Process cmd.exe -WorkingDirectory $BackendDir -ArgumentList "/k title $Title & `"$Binary`"" }
  else { Start-Process cmd.exe -WorkingDirectory $BackendDir -ArgumentList "/k title $Title & $Fallback" }
}
$env:CLICKHOUSE_URL = 'http://127.0.0.1:8123'; $env:CLICKHOUSE_USER = 'default'; $env:CLICKHOUSE_PASSWORD = ''
$env:CLICKHOUSE_DB = 'ndr'; $env:VALKEY_URL = 'redis://127.0.0.1:6379'; $env:LISTEN_ADDR = '0.0.0.0:3001'
$secretFile = Join-Path $BackendDir 'data\jwt_secret.txt'
if (-not (Test-Path $secretFile)) { New-Item -ItemType Directory -Force (Split-Path $secretFile) | Out-Null; $bytes = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes); [IO.File]::WriteAllText($secretFile, (($bytes | ForEach-Object { $_.ToString('x2') }) -join '')) }
$env:JWT_SECRET = (Get-Content -Raw $secretFile).Trim()
if (-not (Test-ListeningPort 8123)) { throw 'ClickHouse is not listening on :8123. Start Docker dependencies first.' }
if (-not (Test-ListeningPort 6379)) { throw 'Valkey is not listening on :6379. Start Docker dependencies first.' }
if (-not (Test-ListeningPort 3001)) { Start-Backend 'Provigil Auth Service (:3001)' (Join-Path $BackendDir 'target\release\auth-service.exe') 'cargo run --release -p auth-service' }
if (-not (Wait-ListeningPort 3001 'Auth service')) { exit 1 }
if (-not (Test-ListeningPort 8088)) { Start-Backend 'Provigil SIEM API (:8088)' (Join-Path $BackendDir 'target\release\siem-api.exe') 'cargo run --bin siem-api' }
if (-not (Wait-ListeningPort 8088 'SIEM API')) { exit 1 }
if (-not (Test-ListeningPort 4200)) { Start-Process cmd.exe -WorkingDirectory $FrontendDir -ArgumentList '/k title Provigil Angular UI (:4200) & npm start' }
if (-not (Wait-ListeningPort 4200 'Angular UI' 45)) { exit 1 }
Write-Host "[OK] SIEM is ready: http://localhost:4200" -ForegroundColor Green
Start-Process 'http://localhost:4200'
