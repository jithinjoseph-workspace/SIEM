# ==============================================================================
# PROVIGIL AETHER - NEXT-GEN SIEM & EDR POWERSHELL LAUNCHER
# ==============================================================================

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "       PROVIGIL AETHER SIEM & EDR - UNIFIED SERVICE CONTROLLER" -ForegroundColor Green
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$BackendDir = Join-Path $ScriptDir "wazuh-rust-angular\backend-rust"
$FrontendDir = Join-Path $ScriptDir "wazuh-rust-angular\frontend-angular"

# 1. Check Port 8088 (Backend)
$BackendConn = Get-NetTCPConnection -LocalPort 8088 -ErrorAction SilentlyContinue
if ($BackendConn) {
    Write-Host "[OK] Rust SIEM Backend is already running on http://127.0.0.1:8088 (PID: $($BackendConn[0].OwningProcess))" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Rust SIEM Backend on port 8088..." -ForegroundColor Yellow
    $ReleaseBin = Join-Path $BackendDir "target\release\siem-api.exe"
    $DebugBin = Join-Path $BackendDir "target\debug\siem-api.exe"

    if (Test-Path $ReleaseBin) {
        Start-Process -FilePath $ReleaseBin -WorkingDirectory $BackendDir -WindowStyle Normal
    } elseif (Test-Path $DebugBin) {
        Start-Process -FilePath $DebugBin -WorkingDirectory $BackendDir -WindowStyle Normal
    } else {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$BackendDir`" && cargo run --bin siem-api" -WindowStyle Normal
    }
}

# 2. Check Port 4200 (Frontend)
$FrontendConn = Get-NetTCPConnection -LocalPort 4200 -ErrorAction SilentlyContinue
if ($FrontendConn) {
    Write-Host "[OK] Angular Frontend is already running on http://localhost:4200 (PID: $($FrontendConn[0].OwningProcess))" -ForegroundColor Green
} else {
    Write-Host "[*] Launching Angular Web Console on port 4200..." -ForegroundColor Yellow
    $DistDir = Join-Path $FrontendDir "dist\frontend-angular"
    if (Test-Path $DistDir) {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$FrontendDir`" && npx -y serve -s dist/frontend-angular -l 4200" -WindowStyle Normal
    } else {
        Start-Process -FilePath "cmd.exe" -ArgumentList "/k cd /d `"$FrontendDir`" && npm start" -WindowStyle Normal
    }
}

# 3. Health Check
Write-Host "`n[*] Verifying service health..." -ForegroundColor Cyan
$BackendHealthy = $false
for ($i = 0; $i -lt 10; $i++) {
    try {
        $res = Invoke-RestMethod -Uri "http://127.0.0.1:8088/api/dashboard" -TimeoutSec 2 -ErrorAction Stop
        if ($res.stats) {
            $BackendHealthy = $true
            break
        }
    } catch {
        Start-Sleep -Seconds 1
    }
}

if ($BackendHealthy) {
    Write-Host "[OK] Backend API Healthy (EPS: $($res.stats.eps_current), Ingested: $($res.stats.logs_today))" -ForegroundColor Green
} else {
    Write-Host "[!] Backend is still initializing, check the terminal window." -ForegroundColor Yellow
}

Write-Host "`n==============================================================================" -ForegroundColor Cyan
Write-Host "[OK] Services Active:" -ForegroundColor Green
Write-Host "    - Web Console URL:   http://localhost:4200" -ForegroundColor White
Write-Host "    - Rust REST API:     http://localhost:8088" -ForegroundColor White
Write-Host "    - WebSocket Alerts:  ws://localhost:8088/ws/alerts" -ForegroundColor White
Write-Host "==============================================================================" -ForegroundColor Cyan

Start-Sleep -Seconds 2
Start-Process "http://localhost:4200"
