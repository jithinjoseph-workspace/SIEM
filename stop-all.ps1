# ==============================================================================
# PROVIGIL AETHER SIEM - STOP SERVICES POWERSHELL SCRIPT
# ==============================================================================

Write-Host "Stopping all Provigil SIEM & EDR services..." -ForegroundColor Yellow

$Ports = @(8088, 4200)
foreach ($Port in $Ports) {
    $Conns = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    if ($Conns) {
        foreach ($Conn in $Conns) {
            $PIDToKill = $Conn.OwningProcess
            try {
                Stop-Process -Id $PIDToKill -Force -ErrorAction SilentlyContinue
                Write-Host "[OK] Terminated PID $PIDToKill on port $Port" -ForegroundColor Green
            } catch {
                Write-Host "[!] Could not terminate PID $PIDToKill on port $Port" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "[-] Port $Port is not in use" -ForegroundColor Gray
    }
}

Get-Process | Where-Object { $_.ProcessName -eq "siem-api" } | ForEach-Object {
    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
    Write-Host "[OK] Stopped process siem-api ($($_.Id))" -ForegroundColor Green
}

Write-Host "`nAll SIEM services stopped." -ForegroundColor Green
