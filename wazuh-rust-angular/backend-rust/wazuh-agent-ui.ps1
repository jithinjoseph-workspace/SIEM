# ==============================================================================
# Wazuh Rust Agent - Desktop Management GUI (Equivalent to win32ui.exe)
# ==============================================================================
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$serviceName = "WazuhRustSvc"
$managerUrl = if ($env:SIEM_MANAGER_URL) { $env:SIEM_MANAGER_URL } else { "http://127.0.0.1:8088" }
$agentId = if ($env:SIEM_AGENT_ID) { $env:SIEM_AGENT_ID } else { "001" }
$hostname = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "wazuh-endpoint" }

# Create Form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Wazuh Rust Endpoint Agent - Manager Console"
$form.Size = New-Object System.Drawing.Size(620, 520)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false
$form.BackColor = [System.Drawing.Color]::FromArgb(18, 24, 38)
$form.ForeColor = [System.Drawing.Color]::White

# Top Header Panel
$headerPanel = New-Object System.Windows.Forms.Panel
$headerPanel.Location = New-Object System.Drawing.Point(0, 0)
$headerPanel.Size = New-Object System.Drawing.Size(620, 70)
$headerPanel.BackColor = [System.Drawing.Color]::FromArgb(10, 15, 26)
$form.Controls.Add($headerPanel)

$titleLabel = New-Object System.Windows.Forms.Label
$titleLabel.Text = "WAZUH RUST ENDPOINT AGENT"
$titleLabel.Font = New-Object System.Drawing.Font("Segoe UI", 14, [System.Drawing.FontStyle]::Bold)
$titleLabel.ForeColor = [System.Drawing.Color]::FromArgb(0, 229, 255)
$titleLabel.Location = New-Object System.Drawing.Point(20, 12)
$titleLabel.AutoSize = $true
$headerPanel.Controls.Add($titleLabel)

$subLabel = New-Object System.Windows.Forms.Label
$subLabel.Text = "Next-Gen Distributed SIEM & XDR Endpoint Sentinel (win32ui.exe Parity)"
$subLabel.Font = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Regular)
$subLabel.ForeColor = [System.Drawing.Color]::FromArgb(140, 155, 180)
$subLabel.Location = New-Object System.Drawing.Point(22, 40)
$subLabel.AutoSize = $true
$headerPanel.Controls.Add($subLabel)

# Service Status Panel
$statusGroup = New-Object System.Windows.Forms.GroupBox
$statusGroup.Text = " SERVICE STATUS "
$statusGroup.Location = New-Object System.Drawing.Point(20, 85)
$statusGroup.Size = New-Object System.Drawing.Size(565, 80)
$statusGroup.ForeColor = [System.Drawing.Color]::FromArgb(0, 229, 255)
$form.Controls.Add($statusGroup)

$lblStatusText = New-Object System.Windows.Forms.Label
$lblStatusText.Location = New-Object System.Drawing.Point(20, 30)
$lblStatusText.Size = New-Object System.Drawing.Size(250, 30)
$lblStatusText.Font = New-Object System.Drawing.Font("Segoe UI", 11, [System.Drawing.FontStyle]::Bold)
$statusGroup.Controls.Add($lblStatusText)

function Update-ServiceStatus {
    $svc = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq "Running") {
            $lblStatusText.Text = "● ACTIVE (Running in Background)"
            $lblStatusText.ForeColor = [System.Drawing.Color]::FromArgb(52, 211, 153)
        } else {
            $lblStatusText.Text = "○ STOPPED ($($svc.Status))"
            $lblStatusText.ForeColor = [System.Drawing.Color]::FromArgb(248, 113, 113)
        }
    } else {
        $lblStatusText.Text = "⚠ NOT INSTALLED AS SERVICE"
        $lblStatusText.ForeColor = [System.Drawing.Color]::FromArgb(251, 191, 36)
    }
}

$btnRefresh = New-Object System.Windows.Forms.Button
$btnRefresh.Text = "Refresh"
$btnRefresh.Location = New-Object System.Drawing.Point(460, 28)
$btnRefresh.Size = New-Object System.Drawing.Size(85, 32)
$btnRefresh.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnRefresh.ForeColor = [System.Drawing.Color]::White
$btnRefresh.FlatStyle = "Flat"
$btnRefresh.Add_Click({ Update-ServiceStatus })
$statusGroup.Controls.Add($btnRefresh)

# Config Panel
$cfgGroup = New-Object System.Windows.Forms.GroupBox
$cfgGroup.Text = " AGENT & SIEM CONFIGURATION "
$cfgGroup.Location = New-Object System.Drawing.Point(20, 180)
$cfgGroup.Size = New-Object System.Drawing.Size(565, 140)
$cfgGroup.ForeColor = [System.Drawing.Color]::FromArgb(0, 229, 255)
$form.Controls.Add($cfgGroup)

# Manager URL
$lblUrl = New-Object System.Windows.Forms.Label
$lblUrl.Text = "Manager Endpoint URL:"
$lblUrl.Location = New-Object System.Drawing.Point(20, 30)
$lblUrl.Size = New-Object System.Drawing.Size(150, 20)
$lblUrl.ForeColor = [System.Drawing.Color]::FromArgb(200, 210, 225)
$cfgGroup.Controls.Add($lblUrl)

$txtUrl = New-Object System.Windows.Forms.TextBox
$txtUrl.Text = $managerUrl
$txtUrl.Location = New-Object System.Drawing.Point(180, 28)
$txtUrl.Size = New-Object System.Drawing.Size(260, 24)
$txtUrl.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$txtUrl.ForeColor = [System.Drawing.Color]::White
$cfgGroup.Controls.Add($txtUrl)

# Agent ID
$lblId = New-Object System.Windows.Forms.Label
$lblId.Text = "Agent ID / Hostname:"
$lblId.Location = New-Object System.Drawing.Point(20, 65)
$lblId.Size = New-Object System.Drawing.Size(150, 20)
$lblId.ForeColor = [System.Drawing.Color]::FromArgb(200, 210, 225)
$cfgGroup.Controls.Add($lblId)

$txtId = New-Object System.Windows.Forms.TextBox
$txtId.Text = "$agentId ($hostname)"
$txtId.Location = New-Object System.Drawing.Point(180, 63)
$txtId.Size = New-Object System.Drawing.Size(260, 24)
$txtId.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$txtId.ForeColor = [System.Drawing.Color]::White
$cfgGroup.Controls.Add($txtId)

# Save Config Button
$btnSave = New-Object System.Windows.Forms.Button
$btnSave.Text = "Save Config"
$btnSave.Location = New-Object System.Drawing.Point(460, 28)
$btnSave.Size = New-Object System.Drawing.Size(85, 59)
$btnSave.BackColor = [System.Drawing.Color]::FromArgb(14, 116, 144)
$btnSave.ForeColor = [System.Drawing.Color]::White
$btnSave.FlatStyle = "Flat"
$btnSave.Add_Click({
    [System.Environment]::SetEnvironmentVariable("SIEM_MANAGER_URL", $txtUrl.Text, "Machine")
    [System.Windows.Forms.MessageBox]::Show("Configuration saved to System Environment! Restart the service to apply.", "Wazuh Agent", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})
$cfgGroup.Controls.Add($btnSave)

# Subsystems Checklist
$lblModules = New-Object System.Windows.Forms.Label
$lblModules.Text = "Active Subsystems: EventChannel | FIM (SHA-256) | Registry Sentinel | Syscollector | SCA CIS | win_execd"
$lblModules.Location = New-Object System.Drawing.Point(20, 105)
$lblModules.Size = New-Object System.Drawing.Size(530, 20)
$lblModules.Font = New-Object System.Drawing.Font("Segoe UI", 7.5)
$lblModules.ForeColor = [System.Drawing.Color]::FromArgb(148, 163, 184)
$cfgGroup.Controls.Add($lblModules)

# Action Buttons
$btnStart = New-Object System.Windows.Forms.Button
$btnStart.Text = "▶ Start Service"
$btnStart.Location = New-Object System.Drawing.Point(20, 340)
$btnStart.Size = New-Object System.Drawing.Size(125, 40)
$btnStart.BackColor = [System.Drawing.Color]::FromArgb(5, 150, 105)
$btnStart.ForeColor = [System.Drawing.Color]::White
$btnStart.FlatStyle = "Flat"
$btnStart.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnStart.Add_Click({
    Start-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Update-ServiceStatus
})
$form.Controls.Add($btnStart)

$btnStop = New-Object System.Windows.Forms.Button
$btnStop.Text = "⏹ Stop Service"
$btnStop.Location = New-Object System.Drawing.Point(155, 340)
$btnStop.Size = New-Object System.Drawing.Size(125, 40)
$btnStop.BackColor = [System.Drawing.Color]::FromArgb(220, 38, 38)
$btnStop.ForeColor = [System.Drawing.Color]::White
$btnStop.FlatStyle = "Flat"
$btnStop.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnStop.Add_Click({
    Stop-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Update-ServiceStatus
})
$form.Controls.Add($btnStop)

$btnRestart = New-Object System.Windows.Forms.Button
$btnRestart.Text = "🔄 Restart"
$btnRestart.Location = New-Object System.Drawing.Point(290, 340)
$btnRestart.Size = New-Object System.Drawing.Size(100, 40)
$btnRestart.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnRestart.ForeColor = [System.Drawing.Color]::White
$btnRestart.FlatStyle = "Flat"
$btnRestart.Add_Click({
    Restart-Service -Name $serviceName -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
    Update-ServiceStatus
})
$form.Controls.Add($btnRestart)

$btnPortal = New-Object System.Windows.Forms.Button
$btnPortal.Text = "🌐 Open SOC Dashboard"
$btnPortal.Location = New-Object System.Drawing.Point(400, 340)
$btnPortal.Size = New-Object System.Drawing.Size(185, 40)
$btnPortal.BackColor = [System.Drawing.Color]::FromArgb(99, 102, 241)
$btnPortal.ForeColor = [System.Drawing.Color]::White
$btnPortal.FlatStyle = "Flat"
$btnPortal.Font = New-Object System.Drawing.Font("Segoe UI", 9, [System.Drawing.FontStyle]::Bold)
$btnPortal.Add_Click({
    Start-Process "http://localhost:4200"
})
$form.Controls.Add($btnPortal)

# Quick Inspection Commands (Matching win32ui.c View & Help Menus)
$cmdGroup = New-Object System.Windows.Forms.GroupBox
$cmdGroup.Text = " INSPECTION & HELP (win32ui.c PARITY) "
$cmdGroup.Location = New-Object System.Drawing.Point(20, 395)
$cmdGroup.Size = New-Object System.Drawing.Size(565, 70)
$cmdGroup.ForeColor = [System.Drawing.Color]::FromArgb(0, 229, 255)
$form.Controls.Add($cmdGroup)

$btnLogs = New-Object System.Windows.Forms.Button
$btnLogs.Text = "View State / Logs"
$btnLogs.Location = New-Object System.Drawing.Point(15, 25)
$btnLogs.Size = New-Object System.Drawing.Size(120, 30)
$btnLogs.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnLogs.ForeColor = [System.Drawing.Color]::White
$btnLogs.FlatStyle = "Flat"
$btnLogs.Add_Click({
    if (Test-Path "wazuh-agent.state") {
        Start-Process "notepad.exe" -ArgumentList "wazuh-agent.state"
    } else {
        [System.Windows.Forms.MessageBox]::Show("wazuh-agent.state will be generated when the agent completes its first keepalive.", "Agent Logs")
    }
})
$cmdGroup.Controls.Add($btnLogs)

$btnEventLog = New-Object System.Windows.Forms.Button
$btnEventLog.Text = "Windows Events"
$btnEventLog.Location = New-Object System.Drawing.Point(145, 25)
$btnEventLog.Size = New-Object System.Drawing.Size(115, 30)
$btnEventLog.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnEventLog.ForeColor = [System.Drawing.Color]::White
$btnEventLog.FlatStyle = "Flat"
$btnEventLog.Add_Click({
    Start-Process "eventvwr.msc"
})
$cmdGroup.Controls.Add($btnEventLog)

$btnAbout = New-Object System.Windows.Forms.Button
$btnAbout.Text = "About Agent"
$btnAbout.Location = New-Object System.Drawing.Point(270, 25)
$btnAbout.Size = New-Object System.Drawing.Size(100, 30)
$btnAbout.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnAbout.ForeColor = [System.Drawing.Color]::White
$btnAbout.FlatStyle = "Flat"
$btnAbout.Add_Click({
    [System.Windows.Forms.MessageBox]::Show("Wazuh Rust Endpoint Agent v4.14.7-Rust`n`nHigh-Performance Native Distributed SIEM & XDR Sentinel`nLanguage: 100% Rust + Windows SCM & Win32 API`n`nStatus: Operational", "About Wazuh Agent", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
})
$cmdGroup.Controls.Add($btnAbout)

$btnExit = New-Object System.Windows.Forms.Button
$btnExit.Text = "Close"
$btnExit.Location = New-Object System.Drawing.Point(460, 25)
$btnExit.Size = New-Object System.Drawing.Size(85, 30)
$btnExit.BackColor = [System.Drawing.Color]::FromArgb(30, 41, 59)
$btnExit.ForeColor = [System.Drawing.Color]::White
$btnExit.FlatStyle = "Flat"
$btnExit.Add_Click({ $form.Close() })
$cmdGroup.Controls.Add($btnExit)

# Initial Load
Update-ServiceStatus

# Show Dialog
$form.ShowDialog() | Out-Null
