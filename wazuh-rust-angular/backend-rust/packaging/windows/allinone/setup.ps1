<#
  ProVigil all-in-one on Windows (containers): run by ProVigil-AllInOne-Setup-<v>.msi after it installs.
  1. WSL2 on (one reboot when it was off; this script continues after the sign-in).
  2. ProVigil's own Ubuntu 24.04 (distro "ProVigil", checked against Ubuntu's SHA256SUMS), systemd on.
  3. Network: mirrored (Windows 11 22H2+), so the containers answer on this PC's LAN address; older
     Windows: port forwarding refreshed at every start. Firewall: 443, 8089, 8443, 9092.
  4. provigil-install.sh inside it, role all-in-one, with the licence: Docker Engine and the licensed
     SIEM and NDR containers.
  5. A task keeps it running from Windows start (and sign-in); the console opens.
  Log: %ProgramData%\ProVigil\allinone-setup.log
#>
param([string]$Licence, [string]$Msi, [switch]$Resume)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Here = $PSScriptRoot
$Distro = 'ProVigil'
$Data = Join-Path $env:ProgramData 'ProVigil'
$WslHome = Join-Path $Data 'wsl'
$Ports = 443, 8089, 8443, 9092
$Rootfs = 'https://cloud-images.ubuntu.com/wsl/releases/24.04/current/ubuntu-noble-wsl-amd64-wsl.rootfs.tar.gz'
$Sums = 'https://cloud-images.ubuntu.com/wsl/releases/24.04/current/SHA256SUMS'

function Say($m) { Write-Host "[provigil] $m" -ForegroundColor Green }
function Stop-Setup($m) { Write-Host "[provigil] ERROR: $m" -ForegroundColor Red; Read-Host 'Press Enter to close'; exit 1 }

# administrator rights, as the same user (WSL distros belong to a user)
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) {
    $a = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
    if ($Licence) { $a += '-Licence', "`"$Licence`"" }
    if ($Msi) { $a += '-Msi', "`"$Msi`"" }
    if ($Resume) { $a += '-Resume' }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $a
    exit 0
}
New-Item -ItemType Directory -Force $Data | Out-Null
Start-Transcript -Append (Join-Path $Data 'allinone-setup.log') | Out-Null

$build = [Environment]::OSVersion.Version.Build
if ($build -lt 19041) { Stop-Setup "Windows 10 2004 (build 19041) or newer is needed for WSL2 (this is build $build)" }
$mirrored = $build -ge 22621

# the licence: given, next to the MSI, kept from an earlier run, or chosen
$kept = Join-Path $Data 'licence.jwt'
if (-not $Licence -and $Msi) { $Licence = Join-Path (Split-Path $Msi) 'licence.jwt' }
if (-not $Licence -or -not (Test-Path $Licence)) { $Licence = if (Test-Path $kept) { $kept } else { $null } }
if (-not $Licence) {
    Add-Type -AssemblyName System.Windows.Forms
    $d = New-Object System.Windows.Forms.OpenFileDialog -Property @{ Title = 'ProVigil licence (licence.jwt from the installer zip)'; Filter = 'Licence (*.jwt)|*.jwt|All files|*.*' }
    if ($d.ShowDialog() -ne 'OK') { Stop-Setup 'no licence chosen' }
    $Licence = $d.FileName
}
if ((Resolve-Path $Licence).Path -ne $kept) { Copy-Item $Licence $kept -Force }
Say "licence: $kept"

# 1. WSL2
$restart = $false
foreach ($f in 'Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform') {
    if ((Get-WindowsOptionalFeature -Online -FeatureName $f).State -ne 'Enabled') {
        Say "turning on $f..."
        if ((Enable-WindowsOptionalFeature -Online -FeatureName $f -All -NoRestart).RestartNeeded) { $restart = $true }
    }
}
if ($restart) {
    # continue after the restart, at this user's sign-in
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Licence `"$kept`" -Resume"
    Set-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce' 'ProVigilSetup' $cmd
    Say 'Windows must restart once. Setup continues by itself after you sign in again.'
    if ((Read-Host 'Restart now? [Y/n]') -notmatch '^[nN]') { Restart-Computer -Force }
    exit 0
}
Say 'updating WSL...'
& wsl.exe --update
& wsl.exe --set-default-version 2 *> $null

# 2. ProVigil's Ubuntu
$have = (& wsl.exe --list --quiet) -replace "`0", '' | Where-Object { $_.Trim() -eq $Distro }
if (-not $have) {
    New-Item -ItemType Directory -Force $WslHome | Out-Null
    $tar = Join-Path $env:TEMP 'provigil-ubuntu-rootfs.tar.gz'
    Say 'downloading Ubuntu 24.04 for WSL (about 350 MB)...'
    & curl.exe -fL --retry 3 -o $tar $Rootfs
    if ($LASTEXITCODE -ne 0) { Stop-Setup "Ubuntu did not download ($Rootfs)" }
    $want = ((Invoke-WebRequest -UseBasicParsing $Sums).Content -split "`n" | Where-Object { $_ -match 'amd64-wsl\.rootfs\.tar\.gz$' } | Select-Object -First 1) -split '\s+' | Select-Object -First 1
    $got = (Get-FileHash $tar -Algorithm SHA256).Hash
    if (-not $want -or $got -ne $want.ToUpper()) { Remove-Item $tar; Stop-Setup 'the Ubuntu download does not match Ubuntu''s checksum' }
    Say 'creating the ProVigil Linux (WSL2)...'
    & wsl.exe --import $Distro $WslHome $tar --version 2
    if ($LASTEXITCODE -ne 0) { Stop-Setup 'wsl --import failed' }
    Remove-Item $tar
}
& wsl.exe -d $Distro -u root -e sh -c "printf '[boot]\nsystemd=true\n[user]\ndefault=root\n' > /etc/wsl.conf"
& wsl.exe --terminate $Distro *> $null

# 3. network and firewall
$cfg = Join-Path $env:USERPROFILE '.wslconfig'
$text = if (Test-Path $cfg) { Get-Content $cfg -Raw } else { '' }
$gb = [math]::Max(4, [math]::Floor((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB * 0.75))
if ($text -notmatch '(?m)^\s*\[wsl2\]') { $text = $text.TrimEnd() + "`r`n[wsl2]`r`n" }
$add = @()
if ($mirrored -and $text -notmatch '(?m)^\s*networkingMode') { $add += 'networkingMode=mirrored' }
if ($text -notmatch '(?m)^\s*memory\s*=') { $add += "memory=${gb}GB" }
if ($text -notmatch '(?m)^\s*vmIdleTimeout') { $add += 'vmIdleTimeout=-1' }
if ($add) {
    $text = $text -replace '(?m)^(\s*\[wsl2\]\s*)$', ('$1' + "`r`n" + ($add -join "`r`n"))
    Set-Content $cfg $text.Trim() -Encoding ascii
    & wsl.exe --shutdown
}
if ($mirrored -and (Get-Command Set-NetFirewallHyperVVMSetting -ErrorAction SilentlyContinue)) {
    Set-NetFirewallHyperVVMSetting -Name '{40E0AC32-46A5-438A-A0B2-2B479E8F2E90}' -DefaultInboundAction Allow
}
if (-not (Get-NetFirewallRule -DisplayName 'ProVigil' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName 'ProVigil' -Direction Inbound -Protocol TCP -LocalPort $Ports -Action Allow | Out-Null
}

# 4. the ProVigil install inside it (asks its own questions in this window)
# -e: the arguments go as they are (paths with spaces, like Program Files)
$inst = & wsl.exe -d $Distro -u root -e wslpath -a ((Join-Path $Here 'provigil-install.sh') -replace '\\', '/')
$lic = & wsl.exe -d $Distro -u root -e wslpath -a ($kept -replace '\\', '/')
Say 'installing ProVigil (Docker Engine and the licensed SIEM and NDR containers)...'
& wsl.exe -d $Distro -u root -e bash $inst --role allinone --licence $lic
if ($LASTEXITCODE -ne 0) { Stop-Setup "the ProVigil install stopped (exit $LASTEXITCODE); run the MSI again to retry" }

# 5. running from Windows start: a task holds the Linux open (WSL stops an idle one)
$keep = Join-Path $Here 'keep-running.ps1'
$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$keep`""
$trig = @((New-ScheduledTaskTrigger -AtStartup), (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME))
$set = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
# shortcut: S4U (no stored password) runs the start trigger without a sign-in; if WSL refuses it on a
# Windows version, the sign-in trigger still starts it: use auto sign-in there, or a task password
$who = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType S4U -RunLevel Highest
Register-ScheduledTask -TaskName 'ProVigil' -Action $act -Trigger $trig -Settings $set -Principal $who -Force | Out-Null
Start-ScheduledTask -TaskName 'ProVigil'

Set-Content (Join-Path $Data 'allinone.done') (Get-Date -Format s)
Say 'ProVigil is installed. The console: https://localhost (other PCs: https://<this PC''s IP>)'
Start-Process 'https://localhost'
Stop-Transcript | Out-Null
Read-Host 'Press Enter to close'
