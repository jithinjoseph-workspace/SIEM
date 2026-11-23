# ProVigil remote support for a managed on-premises master: an OUTBOUND SSH tunnel to ProVigil's
# support server. Nothing is opened inbound at the client; the client switches it on and off.
#
#   .\support-tunnel.ps1 -Enable -SupportHost support.example.com -User site-acme -RemotePort 20001 -HostKey 'ssh-ed25519 AAAA...' [-Hours 8] [-AllowRdp]
#   .\support-tunnel.ps1 -Disable
#   .\support-tunnel.ps1 -Status
#
# -Enable (as administrator) makes a key for this purpose only (C:\ProgramData\ProVigil\support),
# pins the support server's host key, and starts a scheduled task (SYSTEM, at start-up) that keeps
# the tunnel up: the support server's port -RemotePort reaches this master's console (and RDP with
# -AllowRdp). With -Hours the tunnel switches itself off after that many hours.
# Send ProVigil the public key it prints; on the support server it goes into authorized_keys as
#   restrict,port-forwarding,permitlisten="localhost:<RemotePort>",command="/bin/false" <key>
# (with -AllowRdp add ,permitlisten="localhost:<RemotePort+1>") so the key can open that tunnel
# and nothing else: no shell, no other port.
param(
    [switch]$Enable, [switch]$Disable, [switch]$Status,
    [string]$SupportHost, [string]$User, [int]$RemotePort, [string]$HostKey,
    [int]$SshPort = 22, [int]$ConsolePort = 4200, [int]$Hours = 0, [switch]$AllowRdp,
    [string]$Dir = 'C:\ProgramData\ProVigil\support', [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$TaskName = 'ProVigil support tunnel'
function Say($m) { Write-Host "[provigil] $m" }
function Stop-Run($m) { Write-Host "[provigil] ERROR: $m" -ForegroundColor Red; exit 1 }
$key = Join-Path $Dir 'id_ed25519'

if (@($Enable, $Disable, $Status).Where({ $_ }).Count -ne 1) { Stop-Run 'give one of -Enable, -Disable, -Status' }

if ($Status) {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if (-not $t) { Say 'support tunnel: off'; exit 0 }
    $ssh = @(Get-CimInstance Win32_Process -Filter "Name = 'ssh.exe'" | Where-Object { $_.CommandLine -like "*$key*" })
    Say "support tunnel: task $($t.State); connection $(if ($ssh.Count) { 'up' } else { 'not connected (retrying every 30 s)' })"
    if (Test-Path (Join-Path $Dir 'until.txt')) { Say "switches itself off at $(Get-Content (Join-Path $Dir 'until.txt'))" }
    exit 0
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin -and -not $DryRun) { Stop-Run 'run as administrator' }

if ($Disable) {
    if ($DryRun) { Say "dry run: would remove the task '$TaskName' and end its connection"; exit 0 }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name = 'ssh.exe'" | Where-Object { $_.CommandLine -like "*$key*" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }
    Remove-Item (Join-Path $Dir 'until.txt') -ErrorAction SilentlyContinue
    Say 'support tunnel switched off (the key is kept; delete the folder to revoke it here too)'
    exit 0
}

# -Enable: check everything before changing anything
if ($SupportHost -notmatch '^[A-Za-z0-9.-]{1,253}$') { Stop-Run '-SupportHost must be a host name or IP address' }
if ($User -notmatch '^[a-z0-9][a-z0-9_-]{0,31}$') { Stop-Run '-User must be a short lower-case account name' }
if ($RemotePort -lt 1024 -or $RemotePort -gt 65535) { Stop-Run '-RemotePort must be 1024-65535' }
if ($HostKey -notmatch '^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) [A-Za-z0-9+/=]{40,}$') { Stop-Run "-HostKey must be the support server's public host key ('ssh-ed25519 AAAA...')" }
if ($Hours -lt 0 -or $Hours -gt 720) { Stop-Run '-Hours must be 0 (no limit) to 720' }
$sshExe = (Get-Command ssh.exe -ErrorAction SilentlyContinue).Source
if (-not $sshExe) { Stop-Run "Windows' OpenSSH client is missing (Settings > Optional features > OpenSSH Client)" }

# "localhost:<port>": the support server's permitlisten compares this text literally
$forwards = @("-R", "localhost:${RemotePort}:127.0.0.1:$ConsolePort")
if ($AllowRdp) { $forwards += @("-R", "localhost:$($RemotePort + 1):127.0.0.1:3389") }
$known = Join-Path $Dir 'known_hosts'
$hostEntry = if ($SshPort -eq 22) { $SupportHost } else { "[$SupportHost]:$SshPort" }
$sshArgs = @('-N', '-T', '-i', $key, '-p', "$SshPort", '-o', 'BatchMode=yes', '-o', 'ExitOnForwardFailure=yes', '-o', 'ServerAliveInterval=30', '-o', 'ServerAliveCountMax=3',
    '-o', "UserKnownHostsFile=$known", '-o', 'StrictHostKeyChecking=yes', '-o', 'IdentitiesOnly=yes') + $forwards + @("$User@$SupportHost")

if ($DryRun) {
    Say "dry run: would run, again 30 s after each drop: ssh $($sshArgs -join ' ')"
    if ($Hours) { Say "dry run: would switch itself off after $Hours hours" }
    exit 0
}

New-Item -ItemType Directory -Force $Dir | Out-Null
# only SYSTEM and administrators may read the key
icacls $Dir /inheritance:r /grant:r 'SYSTEM:(OI)(CI)F' 'Administrators:(OI)(CI)F' | Out-Null
if (-not (Test-Path $key)) {
    & ssh-keygen.exe -q -t ed25519 -N '""' -C "provigil-support-$User" -f $key
    if ($LASTEXITCODE -ne 0) { Stop-Run 'ssh-keygen failed' }
}
Set-Content -Encoding ascii $known "$hostEntry $HostKey"
$until = if ($Hours) { (Get-Date).AddHours($Hours) } else { $null }
if ($until) { Set-Content (Join-Path $Dir 'until.txt') ($until.ToString('yyyy-MM-dd HH:mm')) } else { Remove-Item (Join-Path $Dir 'until.txt') -ErrorAction SilentlyContinue }

# the task's loop: reconnect 30 s after a drop; past the end time, remove itself
$quoted = ($sshArgs | ForEach-Object { "'" + ($_ -replace "'", "''") + "'" }) -join ','
$loop = @"
`$a = @($quoted)
while (`$true) {
  `$u = Join-Path '$Dir' 'until.txt'
  if ((Test-Path `$u) -and ((Get-Date) -ge [datetime](Get-Content `$u))) { Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false; Remove-Item `$u; exit }
  & '$sshExe' @a
  Start-Sleep 30
}
"@
$loopFile = Join-Path $Dir 'tunnel-loop.ps1'
Set-Content -Encoding utf8 $loopFile $loop
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$loopFile`""
$trigger = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Say "support tunnel on: $User@${SupportHost}:$SshPort, support port $RemotePort -> this console$(if ($AllowRdp) { ", $($RemotePort + 1) -> RDP" })$(if ($until) { ", until $($until.ToString('yyyy-MM-dd HH:mm'))" })"
Say 'send ProVigil this public key (for the support server, tunnel only):'
Get-Content "$key.pub"
