# ProVigil master (PC 1): connects this master to the data lake (PC 2) and the AI node (PC 3).
#
#   .\connect-master.ps1 -DataLake 192.168.1.20 [-AiNode 192.168.1.30] [-PasswordFile pw.txt] [-NoFirewall] [-DryRun]
#
# Checks that the data lake answers with the ProVigil user's password (asked for, or read from
# -PasswordFile), backs up .env and points it at the data lake, opens the inbound ports agents and
# the console need (as administrator), and checks the AI node. Restart ProVigil afterwards
# (stop-all.bat, start-all.bat); start-all then uses the data lake and starts only Valkey locally.
# The data already on this PC is not moved: see deploy/server/README.md, "Moving to the three-PC setup".
param(
    [Parameter(Mandatory = $true)][string]$DataLake,
    [string]$User = 'provigil',
    [string]$PasswordFile,
    [string]$AiNode,
    [string]$EnvFile = (Join-Path $PSScriptRoot '..\..\..\.env'),
    [int]$DataLakePort = 8123,
    [int]$AiPort = 11434,
    [switch]$NoFirewall,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
function Say($m) { Write-Host "[provigil] $m" }
function Stop-Run($m) { Write-Host "[provigil] ERROR: $m" -ForegroundColor Red; exit 1 }

$hostPattern = '^[A-Za-z0-9.-]{1,253}$'
if ($DataLake -notmatch $hostPattern) { Stop-Run '-DataLake must be a host name or IP address' }
if ($AiNode -and $AiNode -notmatch $hostPattern) { Stop-Run '-AiNode must be a host name or IP address' }
if ($User -notmatch '^[A-Za-z0-9_]{1,64}$') { Stop-Run '-User may only have letters, digits and _' }
if (-not (Test-Path $EnvFile)) { Stop-Run "settings file not found: $EnvFile" }

# the password: never on the command line
if ($PasswordFile) {
    $password = (Get-Content -TotalCount 1 $PasswordFile).Trim()
} else {
    $sec = Read-Host -AsSecureString "Password of '$User' on the data lake"
    $password = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}
if ($password.Length -lt 16) { Stop-Run 'the password must have at least 16 characters' }
# .env is read by a batch file: these characters would break or change it
if ($password -match '[&|<>^%"!\s=]') { Stop-Run 'the password has a character the settings file cannot hold (& | < > ^ % " ! = or a space); use letters and digits' }

# 1. the data lake answers, with this user
$url = "http://${DataLake}:$DataLakePort"
$auth = @{ Authorization = 'Basic ' + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("${User}:$password")) }
function Get-Lake($q) { (Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Headers $auth -Uri ("$url/?query=" + [Uri]::EscapeDataString($q))).Content.Trim() }
try { $version = Get-Lake 'SELECT version()' } catch { Stop-Run "the data lake at $url does not accept '$User': $($_.Exception.Message)" }
Say "data lake $url answers (ClickHouse $version)"
if ((Get-Lake "SELECT count() FROM system.databases WHERE name = 'ndr'") -ne '1') { Say 'warning: the data lake has no ndr database yet; run install-datalake.sh there first' }

# 2. the AI node (optional): answers, and which models it has
if ($AiNode) {
    try {
        $tags = Invoke-RestMethod -TimeoutSec 10 -Uri "http://${AiNode}:$AiPort/api/tags"
        $models = @($tags.models | ForEach-Object { $_.name }) -join ', '
        Say "AI node http://${AiNode}:$AiPort answers; models: $models"
        Say "in the console, Admin > AI providers > add: type openai, base URL http://${AiNode}:$AiPort, model one of the above, no key, priority 1"
    } catch { Stop-Run "the AI node at http://${AiNode}:$AiPort does not answer: $($_.Exception.Message)" }
}

# 3. .env: a dated copy first, then the three data lake lines replaced (or added)
$lines = [Collections.Generic.List[string]](Get-Content $EnvFile)
$set = [ordered]@{ CLICKHOUSE_URL = $url; CLICKHOUSE_USER = $User; CLICKHOUSE_PASSWORD = $password }
foreach ($k in $set.Keys) {
    $i = -1; for ($n = 0; $n -lt $lines.Count; $n++) { if ($lines[$n] -match "^$k=") { $i = $n } }
    if ($i -ge 0) { $lines[$i] = "$k=$($set[$k])" } else { $lines.Add("$k=$($set[$k])") }
}
if ($DryRun) {
    Say "dry run: .env would get CLICKHOUSE_URL=$url and CLICKHOUSE_USER=$User (and the password)"
} else {
    $backup = "$EnvFile.bak-" + (Get-Date -Format 'yyyyMMddHHmmss')
    Copy-Item $EnvFile $backup
    [IO.File]::WriteAllText((Resolve-Path $EnvFile), (($lines -join "`r`n") + "`r`n"), [Text.Encoding]::ASCII)
    Say ".env now points at the data lake (previous settings kept in $backup)"
}

# 4. inbound ports: agents 8089 and 8443, console 8088 and 4200
if (-not $NoFirewall) {
    $admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $rules = @(@{ Name = 'ProVigil agents'; Ports = @('8089', '8443') }, @{ Name = 'ProVigil console'; Ports = @('8088', '4200') })
    foreach ($r in $rules) {
        if (Get-NetFirewallRule -DisplayName $r.Name -ErrorAction SilentlyContinue) { Say "firewall rule '$($r.Name)' is already there"; continue }
        if ($DryRun) { Say "dry run: would open TCP $($r.Ports -join ', ') ('$($r.Name)')"; continue }
        if (-not $admin) { Say "warning: not administrator, so '$($r.Name)' (TCP $($r.Ports -join ', ')) was not opened; run again as administrator"; continue }
        New-NetFirewallRule -DisplayName $r.Name -Direction Inbound -Protocol TCP -LocalPort $r.Ports -Action Allow | Out-Null
        Say "firewall: opened TCP $($r.Ports -join ', ') ('$($r.Name)')"
    }
}
Say 'done. Restart ProVigil (stop-all.bat, then start-all.bat) to use the data lake.'
