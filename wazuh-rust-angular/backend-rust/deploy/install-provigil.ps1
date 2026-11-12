<#
.SYNOPSIS
  Installs the ProVigil agent on this PC from the deployment kit next to this script.

.DESCRIPTION
  Part of the ProVigil deployment kit (specs/provigil-mass-deploy.md, C3). Used three ways:
    - by deploy-provigil.ps1 on every Windows PC it reaches (copied there with the kit's files);
    - as a Group Policy computer startup script, with the kit on a read-only share: runs as SYSTEM
      at boot, and returns in a second when the agent is already installed and current;
    - by hand: right-click PowerShell "Run as administrator", then .\install-provigil.ps1

  Reads deploy.json (gateway addresses, deployment token, agent group, options) and ca.pem, checks
  the SHA-256 of every file before anything changes, installs the ProVigilSvc service and waits for
  the agent to enroll. The agent enrolls under this computer's name; a reinstall keeps its name and ID.

  Prints one line "PROVIGIL_RESULT {json}" and writes the same JSON to -ResultFile.
  Exit codes: 0 installed, 1 already installed and enrolled, 2 enrollment failed,
  3 kit files bad, 4 not elevated, 5 uninstalled / uninstall failed (with -Uninstall).
#>
param(
    [string]$Kit = $PSScriptRoot,
    [string]$ResultFile = (Join-Path $PSScriptRoot 'result.json'),
    [switch]$Uninstall,
    [switch]$Force
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Service = 'ProVigilSvc'
$LegacyService = 'WazuhSvc'
$Dir = "${env:ProgramFiles(x86)}\ProVigil Agent"
$LegacyDir = "${env:ProgramFiles(x86)}\ossec-agent"
$IdFile = "$Dir\data\agent-identity.json"
$LogFile = "$env:ProgramData\ProVigil-install.log"

function Log([string]$m) {
    $line = "$(Get-Date -Format s) $m"
    Write-Host $line
    try { Add-Content -LiteralPath $LogFile -Value $line } catch { }
}

function Finish([int]$code, [string]$outcome, [string]$reason, [string]$agentId = '', [string]$agentName = '') {
    $os = try { (Get-CimInstance Win32_OperatingSystem).Caption } catch { 'Windows' }
    $r = [ordered]@{ computer = $env:COMPUTERNAME; os = $os; os_version = [Environment]::OSVersion.Version.ToString(); outcome = $outcome; reason = $reason; agent_id = $agentId; agent_name = $agentName }
    $json = $r | ConvertTo-Json -Compress
    Write-Output "PROVIGIL_RESULT $json"
    # read-only on a Group Policy share: the console has the enrollment anyway
    try { [IO.File]::WriteAllText($ResultFile, $json) } catch { }
    Log "$outcome $reason"
    exit $code
}

function Identity {
    if (Test-Path $IdFile) { try { return Get-Content -Raw $IdFile | ConvertFrom-Json } catch { } }
    $null
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Finish 4 'failed' 'not running as administrator' }

if ($Uninstall) {
    try {
        if (Get-Service $Service -ErrorAction SilentlyContinue) {
            & "$Dir\provigil-agent.exe" uninstall-service | Out-Null
            if (Get-Service $Service -ErrorAction SilentlyContinue) { throw 'the service is still there (tamper protection: open a maintenance window in the console first)' }
        }
        Finish 5 'skipped' 'agent uninstalled'
    } catch { Finish 5 'failed' "uninstall: $_" }
}

# ---------------------------------------------------------------- the kit
try {
    $deploy = Get-Content -Raw -LiteralPath (Join-Path $Kit 'deploy.json') | ConvertFrom-Json
} catch { Finish 3 'failed' "deploy.json not readable in $Kit" }
$files = @()
foreach ($p in $deploy.files.PSObject.Properties) {
    if ($p.Name -like 'windows/*' -or $p.Name -eq 'ca.pem') { $files += $p }
}
$agentHash = ($files | Where-Object { $_.Name -eq 'windows/provigil-agent.exe' }).Value
if (-not $agentHash) { Finish 3 'failed' 'deploy.json lists no windows/provigil-agent.exe' }

# ---------------------------------------------------------------- optional logging (deploy.json "options")
function PsLoggingOn {
    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
    (Get-ItemProperty "$k\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1 -and
        (Get-ItemProperty "$k\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging -eq 1
}
# shortcut: checks the two registry values this script sets, not each audit subcategory; re-run with -Force to set them all again
function AuditPolicyOn {
    (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).SCENoApplyLegacyAuditPolicy -eq 1 -and
        (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled -eq 1
}
function SysmonOn {
    $sv = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' OR Name='Sysmon64a' OR Name='Sysmon'" | Select-Object -First 1
    $sv -and $sv.State -eq 'Running'
}
# $all: after a (re)install, apply every option the kit turns on; else only the ones missing on this PC.
# Returns what was added.
function ApplyOptions([bool]$all) {
    $added = New-Object System.Collections.ArrayList
    $o = $deploy.options
    if (-not $o) { return ,$added }
    if ($o.ps_logging -and ($all -or -not (PsLoggingOn))) {
        try {
            $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
            New-Item -Path "$k\ScriptBlockLogging" -Force | Out-Null; Set-ItemProperty -Path "$k\ScriptBlockLogging" -Name EnableScriptBlockLogging -Value 1 -Type DWord
            New-Item -Path "$k\ModuleLogging\ModuleNames" -Force | Out-Null; Set-ItemProperty -Path "$k\ModuleLogging" -Name EnableModuleLogging -Value 1 -Type DWord
            Set-ItemProperty -Path "$k\ModuleLogging\ModuleNames" -Name '*' -Value '*'
            Log 'PowerShell script block and module logging turned on'; $added.Add('PowerShell logging') | Out-Null
        } catch { Log "PowerShell logging not changed: $_" }
    }
    if ($o.audit_policy -and ($all -or -not (AuditPolicyOn))) {
        try {
            Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord
            # by GUID (the names are translated in non-English Windows): credential validation, logon,
            # account lockout, user accounts, security groups, process creation
            $sets = @(
                @('{0CCE923F-69AE-11D9-BED3-505054503030}', $true, $true), @('{0CCE9215-69AE-11D9-BED3-505054503030}', $true, $true),
                @('{0CCE9217-69AE-11D9-BED3-505054503030}', $false, $true), @('{0CCE9235-69AE-11D9-BED3-505054503030}', $true, $true),
                @('{0CCE9237-69AE-11D9-BED3-505054503030}', $true, $false), @('{0CCE922B-69AE-11D9-BED3-505054503030}', $true, $false))
            foreach ($s in $sets) {
                $a = @('/set', "/subcategory:$($s[0])"); if ($s[1]) { $a += '/success:enable' }; if ($s[2]) { $a += '/failure:enable' }
                & auditpol @a | Out-Null
                if ($LASTEXITCODE -ne 0) { throw "auditpol $($s[0]) exited with $LASTEXITCODE" }
            }
            $k = 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System\Audit'; New-Item -Path $k -Force | Out-Null
            Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
            Log 'Windows audit policy set (with command lines)'; $added.Add('audit policy') | Out-Null
        } catch { Log "Audit policy not changed: $_" }
    }
    if ($o.sysmon -and ($all -or -not (SysmonOn))) {
        # Sysmon only from Microsoft over HTTPS, run only when Microsoft signed it
        $t = Join-Path $env:TEMP ('sysmon-' + [guid]::NewGuid())
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            New-Item -ItemType Directory -Path $t | Out-Null
            $sv = Get-CimInstance Win32_Service -Filter "Name='Sysmon64' OR Name='Sysmon64a' OR Name='Sysmon'" | Select-Object -First 1
            if ($sv -and -not $all) {
                # installed but stopped: start it, nothing to download
                Start-Service -Name $sv.Name; Log 'Sysmon started'; $added.Add('Sysmon (started)') | Out-Null
            } else {
            $xml = Join-Path $Kit 'sysmon.xml'
            $want = $deploy.files.'sysmon.xml'
            if ($want -and (Get-FileHash -Algorithm SHA256 -LiteralPath $xml).Hash -ne $want) { throw 'sysmon.xml does not match its SHA-256 in deploy.json' }
            Copy-Item -LiteralPath $xml -Destination "$t\sysmon.xml"
            if ($sv) { $exe = $sv.PathName.Trim('"'); $op = '-c' } else {
                Invoke-WebRequest -UseBasicParsing -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile "$t\Sysmon.zip"
                Expand-Archive -Path "$t\Sysmon.zip" -DestinationPath $t -Force
                $exe = Join-Path $t $(if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'Sysmon64a.exe' } elseif ([Environment]::Is64BitOperatingSystem) { 'Sysmon64.exe' } else { 'Sysmon.exe' }); $op = '-i'
            }
            $sig = Get-AuthenticodeSignature $exe
            if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation,') { throw "$exe is not signed by Microsoft ($($sig.Status))" }
            $ErrorActionPreference = 'Continue'
            & $exe -accepteula $op "$t\sysmon.xml" 2>&1 | Out-Null
            $ErrorActionPreference = 'Stop'
            if ($LASTEXITCODE -ne 0) { throw "Sysmon $op exited with $LASTEXITCODE" }
            Log 'Sysmon installed or updated'; $added.Add('Sysmon') | Out-Null
            }
        } catch { Log "Sysmon not installed: $_" } finally { Remove-Item -Recurse -Force $t -ErrorAction SilentlyContinue }
    }
    return ,$added
}

# already installed, running, enrolled and current: nothing to do (each boot under Group Policy)
$id = Identity
$svc = Get-Service $Service -ErrorAction SilentlyContinue
if (-not $Force -and $id -and $svc -and $svc.Status -eq 'Running' -and (Test-Path "$Dir\provigil-agent.exe") -and
    (Get-FileHash -Algorithm SHA256 -LiteralPath "$Dir\provigil-agent.exe").Hash -eq $agentHash) {
    # the kit may turn on options this PC does not have yet (Sysmon, audit policy, PowerShell logging)
    $added = ApplyOptions $false
    $why = if ($added.Count) { 'added: ' + ($added -join ', ') } else { '' }
    Finish 1 'already installed' $why "$($id.agent_id)" "$($id.agent_name)"
}

foreach ($f in $files) {
    $path = Join-Path $Kit ($f.Name -replace '/', '\')
    if (-not (Test-Path -LiteralPath $path)) { Finish 3 'failed' "kit file missing: $($f.Name)" }
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $f.Value) { Finish 3 'failed' "kit file does not match its SHA-256: $($f.Name)" }
}

# ---------------------------------------------------------------- install
try {
    Log "Installing the ProVigil agent from $Kit"
    if ($svc) { Stop-Service $Service -Force -ErrorAction SilentlyContinue }
    # the agent from before the ProVigil rename is replaced; the PC keeps its name and ID
    if (Get-Service $LegacyService -ErrorAction SilentlyContinue) { Stop-Service $LegacyService -Force -ErrorAction SilentlyContinue; sc.exe delete $LegacyService | Out-Null }
    foreach ($s in @('active-response\bin', 'bookmarks', 'data', 'logs', 'shared', 'upgrade')) { New-Item -ItemType Directory -Force -Path "$Dir\$s" | Out-Null }
    if (-not (Test-Path "$Dir\active-response\active-responses.log")) { New-Item -ItemType File -Path "$Dir\active-response\active-responses.log" | Out-Null }
    foreach ($f in $files) {
        if ($f.Name -notlike 'windows/*') { continue }
        $name = $f.Name.Substring(8)
        $to = if ($name -eq 'provigil-agent.exe') { "$Dir\$name" } else { "$Dir\active-response\bin\$name" }
        Copy-Item -Force -LiteralPath (Join-Path $Kit "windows\$name") -Destination $to
    }

    # the name: kept from an earlier install, else empty and the agent uses the computer name
    $n = ''
    foreach ($k in @("$LegacyDir\client.keys", "$Dir\client.keys")) {
        if (Test-Path $k) { $p = ((Get-Content $k -TotalCount 1) -split ' '); if ($p.Count -ge 4 -and $p[1]) { $n = $p[1] } }
    }
    if ($id -and $id.agent_name) { $n = "$($id.agent_name)" }
    # an enrolled agent's identity and settings, put back when this enrollment is refused: a
    # refused reinstall must not break an agent that works
    $kept = $null
    if (Test-Path $IdFile) {
        $kept = Join-Path $env:TEMP ('provigil-kept-' + [guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $kept | Out-Null
        foreach ($f in @($IdFile, "$Dir\provigil-agent.json", "$Dir\client.keys", "$Dir\data\client.keys")) { if (Test-Path $f) { Copy-Item -LiteralPath $f -Destination (Join-Path $kept ($f.Substring($Dir.Length + 1) -replace '\\', '__')) } }
    }
    # the agent enrolls again, for a new key
    Remove-Item -Force -ErrorAction SilentlyContinue $IdFile, "$Dir\data\force-enroll-used", "$Dir\client.keys", "$Dir\data\client.keys"

    Copy-Item -Force -LiteralPath (Join-Path $Kit 'ca.pem') -Destination "$Dir\ca.pem"
    $cfg = [ordered]@{ manager_url = "$($deploy.manager_url)"; grpc_url = "$($deploy.grpc_url)"; ca_file = "$Dir\ca.pem"; agent_name = $n; tenant_key = "$($deploy.token)"; force_enroll = $true }
    # empty: the deployment token's own group
    if ("$($deploy.groups)") { $cfg['groups'] = "$($deploy.groups)" }
    [IO.File]::WriteAllText("$Dir\provigil-agent.json", ($cfg | ConvertTo-Json))

    # Administrators and SYSTEM full; users read and run, but not the settings with the token
    icacls "$Dir" /reset /t /q | Out-Null
    icacls "$Dir" /inheritancelevel:r /q | Out-Null
    icacls "$Dir" /grant '*S-1-5-32-544:(OI)(CI)F' /q | Out-Null
    icacls "$Dir" /grant '*S-1-5-18:(OI)(CI)F' /q | Out-Null
    icacls "$Dir\*" /grant '*S-1-5-11:(OI)(CI)RX' /q | Out-Null
    icacls "$Dir\*" /grant '*S-1-5-11:RX' /q | Out-Null
    icacls "$Dir" /grant '*S-1-5-11:RX' /q | Out-Null
    icacls "$Dir\provigil-agent.json" /remove '*S-1-5-11' /q | Out-Null

    & "$Dir\provigil-agent.exe" install-service | Out-Null
    Start-Service -Name $Service
} catch { Finish 2 'failed' "install: $_" }

$w = 0
while (-not (Test-Path $IdFile) -and $w -lt 90) { Start-Sleep -Seconds 2; $w += 2 }
if (-not (Test-Path $IdFile)) {
    $why = ''
    $log = "$Dir\logs\provigil-agent.log"
    if (Test-Path $log) { $why = ((Get-Content $log -Tail 3) -join ' / ') }
    if ($kept) {
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        foreach ($f in Get-ChildItem -LiteralPath $kept) { Copy-Item -Force -LiteralPath $f.FullName -Destination (Join-Path $Dir ($f.Name -replace '__', '\')) }
        Remove-Item -Recurse -Force -LiteralPath $kept -ErrorAction SilentlyContinue
        Start-Service $Service -ErrorAction SilentlyContinue
        $why += ' ; the agent already installed here was kept'
    }
    Finish 2 'failed' "the agent did not enroll with $($deploy.manager_url) within 90 s (outbound 8443/8089 open? token valid?) $why"
}
Start-Sleep -Seconds 1
$id = Identity
if ($kept) { Remove-Item -Recurse -Force -LiteralPath $kept -ErrorAction SilentlyContinue }

ApplyOptions $true | Out-Null

Finish 0 'installed' '' "$($id.agent_id)" "$($id.agent_name)"
