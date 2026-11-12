<#
.SYNOPSIS
  ProVigil mass deployment: one run on one PC installs the agent on every PC it can reach.

.DESCRIPTION
  Part of the ProVigil deployment kit (specs/provigil-mass-deploy.md, C5). Read GUIDE.md first.

  Stage 1 (default), as the client administrator's own account, elevated:
    checks the kit and the cloud, asks for the deployment account (and an optional Linux login),
    stores the password once as the Windows auto-login secret, registers stage 2 for that
    account's logon and restarts the PC after a 60-second countdown (C cancels).
  Stage 2 (runs by itself after the restart, as the deployment account):
    first removes the auto-login and its secret, installs the agent here, finds the PCs (Active
    Directory and/or a network scan), installs on Windows PCs (admin share + remote PowerShell,
    a one-time service, or a one-time task) and Linux PCs (SSH), writes results.csv, sends the
    results to the console, shows a summary and logs off.

.PARAMETER NoReboot
  Run stage 2 now in this session (you are logged in as the deployment account already).
.PARAMETER DiscoverOnly
  Only find and list the PCs (discovered.csv); install nothing. A dry run to show first.
.PARAMETER ComputerList
  A text file of computer names or addresses, one per line: only these, no discovery.
.PARAMETER SearchBase
  Active Directory: only computers under this OU ("OU=PCs,DC=corp,DC=local").
.PARAMETER Ranges
  Networks to scan, "10.1.0.0/24,10.2.0.0/23"; default the admin PC's own networks (/22 at most).
.PARAMETER Retry
  Only the PCs that failed or were unreachable in the last run (logs\results.json).
.PARAMETER Local
  Install on this PC only (the same as running install-provigil.ps1).
.PARAMETER LinuxUser
  With -NoReboot or -Retry: the SSH user with sudo for Linux PCs (asks for the password).
.PARAMETER LinuxKey
  With -LinuxUser: an SSH private key file instead of a password.
.PARAMETER Uninstall
  Remove the agent from the listed PCs (-ComputerList needed). Tamper protection: open a
  maintenance window in the console first.
#>
param(
    [ValidateSet(1, 2)][int]$Stage = 1,
    [switch]$NoReboot,
    [switch]$DiscoverOnly,
    [string]$ComputerList,
    [string]$SearchBase,
    [string]$Ranges,
    [ValidateRange(1, 100)][int]$Throttle = 30,
    [switch]$Retry,
    [switch]$Local,
    [switch]$Uninstall,
    [switch]$NoScan,
    [switch]$NoAD,
    [string]$LinuxUser,
    [string]$LinuxKey
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$Home_ = Join-Path $env:ProgramData 'ProVigilDeploy'
$TaskName = 'ProVigil Deploy Stage 2'
$Winlogon = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
$Kit = $PSScriptRoot
$Logs = Join-Path $Kit 'logs'

# ---------------------------------------------------------------- helpers

function Say([string]$m, [string]$color = 'Gray') {
    Write-Host $m -ForegroundColor $color
    try { New-Item -ItemType Directory -Force -Path $Logs | Out-Null; Add-Content -LiteralPath (Join-Path $Logs 'deploy.log') -Value "$(Get-Date -Format s) $m" } catch { }
}

function Stop-Run([string]$m) {
    Say "STOPPED: $m" 'Red'
    exit 1
}

# The Windows auto-login secret (LSA private data "DefaultPassword"), as Windows' own auto-login
# tool stores it: never the plain-text registry value.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class PvLsa {
    [StructLayout(LayoutKind.Sequential)] struct US { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
    [StructLayout(LayoutKind.Sequential)] struct OA { public int Length; public IntPtr RootDirectory; public IntPtr ObjectName; public uint Attributes; public IntPtr SecurityDescriptor; public IntPtr SecurityQualityOfService; }
    [DllImport("advapi32.dll")] static extern uint LsaOpenPolicy(IntPtr system, ref OA attrs, uint access, out IntPtr handle);
    [DllImport("advapi32.dll")] static extern uint LsaStorePrivateData(IntPtr policy, ref US key, IntPtr data);
    [DllImport("advapi32.dll")] static extern uint LsaRetrievePrivateData(IntPtr policy, ref US key, out IntPtr data);
    [DllImport("advapi32.dll")] static extern uint LsaClose(IntPtr handle);
    [DllImport("advapi32.dll")] static extern uint LsaFreeMemory(IntPtr p);
    [DllImport("advapi32.dll")] static extern int LsaNtStatusToWinError(uint status);
    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)] static extern bool LogonUser(string user, string domain, string password, int type, int provider, out IntPtr token);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);

    static US Str(string s, out IntPtr mem) {
        US u = new US(); mem = Marshal.StringToHGlobalUni(s);
        u.Buffer = mem; u.Length = (ushort)(s.Length * 2); u.MaximumLength = (ushort)(s.Length * 2 + 2); return u;
    }
    static IntPtr Open() {
        OA oa = new OA(); IntPtr h;
        uint st = LsaOpenPolicy(IntPtr.Zero, ref oa, 0x000F0FFF /* POLICY_ALL_ACCESS: create and read secrets */, out h);
        if (st != 0) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
        return h;
    }
    /// value null: removes the secret
    public static void Store(string name, string value) {
        IntPtr h = Open(), km, vm = IntPtr.Zero;
        try {
            US k = Str(name, out km);
            IntPtr pv = IntPtr.Zero;
            if (value != null) { US v = Str(value, out vm); pv = Marshal.AllocHGlobal(Marshal.SizeOf(v)); Marshal.StructureToPtr(v, pv, false); }
            uint st = LsaStorePrivateData(h, ref k, pv);
            if (pv != IntPtr.Zero) Marshal.FreeHGlobal(pv);
            Marshal.FreeHGlobal(km);
            if (vm != IntPtr.Zero) { Marshal.FreeHGlobal(vm); }
            if (st != 0 && !(value == null && st == 0xC0000034 /* not found */)) throw new System.ComponentModel.Win32Exception(LsaNtStatusToWinError(st));
        } finally { LsaClose(h); }
    }
    public static bool Exists(string name) {
        IntPtr h = Open(), km, data;
        try {
            US k = Str(name, out km);
            uint st = LsaRetrievePrivateData(h, ref k, out data);
            Marshal.FreeHGlobal(km);
            if (st == 0 && data != IntPtr.Zero) { LsaFreeMemory(data); return true; }
            return false;
        } finally { LsaClose(h); }
    }
    /// interactive logon test of an account (does not keep the session)
    public static int TestLogon(string user, string domain, string password) {
        IntPtr t;
        if (LogonUser(user, domain, password, 2, 0, out t)) { CloseHandle(t); return 0; }
        return Marshal.GetLastWin32Error();
    }
}
'@

function Is-Admin {
    ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Read-Deploy {
    try { Get-Content -Raw -LiteralPath (Join-Path $Kit 'deploy.json') | ConvertFrom-Json } catch { Stop-Run "deploy.json not readable in $Kit" }
}

function Test-Kit($deploy) {
    foreach ($p in $deploy.files.PSObject.Properties) {
        $path = Join-Path $Kit ($p.Name -replace '/', '\')
        if (-not (Test-Path -LiteralPath $path)) { Stop-Run "kit file missing: $($p.Name). Download the kit again." }
        if ((Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash -ne $p.Value) { Stop-Run "kit file changed or damaged: $($p.Name). Download the kit again." }
    }
}

function Invoke-Helper([string[]]$a) {
    $out = & (Join-Path $Kit 'provigil-deploy.exe') @a 2>&1 | Out-String
    try { ($out.Trim() -split "`n")[-1] | ConvertFrom-Json } catch { [pscustomobject]@{ status = 'error'; message = $out.Trim() } }
}

# Removes every trace of the auto-login and stage 2 task. Run first in stage 2 and on cancel.
function Remove-AutoLogon {
    foreach ($v in 'AutoAdminLogon', 'AutoLogonCount', 'DefaultPassword') {
        Remove-ItemProperty -Path $Winlogon -Name $v -ErrorAction SilentlyContinue
    }
    Set-ItemProperty -Path $Winlogon -Name AutoAdminLogon -Value '0'
    try { [PvLsa]::Store('DefaultPassword', $null) } catch { Say "auto-login secret: $_" 'Yellow' }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $left = @()
    if ((Get-ItemProperty -Path $Winlogon -ErrorAction SilentlyContinue).AutoAdminLogon -eq '1') { $left += 'AutoAdminLogon' }
    if ([PvLsa]::Exists('DefaultPassword')) { $left += 'auto-login secret' }
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $left += 'stage 2 task' }
    if ($left) { Say "WARNING: could not remove: $($left -join ', ')" 'Red' } else { Say 'Auto-login and its secret removed; stage 2 task removed.' 'Green' }
}

# ---------------------------------------------------------------- discovery

# IPv4 addresses of a CIDR range (at most a /16).
function Expand-Cidr([string]$cidr) {
    $ip, $bits = $cidr.Trim() -split '/'
    $bits = if ($bits) { [int]$bits } else { 32 }
    if ($bits -lt 16 -or $bits -gt 32) { throw "range $cidr : use /16 to /32" }
    $b = ([Net.IPAddress]::Parse($ip)).GetAddressBytes(); [Array]::Reverse($b)
    $n = [BitConverter]::ToUInt32($b, 0)
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $bits))
    $net = [uint32]($n -band $mask)
    $count = [uint32]([math]::Pow(2, 32 - $bits))
    $first, $last = if ($bits -ge 31) { 0, ($count - 1) } else { 1, ($count - 2) }
    for ($i = $first; $i -le $last; $i++) {
        $x = [BitConverter]::GetBytes([uint32]($net + $i)); [Array]::Reverse($x)
        ([Net.IPAddress]$x).ToString()
    }
}

# This PC's own networks, each at most a /22 around its address.
function Get-LocalRanges {
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '169.254.*' -and $_.PrefixOrigin -ne 'WellKnown' -and $_.InterfaceAlias -notmatch 'vEthernet|WSL|Docker|VirtualBox|VMware|Loopback' } |
        ForEach-Object { "$($_.IPAddress)/$([math]::Max([int]$_.PrefixLength, 22))" }
}

function Get-ADComputers {
    $f = '(&(objectCategory=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))'
    $s = if ($SearchBase) { New-Object DirectoryServices.DirectorySearcher([adsi]"LDAP://$SearchBase", $f) } else { New-Object DirectoryServices.DirectorySearcher($f) }
    $s.PageSize = 500
    foreach ($p in 'name', 'dnshostname', 'operatingsystem', 'lastlogontimestamp') { [void]$s.PropertiesToLoad.Add($p) }
    foreach ($r in $s.FindAll()) {
        $last = if ($r.Properties['lastlogontimestamp'].Count) { [DateTime]::FromFileTime([int64]$r.Properties['lastlogontimestamp'][0]) } else { $null }
        [pscustomobject]@{
            name  = "$($r.Properties['name'][0])"
            dns   = "$($r.Properties['dnshostname'][0])"
            os    = "$($r.Properties['operatingsystem'][0])"
            stale = ($null -eq $last -or $last -lt (Get-Date).AddDays(-90))
        }
    }
}

# Probes many addresses in parallel: ping TTL, ports 445 / 5985 / 22, the SSH greeting.
$Probe = {
    param($addr)
    $r = [ordered]@{ address = $addr; ttl = 0; p445 = $false; p5985 = $false; p22 = $false; ssh = '' }
    try { $p = (New-Object Net.NetworkInformation.Ping).Send($addr, 700); if ($p.Status -eq 'Success') { $r.ttl = $p.Options.Ttl } } catch { }
    foreach ($port in 445, 5985, 22) {
        $c = New-Object Net.Sockets.TcpClient
        try {
            if ($c.ConnectAsync($addr, $port).Wait(700) -and $c.Connected) {
                $r["p$port"] = $true
                if ($port -eq 22) {
                    $s = $c.GetStream(); $s.ReadTimeout = 1500
                    $buf = New-Object byte[] 256; $n = $s.Read($buf, 0, 256)
                    $r.ssh = ([Text.Encoding]::ASCII.GetString($buf, 0, $n)).Trim()
                }
            }
        } catch { } finally { $c.Dispose() }
    }
    [pscustomobject]$r
}

function Invoke-Parallel([scriptblock]$block, $items, [int]$n, [string]$what) {
    $pool = [RunspaceFactory]::CreateRunspacePool(1, $n); $pool.Open()
    $jobs = foreach ($i in $items) { $ps = [PowerShell]::Create().AddScript($block).AddArgument($i); $ps.RunspacePool = $pool; @{ ps = $ps; h = $ps.BeginInvoke() } }
    $out = @(); $done = 0; $total = @($jobs).Count
    foreach ($j in $jobs) {
        $out += $j.ps.EndInvoke($j.h); $j.ps.Dispose(); $done++
        Write-Progress -Activity $what -Status "$done of $total" -PercentComplete ([int](100 * $done / [math]::Max($total, 1)))
    }
    Write-Progress -Activity $what -Completed
    $pool.Close(); $out
}

function Find-Targets($run) {
    $byAddr = @{}
    $self = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object IPAddress)
    $named = @()
    if ($ComputerList) {
        $named = Get-Content -LiteralPath $ComputerList | ForEach-Object { $_.Trim() } | Where-Object { $_ -and -not $_.StartsWith('#') } | ForEach-Object { [pscustomobject]@{ name = $_; dns = $_; os = ''; stale = $false } }
    } elseif ($Retry) {
        $last = Get-Content -Raw (Join-Path $Logs 'results.json') | ConvertFrom-Json
        $named = $last | Where-Object { $_.outcome -in 'failed', 'access denied', 'unreachable' } | ForEach-Object { [pscustomobject]@{ name = $(if ($_.computer) { $_.computer } else { $_.address }); dns = $(if ($_.address) { $_.address } else { $_.computer }); os = $_.os; stale = $false } }
    } else {
        if ($run.ad) {
            Say 'Reading the computers from Active Directory...'
            $named = @(Get-ADComputers)
            Say "  $($named.Count) enabled computer accounts ($(@($named | Where-Object stale).Count) not seen for 90 days)"
        }
    }
    # names to addresses
    foreach ($c in $named) {
        $ip = $null
        if ($c.dns -match '^\d+\.\d+\.\d+\.\d+$') { $ip = $c.dns } else {
            try { $ip = ([Net.Dns]::GetHostAddresses($(if ($c.dns) { $c.dns } else { $c.name })) | Where-Object AddressFamily -eq 'InterNetwork' | Select-Object -First 1).IPAddressToString } catch { }
        }
        $key = if ($ip) { $ip } else { "name:$($c.name)" }
        $byAddr[$key] = [pscustomobject]@{ computer = $c.name; address = $ip; adOs = $c.os; stale = $c.stale }
    }
    $scan = @($byAddr.Keys | Where-Object { $_ -notlike 'name:*' })
    if ($run.ranges -and -not $ComputerList -and -not $Retry) {
        foreach ($r in $run.ranges) { $scan += @(Expand-Cidr $r) }
        Say "Scanning $(@($scan | Select-Object -Unique).Count) addresses (ping, ports 445, 5985, 22)..."
    }
    $scan = @($scan | Select-Object -Unique | Where-Object { $_ -notin $self })
    $probed = @{}
    foreach ($p in (Invoke-Parallel $Probe $scan 64 'Finding PCs')) { $probed[$p.address] = $p }

    $targets = foreach ($key in (@($byAddr.Keys) + @($probed.Keys) | Select-Object -Unique)) {
        $k = $byAddr[$key]; $p = $probed[$key]
        if ($k -and ($k.computer -in $env:COMPUTERNAME)) { continue }
        $ssh = if ($p) { $p.ssh } else { '' }
        $kind =
            if ($p -and ($p.p445 -or $p.p5985)) { 'windows' }
            elseif ($p -and $p.p22 -and $ssh -notmatch 'Windows') { 'linux' }
            elseif ($k -and $k.adOs -like 'Windows*') { 'windows' }
            elseif ($k) { 'unknown' }
            else { 'none' }
        $os = if ($k -and $k.adOs) { $k.adOs } elseif ($kind -eq 'linux') { ($ssh -replace '^SSH-2\.0-', '') } elseif ($p -and $p.ttl -gt 64 -and $p.ttl -le 128) { 'Windows (guess)' } else { '' }
        # an address that only answers ping, or not at all, and is not a known computer: not a PC
        if ($kind -eq 'none' -and -not $p.ttl) { continue }
        [pscustomobject]@{
            computer = $(if ($k) { $k.computer } else { '' })
            address  = $(if ($k -and $k.address) { $k.address } elseif ($key -notlike 'name:*') { $key } else { '' })
            kind     = $kind; os = $os
            p445     = [bool]($p -and $p.p445); p5985 = [bool]($p -and $p.p5985); p22 = [bool]($p -and $p.p22)
            stale    = [bool]($k -and $k.stale)
        }
    }
    @($targets)
}

# ---------------------------------------------------------------- push to one Windows PC (in a runspace)

$PushWindows = {
    param($job)
    $t = $job.target; $kit = $job.kit
    $host_ = if ($t.computer) { $t.computer } else { $t.address }
    $row = [ordered]@{ computer = $t.computer; address = $t.address; os = $t.os; os_version = ''; method = ''; outcome = 'failed'; reason = ''; agent_id = '' }
    if (-not $t.address -and -not $t.p445) { $row.outcome = 'unreachable'; $row.reason = 'the name is not in DNS (computer account without a current address)'; return [pscustomobject]$row }
    if (-not $t.p445 -and -not $t.p5985) { $row.outcome = 'unreachable'; $row.reason = 'ports 445 and 5985 closed: PC off, or firewall (allow File and Printer Sharing or WinRM from this PC)'; return [pscustomobject]$row }
    $tag = 'ProVigil-' + ([guid]::NewGuid().ToString('N').Substring(0, 8))
    $share = "\\$host_\admin$\Temp\$tag"
    $local = "C:\Windows\Temp\$tag"
    $cmd = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File $local\install-provigil.ps1"
    if ($job.uninstall) { $cmd += ' -Uninstall' }
    try {
        try { New-Item -ItemType Directory -Path "$share\windows" -Force | Out-Null }
        catch {
            $m = "$($_.Exception.Message)"
            if ($m -match 'denied') { $row.outcome = 'access denied'; $row.reason = 'admin share refused: the deployment account is not an administrator on this PC (workgroup: same local admin + LocalAccountTokenFilterPolicy = 1)' }
            else { $row.outcome = 'unreachable'; $row.reason = "admin share not reachable: $m" }
            return [pscustomobject]$row
        }
        foreach ($f in $job.files) { Copy-Item -LiteralPath (Join-Path $kit $f) -Destination (Join-Path $share $f) -Force }

        $ran = $false; $why = @()
        if ($t.p5985) {
            try {
                Invoke-Command -ComputerName $host_ -ScriptBlock { param($c) cmd.exe /c $c | Out-Null } -ArgumentList $cmd -ErrorAction Stop
                $row.method = 'winrm'; $ran = $true
            } catch { $why += "WinRM: $($_.Exception.Message)" }
        }
        if (-not $ran -and $t.p445) {
            # a one-time service that starts the script, then is deleted (needs only file sharing)
            $svc = $tag
            $o = & sc.exe "\\$host_" create $svc binPath= "cmd.exe /c start /b $cmd" type= own start= demand 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) {
                & sc.exe "\\$host_" start $svc 2>&1 | Out-Null
                $row.method = 'service'; $ran = $true
            } else { $why += "service: $($o.Trim())" }
        }
        if (-not $ran) {
            $o = & schtasks.exe /Create /S $host_ /RU SYSTEM /SC ONCE /ST 00:00 /F /TN $tag /TR $cmd 2>&1 | Out-String
            if ($LASTEXITCODE -eq 0) { & schtasks.exe /Run /S $host_ /TN $tag 2>&1 | Out-Null; $row.method = 'task'; $ran = $true }
            else { $why += "task: $($o.Trim())" }
        }
        if (-not $ran) {
            $row.outcome = if (($why -join ' ') -match 'denied') { 'access denied' } else { 'failed' }
            $row.reason = "could not start the install: $($why -join ' | ')"
            return [pscustomobject]$row
        }
        # the result the script writes next to itself
        $deadline = (Get-Date).AddMinutes(10)
        while (-not (Test-Path "$share\result.json") -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 3 }
        if (Test-Path "$share\result.json") {
            Start-Sleep -Milliseconds 500
            $r = Get-Content -Raw "$share\result.json" | ConvertFrom-Json
            foreach ($k in 'outcome', 'reason', 'agent_id', 'os', 'os_version') { if ($r.$k) { $row[$k] = "$($r.$k)" } }
            if (-not $row.computer) { $row.computer = "$($r.computer)" }
            if ($r.outcome -eq '') { $row.outcome = 'failed' }
        } else { $row.reason = 'no result within 10 minutes (install still running, or blocked by endpoint security)' }
    } catch { $row.reason = "$($_.Exception.Message)" }
    finally {
        if ($row.method -eq 'service') { & sc.exe "\\$host_" delete $tag 2>&1 | Out-Null }
        if ($row.method -eq 'task') { & schtasks.exe /Delete /S $host_ /TN $tag /F 2>&1 | Out-Null }
        Remove-Item -Recurse -Force -LiteralPath $share -ErrorAction SilentlyContinue
    }
    [pscustomobject]$row
}

$PushLinux = {
    param($job)
    $t = $job.target
    $a = @('push-linux', '--host', $t.address, '--user', $job.user, '--kit', $job.kit)
    if ($job.key) { $a += @('--key', $job.key) }
    $out = & (Join-Path $job.kit 'provigil-deploy.exe') @a 2>&1 | Out-String
    try { $r = ($out.Trim() -split "`n")[-1] | ConvertFrom-Json } catch { $r = [pscustomobject]@{ outcome = 'failed'; reason = $out.Trim() } }
    [pscustomobject][ordered]@{ computer = $(if ($r.computer) { "$($r.computer)" } else { $t.computer }); address = $t.address; os = $(if ($r.os) { "$($r.os)" } else { $t.os }); os_version = ''; method = 'ssh'; outcome = "$($r.outcome)"; reason = "$($r.reason)"; agent_id = "$($r.agent_id)" }
}

# ---------------------------------------------------------------- stage 2

function Start-Stage2 {
    $fromLogon = -not $NoReboot -and (Test-Path (Join-Path $Kit 'run.json'))
    if (-not $DiscoverOnly -and -not (Is-Admin)) { Stop-Run 'Stage 2 needs administrator rights: the deployment account must be an administrator on this PC.' }
    Say "== ProVigil deployment, stage 2 on $env:COMPUTERNAME as $env:USERDOMAIN\$env:USERNAME ==" 'Cyan'
    # first, whenever stage 1 set it up: no auto-login may stay behind. A run by hand leaves the
    # PC's own auto-login settings alone.
    if ($Stage -eq 2 -or (Test-Path (Join-Path $Kit 'run.json')) -or (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { Remove-AutoLogon }
    $deploy = Read-Deploy
    $run = if (Test-Path (Join-Path $Kit 'run.json')) { Get-Content -Raw (Join-Path $Kit 'run.json') | ConvertFrom-Json } else {
        [pscustomobject]@{ ad = (-not $NoAD -and (Get-CimInstance Win32_ComputerSystem).PartOfDomain); ranges = @($(if ($NoScan) { @() } elseif ($Ranges) { $Ranges -split ',' } else { Get-LocalRanges })); linux_user = $LinuxUser; linux_key = $LinuxKey; throttle = $Throttle }
    }
    $linuxPassword = ''
    $secret = Join-Path $Kit 'linux.bin'
    if ($LinuxUser -and -not $fromLogon) {
        $lp = Read-Host -AsSecureString $(if ($LinuxKey) { 'Key passphrase / sudo password (Enter = none)' } else { "SSH and sudo password of $LinuxUser" })
        $linuxPassword = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($lp))
    }
    if (Test-Path $secret) {
        Add-Type -AssemblyName System.Security
        $linuxPassword = [Text.Encoding]::UTF8.GetString([Security.Cryptography.ProtectedData]::Unprotect([IO.File]::ReadAllBytes($secret), $null, 'LocalMachine'))
    }
    try {
        $results = @()
        if (-not $DiscoverOnly -and -not $Uninstall -and -not $Retry) {
            Say 'Installing the agent on this PC...'
            $line = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Kit 'install-provigil.ps1') | Where-Object { $_ -like 'PROVIGIL_RESULT *' } | Select-Object -Last 1
            $me = if ($line) { $line.Substring(16) | ConvertFrom-Json } else { [pscustomobject]@{ outcome = 'failed'; reason = 'no result from install-provigil.ps1'; agent_id = ''; os = '' } }
            $results += [pscustomobject][ordered]@{ computer = $env:COMPUTERNAME; address = ''; os = "$($me.os)"; os_version = "$($me.os_version)"; method = 'local'; outcome = "$($me.outcome)"; reason = "$($me.reason)"; agent_id = "$($me.agent_id)" }
            Say "  this PC: $($me.outcome) $($me.reason)"
        }

        $targets = Find-Targets $run
        $win = @($targets | Where-Object { $_.kind -in 'windows', 'unknown' })
        $lin = @($targets | Where-Object kind -eq 'linux')
        Say "Found $($win.Count + $lin.Count) PCs: $($win.Count) Windows (or unknown), $($lin.Count) Linux; $(@($targets | Where-Object kind -eq 'none').Count) other devices (not PCs)." 'Cyan'
        if ($DiscoverOnly) {
            $targets | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Logs 'discovered.csv')
            $targets | Format-Table computer, address, kind, os, p445, p5985, p22, stale -AutoSize | Out-String | Write-Host
            Say "List written to $(Join-Path $Logs 'discovered.csv'). Nothing was installed." 'Green'
            return
        }

        $files = @('install-provigil.ps1', 'deploy.json', 'ca.pem') + @($deploy.files.PSObject.Properties.Name | Where-Object { $_ -like 'windows/*' } | ForEach-Object { $_ -replace '/', '\' })
        if (Test-Path (Join-Path $Kit 'sysmon.xml')) { $files += 'sysmon.xml' }
        $jobs = @($win | ForEach-Object { @{ target = $_; kit = $Kit; files = $files; uninstall = [bool]$Uninstall } })
        if ($jobs) {
            Say "Installing on $($jobs.Count) Windows PCs, $($run.throttle) at a time..."
            $results += Invoke-Parallel $PushWindows $jobs $run.throttle 'Windows PCs'
        }
        if ($lin -and -not $Uninstall) {
            if (-not $run.linux_user) {
                $results += $lin | ForEach-Object { [pscustomobject][ordered]@{ computer = $_.computer; address = $_.address; os = $_.os; os_version = ''; method = 'ssh'; outcome = 'skipped'; reason = 'no Linux login given'; agent_id = '' } }
            } else {
                Say "Installing on $($lin.Count) Linux PCs over SSH..."
                $env:PROVIGIL_SSH_PASSWORD = $linuxPassword
                $ljobs = @($lin | ForEach-Object { @{ target = $_; kit = $Kit; user = $run.linux_user; key = $run.linux_key } })
                $results += Invoke-Parallel $PushLinux $ljobs $run.throttle 'Linux PCs'
                Remove-Item Env:\PROVIGIL_SSH_PASSWORD -ErrorAction SilentlyContinue
            }
        }
        $results += $targets | Where-Object kind -eq 'none' | ForEach-Object { [pscustomobject][ordered]@{ computer = ''; address = $_.address; os = $_.os; os_version = ''; method = ''; outcome = 'not a PC'; reason = 'answers ping only (printer, phone, network device?)'; agent_id = '' } }

        # ---- results
        $stamp = Get-Date -Format 'yyyyMMdd-HHmm'
        $results = @($results | ForEach-Object { $_ | Add-Member -NotePropertyName time -NotePropertyValue (Get-Date -Format s) -PassThru -Force })
        $results | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Logs "results-$stamp.csv")
        $results | Export-Csv -NoTypeInformation -Encoding UTF8 (Join-Path $Logs 'results.csv')
        [IO.File]::WriteAllText((Join-Path $Logs 'results.json'), (ConvertTo-Json -InputObject @($results) -Depth 3))
        $sent = Invoke-Helper @('report', '--kit', $Kit, '--file', (Join-Path $Logs 'results.json'), '--from', $env:COMPUTERNAME)
        if ($sent.status -ne 'ok') { Say "Results not sent to the console: $($sent.message). They are in $Logs\results.csv" 'Yellow' }

        $count = { param($o) @($results | Where-Object outcome -eq $o).Count }
        $summary = "Installed: $(& $count 'installed')`nAlready installed: $(& $count 'already installed')`nFailed: $(& $count 'failed')`nAccess denied: $(& $count 'access denied')`nUnreachable: $(& $count 'unreachable')`nSkipped / not a PC / not supported: $((& $count 'skipped') + (& $count 'not a PC') + (& $count 'not supported'))`n`nDetails: $Logs\results.csv`nThe same list is in the console (Agent Deployment).`nFailed and unreachable PCs: fix the reason, then run deploy-provigil.ps1 -NoReboot -Retry"
        Say $summary 'Green'
    } finally {
        $linuxPassword = $null
        Remove-Item -Force -ErrorAction SilentlyContinue $secret, (Join-Path $Kit 'run.json')
    }
    if ($fromLogon) {
        try { [void](New-Object -ComObject WScript.Shell).Popup($summary, 120, 'ProVigil deployment finished', 64) } catch { }
        Say 'Logging off.'
        & shutdown.exe /l
    }
}

# ---------------------------------------------------------------- stage 1

function Start-Stage1 {
    if (-not (Is-Admin)) { Stop-Run 'Run this from PowerShell opened with "Run as administrator".' }
    if ($PSVersionTable.PSVersion.Major -lt 5) { Stop-Run 'Windows PowerShell 5.1 or newer is needed.' }
    Say '== ProVigil deployment, stage 1 ==' 'Cyan'
    $deploy = Read-Deploy
    Test-Kit $deploy
    Say 'Kit files checked.' 'Green'
    $c = Invoke-Helper @('report', '--kit', $Kit)
    if ($c.status -ne 'ok') { Stop-Run "The ProVigil cloud is not reachable or the token was refused: $($c.message)" }
    Say "Cloud reachable at $($deploy.manager_url); deployment token accepted." 'Green'

    $domain = (Get-CimInstance Win32_ComputerSystem).PartOfDomain
    $cred = Get-Credential -Message 'The deployment account the client created for ProVigil (administrator on all PCs). DOMAIN\name or name.'
    if (-not $cred) { Stop-Run 'No deployment account given.' }
    $user = $cred.UserName; $dom = '.'
    if ($user -match '^(.+)\\(.+)$') { $dom = $Matches[1]; $user = $Matches[2] } elseif ($user -match '@') { $dom = '' }
    # a UPN (name@domain) logs on with no domain: null, which PowerShell would turn into ''
    $err = [PvLsa]::TestLogon($user, $(if ($dom) { $dom } else { [NullString]::Value }), $cred.GetNetworkCredential().Password)
    if ($err -ne 0) { Stop-Run "The deployment account could not log on here (Windows error $err): check the name and password, and that it may log on to this PC." }
    Say "Deployment account $($cred.UserName) checked." 'Green'

    $ranges = @()
    if (-not $NoScan) {
        $ranges = if ($Ranges) { $Ranges -split ',' } else { @(Get-LocalRanges) }
        $ans = Read-Host "Networks to scan [$($ranges -join ', ')] (Enter = these, or type others, or 'none')"
        if ($ans -eq 'none') { $ranges = @() } elseif ($ans) { $ranges = $ans -split ',' }
        foreach ($r in $ranges) { try { $null = @(Expand-Cidr $r | Select-Object -First 1) } catch { Stop-Run "$_" } }
    }
    $lu = Read-Host 'Linux PCs: SSH user with sudo (Enter = no Linux installs)'
    $lk = ''; $lp = $null
    if ($lu) {
        $lk = Read-Host 'SSH key file (Enter = use a password)'
        if ($lk -and -not (Test-Path -LiteralPath $lk)) { Stop-Run "key file not found: $lk" }
        $lp = Read-Host -AsSecureString $(if ($lk) { 'Key passphrase / sudo password (Enter = none)' } else { 'SSH and sudo password' })
    }
    $go = Read-Host "This PC will restart and log on as $($cred.UserName), then install on every PC found. Type YES to continue"
    if ($go -ne 'YES') { Stop-Run 'Cancelled; nothing was changed.' }

    # the kit where only Administrators and SYSTEM can read it
    if ($Kit -ne $Home_) {
        New-Item -ItemType Directory -Force -Path $Home_ | Out-Null
        & icacls $Home_ /inheritance:r /grant:r '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-18:(OI)(CI)F' /q | Out-Null
        Copy-Item -Recurse -Force -Path (Join-Path $Kit '*') -Destination $Home_ -Exclude 'logs', 'run.json', 'linux.bin'
    }
    $run = [ordered]@{ ad = ($domain -and -not $NoAD); ranges = @($ranges); linux_user = $lu; linux_key = $lk; throttle = $Throttle }
    [IO.File]::WriteAllText((Join-Path $Home_ 'run.json'), ($run | ConvertTo-Json))
    if ($lp -and $lp.Length) {
        Add-Type -AssemblyName System.Security
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR([Runtime.InteropServices.Marshal]::SecureStringToBSTR($lp))
        [IO.File]::WriteAllBytes((Join-Path $Home_ 'linux.bin'), [Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::UTF8.GetBytes($plain), $null, 'LocalMachine'))
        $plain = $null
    }

    # one-time automatic logon; the password only as the LSA secret
    Set-ItemProperty -Path $Winlogon -Name AutoAdminLogon -Value '1'
    Set-ItemProperty -Path $Winlogon -Name DefaultUserName -Value $user
    Set-ItemProperty -Path $Winlogon -Name DefaultDomainName -Value $(if ($dom -eq '.') { $env:COMPUTERNAME } else { $dom })
    Set-ItemProperty -Path $Winlogon -Name AutoLogonCount -Value 1 -Type DWord
    Remove-ItemProperty -Path $Winlogon -Name DefaultPassword -ErrorAction SilentlyContinue
    [PvLsa]::Store('DefaultPassword', $cred.GetNetworkCredential().Password)

    $who = if ($dom -eq '.') { "$env:COMPUTERNAME\$user" } elseif ($dom) { "$dom\$user" } else { $cred.UserName }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Normal -File `"$Home_\deploy-provigil.ps1`" -Stage 2"
    $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Highest
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger (New-ScheduledTaskTrigger -AtLogOn -User $who) -Principal $principal -Settings (New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -ExecutionTimeLimit (New-TimeSpan -Hours 12)) -Force | Out-Null
    Say "Auto-login and stage 2 set for $who." 'Green'

    Say 'Restarting in 60 seconds. Press C to cancel (removes everything this script set).' 'Yellow'
    for ($i = 60; $i -gt 0; $i--) {
        Write-Host -NoNewline "`r  $i s "
        if ([Console]::KeyAvailable -and [Console]::ReadKey($true).Key -eq 'C') {
            Write-Host ''
            Remove-AutoLogon
            Remove-Item -Force -ErrorAction SilentlyContinue (Join-Path $Home_ 'run.json'), (Join-Path $Home_ 'linux.bin')
            Stop-Run 'Cancelled by the administrator.'
        }
        Start-Sleep -Seconds 1
    }
    Restart-Computer -Force
}

# ---------------------------------------------------------------- main

New-Item -ItemType Directory -Force -Path $Logs | Out-Null
if ($Local) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File (Join-Path $Kit 'install-provigil.ps1')
    exit $LASTEXITCODE
}
if ($Uninstall -and -not $ComputerList) { Stop-Run '-Uninstall needs -ComputerList (the PCs to remove the agent from).' }
if ($Stage -eq 2 -or $NoReboot -or $DiscoverOnly -or $Retry -or $Uninstall) { Start-Stage2 } else { Start-Stage1 }
