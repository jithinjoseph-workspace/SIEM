<#
.SYNOPSIS
  Builds ProVigil-Setup-<version>.msi: the Windows master (specs/provigil-packages.md).

.DESCRIPTION
  1. The programs (release build in target\msi, ProVigil's public licence key built in, so the
     dev build in target\release is not touched).
  2. The console (ng build, production).
  3. Caddy, the console's web server: a pinned release, checked against its published SHA-512.
  4. The stage folder: bin, console, ruleset (the default ruleset siem-api installs), top
     (Caddyfile, routes.caddy, VERSION), data (the repository's data files and the agent package).
  5. The MSI (WiX 5, a local tool: dotnet tool restore), then its .sig with provigil-license sign
     when -Key is given (the same signature the Linux installer checks).

  .\build-msi.ps1 -PublicKey public.pem [-Key private.pem] [-Version 1.2.3] [-SkipBuild] [-SkipConsole]
#>
param(
    [Parameter(Mandatory = $true)][string]$PublicKey,
    [string]$Key,
    [string]$Version,
    [switch]$SkipBuild,
    [switch]$SkipConsole
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Say($m) { Write-Host "[msi] $m" }
function Need($ok, $m) { if (-not $ok) { throw $m } }
# a program's own output on stderr (cargo, npm, dotnet progress) is not a failure; its exit code is
function Run($what, [scriptblock]$cmd) {
    $old = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { & $cmd 2>&1 | ForEach-Object { "$_" } | Out-Host; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $old }
    Need ($code -eq 0) "$what failed (exit $code)"
}

$Here = $PSScriptRoot
$Backend = (Resolve-Path "$Here\..\..").Path
$Ui = (Resolve-Path "$Backend\..\ndr-ui").Path
$Repo = (Resolve-Path "$Backend\..\..").Path
$CaddyVersion = '2.8.4'
if (-not $Version) { $Version = (Get-Content "$Repo\ndr\VERSION" -Raw).Trim() }
Need ($Version -match '^\d+\.\d+\.\d+$') "Version must be X.Y.Z (MSI versions), got '$Version'"
Need (Test-Path $PublicKey) "-PublicKey: ProVigil's public licence key (PEM)"
$Target = "$Backend\target\msi"
$Stage = "$Here\stage"
$Out = "$Here\out"

# 1. programs
$Server = 'auth-service', 'siem-api', 'provigil-gateway', 'provigil-db', 'provigil-analysisd', 'provigil-modulesd', 'provigil-service'
$Agent = 'provigil-agent', 'netsh', 'restart-agent', 'route-null', 'kill-process', 'quarantine-file', 'isolate-host', 'yara-scan', 'live-response', 'tamper-protect'
if (-not $SkipBuild) {
    Say "building the programs (target\msi)..."
    $env:CARGO_TARGET_DIR = $Target
    $env:PROVIGIL_LICENSE_PUBLIC_KEY = (Get-Content $PublicKey -Raw)
    Push-Location $Backend
    try {
        Run "cargo build" { cargo build --release -j 2 -p auth-service -p siem-api -p provigil-gateway -p provigil-agentdb -p provigil-analysisd -p provigil-modulesd -p provigil-service -p provigil-agent -p siem-active-response }
    } finally { Pop-Location; Remove-Item Env:CARGO_TARGET_DIR, Env:PROVIGIL_LICENSE_PUBLIC_KEY -ErrorAction SilentlyContinue }
}
foreach ($p in $Server + $Agent) { Need (Test-Path "$Target\release\$p.exe") "$p.exe was not built ($Target\release)" }

# 2. console
if (-not $SkipConsole) {
    Say "building the console..."
    Push-Location $Ui
    try { Run "ng build" { npx ng build --configuration production } } finally { Pop-Location }
}
$ConsoleOut = "$Ui\dist\ndr-ui\browser"
Need (Test-Path "$ConsoleOut\index.html") "the console is not built ($ConsoleOut)"

# 3. Caddy, checked
$CaddyDir = "$Here\.cache\caddy-$CaddyVersion"
if (-not (Test-Path "$CaddyDir\caddy.exe")) {
    New-Item -ItemType Directory -Force $CaddyDir | Out-Null
    $zip = "$CaddyDir\caddy.zip"; $base = "https://github.com/caddyserver/caddy/releases/download/v$CaddyVersion"
    Invoke-WebRequest -UseBasicParsing "$base/caddy_${CaddyVersion}_windows_amd64.zip" -OutFile $zip
    # saved and read as text (PowerShell 5.1 hands a binary-typed download back as bytes)
    Invoke-WebRequest -UseBasicParsing "$base/caddy_${CaddyVersion}_checksums.txt" -OutFile "$CaddyDir\sums.txt"
    $line = Get-Content "$CaddyDir\sums.txt" | Where-Object { $_.Trim() -match "\s+caddy_${CaddyVersion}_windows_amd64\.zip$" } | Select-Object -First 1
    $want = if ($line) { ($line.Trim() -split '\s+')[0] } else { '' }
    $got = (Get-FileHash $zip -Algorithm SHA512).Hash.ToLower()
    Need ($want -and $got -eq $want.ToLower()) "Caddy's download does not match its published checksum"
    Expand-Archive $zip -DestinationPath $CaddyDir -Force
    Remove-Item $zip
}

# 4. stage
Say "staging..."
if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force "$Stage\bin", "$Stage\console", "$Stage\top", "$Stage\data\agent-dist\windows" | Out-Null
foreach ($p in $Server) { Copy-Item "$Target\release\$p.exe" "$Stage\bin\" }
Copy-Item "$CaddyDir\caddy.exe" "$Stage\bin\"
Copy-Item "$ConsoleOut\*" "$Stage\console\" -Recurse
Copy-Item "$Here\Caddyfile" "$Stage\top\"
Copy-Item "$Backend\..\caddy\routes.caddy" "$Stage\top\"
Set-Content "$Stage\top\VERSION" $Version -Encoding ascii
Copy-Item "$Ui\public\favicon.ico" "$Stage\provigil.ico"
# the default ruleset (what siem-api copies into the manager home: PROVIGIL_SOURCE_DIR)
foreach ($d in 'ruleset\decoders', 'ruleset\rules', 'ruleset\lists') {
    New-Item -ItemType Directory -Force "$Stage\ruleset\$d" | Out-Null
    Copy-Item "$Backend\$d\*" "$Stage\ruleset\$d\" -Recurse
}
New-Item -ItemType Directory -Force "$Stage\ruleset\etc", "$Stage\ruleset\src\agentlessd\scripts" | Out-Null
foreach ($f in 'internal_options.conf', 'local_decoder.xml', 'local_rules.xml') { Copy-Item "$Backend\etc\$f" "$Stage\ruleset\etc\" }
Set-Content "$Stage\ruleset\src\agentlessd\scripts\README.txt" "Agentless monitoring runs on Linux masters only." -Encoding ascii
# the repository's data files (not this PC's runtime data), and the agent package's programs
Push-Location $Backend
try {
    $files = git ls-files data | Where-Object { $_ -notmatch '^data/agent-dist/windows/.*\.exe$' }
    Need ($LASTEXITCODE -eq 0 -and $files) "git ls-files data failed"
    foreach ($f in $files) {
        $to = Join-Path "$Stage" ($f -replace '/', '\')
        New-Item -ItemType Directory -Force (Split-Path $to) | Out-Null
        Copy-Item (Join-Path $Backend ($f -replace '/', '\')) $to
    }
} finally { Pop-Location }
foreach ($p in $Agent) { Copy-Item "$Target\release\$p.exe" "$Stage\data\agent-dist\windows\" }

# 5. MSI
New-Item -ItemType Directory -Force $Out | Out-Null
$Msi = "$Out\ProVigil-Setup-$Version.msi"
Push-Location $Here
try {
    Run "dotnet tool restore" { dotnet tool restore }
    foreach ($e in 'WixToolset.UI.wixext', 'WixToolset.Firewall.wixext', 'WixToolset.Util.wixext') { Run "wix extension add $e" { dotnet tool run wix extension add "$e/5.0.2" } }
    Say "building $Msi..."
    Run "wix build" { dotnet tool run wix build ProVigil.wxs -arch x64 -d "Version=$Version" -d "Stage=$Stage" -ext WixToolset.UI.wixext -ext WixToolset.Firewall.wixext -ext WixToolset.Util.wixext -o $Msi }
} finally { Pop-Location }
Remove-Item "$Out\*.wixpdb" -ErrorAction SilentlyContinue
if ($Key) {
    $tool = "$Target\release\provigil-license.exe"
    if (-not (Test-Path $tool)) { Push-Location $Backend; try { $env:CARGO_TARGET_DIR = $Target; Run "cargo build provigil-license" { cargo build --release -p provigil-license } } finally { Pop-Location; Remove-Item Env:CARGO_TARGET_DIR } }
    Run "signing" { & $tool sign --key $Key $Msi }
}
Say ("done: {0} ({1:N0} MB)" -f $Msi, ((Get-Item $Msi).Length / 1MB))
