<#
.SYNOPSIS
  Builds ProVigil-AllInOne-Setup-<version>.msi: SIEM and NDR in containers on Windows (WSL2).
  It carries setup.ps1, keep-running.ps1 and the release's signed provigil-install.sh (ndr/dist/<v>,
  built by release-kit.sh), so build the release kit first. Signed with -Key (provigil-license sign).

  .\build-allinone-msi.ps1 -Version 1.2.3 [-Key private.pem]
#>
param([Parameter(Mandatory = $true)][string]$Version, [string]$Key)
$ErrorActionPreference = 'Stop'
$Here = $PSScriptRoot
$Backend = (Resolve-Path "$Here\..\..\..").Path
$Repo = (Resolve-Path "$Backend\..\..").Path
$Installer = "$Repo\ndr\dist\$Version\provigil-install.sh"
if (-not (Test-Path $Installer)) { throw "no ${Installer}: run ndr/release-kit.sh $Version first" }
$Stage = "$Here\stage"
$Out = "$Here\..\out"
Remove-Item -Recurse -Force $Stage -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force $Stage, $Out | Out-Null
Copy-Item "$Here\setup.ps1", "$Here\keep-running.ps1", $Installer, "$Here\..\stage\provigil.ico" $Stage -ErrorAction SilentlyContinue
if (-not (Test-Path "$Stage\provigil.ico")) { Copy-Item "$Backend\..\ndr-ui\public\favicon.ico" "$Stage\provigil.ico" }
$Msi = "$Out\ProVigil-AllInOne-Setup-$Version.msi"
Push-Location "$Here\.."
try {
    dotnet tool restore | Out-Null
    dotnet tool run wix build "$Here\ProVigil-AllInOne.wxs" -arch x64 -d "Version=$Version" -d "Stage=$Stage" -o $Msi
    if ($LASTEXITCODE -ne 0) { throw "wix build failed" }
} finally { Pop-Location }
Remove-Item "$Out\*.wixpdb" -ErrorAction SilentlyContinue
if ($Key) {
    & "$Backend\target\release\provigil-license.exe" sign --key $Key $Msi
    if ($LASTEXITCODE -ne 0) { throw "signing failed" }
}
Write-Host ("done: {0} ({1:N1} MB)" -f $Msi, ((Get-Item $Msi).Length / 1MB))
