<#
  Run by the "ProVigil" task at Windows start and sign-in: keeps ProVigil's Linux (WSL2) running, so its
  containers (with restart: always) serve the console, agents and sensors. Windows older than 11 22H2
  has no mirrored network: the ports are forwarded to the Linux's address, which changes at each start.
#>
$Distro = 'ProVigil'
$Ports = 443, 8089, 8443, 9092
if ([Environment]::OSVersion.Version.Build -lt 22621) {
    $ip = ((& wsl.exe -d $Distro -u root -e hostname -I) -split '\s+' | Where-Object { $_ } | Select-Object -First 1)
    if ($ip) {
        foreach ($p in $Ports) {
            & netsh.exe interface portproxy delete v4tov4 listenport=$p listenaddress=0.0.0.0 *> $null
            & netsh.exe interface portproxy add v4tov4 listenport=$p listenaddress=0.0.0.0 connectport=$p connectaddress=$ip | Out-Null
        }
    }
}
# as long as this runs, WSL keeps the Linux (and Docker in it) up
& wsl.exe -d $Distro -u root -e sleep infinity
