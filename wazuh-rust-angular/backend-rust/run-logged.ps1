# Runs a service command, shows its output in this window and writes it to a log file.
# The previous run's log is kept as <log>.1.
param([Parameter(Mandatory)][string]$Log, [Parameter(Mandatory)][string]$Cmd)
New-Item -ItemType Directory -Force (Split-Path $Log) | Out-Null
if (Test-Path $Log) { Move-Item $Log "$Log.1" -Force }
$w = New-Object IO.StreamWriter($Log, $false)
$w.AutoFlush = $true
[Console]::OutputEncoding = [Text.Encoding]::UTF8  # the services print UTF-8
$w.WriteLine("==== started $(Get-Date -Format s): $Cmd ====")
# 2>&1 inside cmd merges stderr as plain text (PowerShell 5.1 would wrap it in error records);
# the window keeps the colors, the file gets them stripped.
cmd /c "($Cmd) 2>&1" | ForEach-Object { $_; $w.WriteLine(($_ -replace '\x1b\[[0-9;]*m', '')) }
$w.WriteLine("==== exited with code $LASTEXITCODE at $(Get-Date -Format s) ====")
$w.Close()
