# Samples the manager every 10 s during a load test: CPU % (of one core) and memory per process,
# analysisd / remoted state, ClickHouse rows of tenant loadtest. Usage: monitor.ps1 <out.csv> <seconds>
param([string]$out, [int]$secs)
$run = "$PSScriptRoot\..\..\data\manager\var\run"
$names = "siem-api", "wazuh-remoted", "wazuh-analysisd", "wazuh-db", "wazuh-modulesd", "loadgen"
function St($f) { $h = @{}; Get-Content "$run\$f" -ErrorAction SilentlyContinue | ForEach-Object { if ($_ -match "^(\w+)='(.*)'") { $h[$matches[1]] = $matches[2] } }; $h }
$cols = @("t_s") + ($names | ForEach-Object { "$_`_cpu", "$_`_mb" }) + "tcp_sessions", "remoted_queue", "remoted_discarded", "ana_received", "ana_dropped", "ana_event_q", "ana_winevt_q", "ana_alerts_q", "ana_archives_q", "alerts_written", "ch_events", "ch_alerts", "ch_cpu", "ch_mem"
($cols -join ",") | Out-File $out -Encoding utf8
$prev = @{}; $t0 = Get-Date
while (((Get-Date) - $t0).TotalSeconds -lt $secs) {
    $now = Get-Date; $row = @([int]($now - $t0).TotalSeconds)
    foreach ($n in $names) {
        $p = Get-Process $n -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($p) {
            $cpu = $p.TotalProcessorTime.TotalSeconds; $c = 0
            if ($prev[$n]) { $c = [math]::Round(100 * ($cpu - $prev[$n][0]) / ($now - $prev[$n][1]).TotalSeconds) }
            $prev[$n] = @($cpu, $now); $row += $c, [int]($p.WorkingSet64 / 1MB)
        } else { $row += "", "" }
    }
    $r = St "wazuh-remoted.state"; $a = St "wazuh-analysisd.state"
    $row += $r.tcp_sessions, $r.queue_size, $r.discarded_count, $a.events_received, $a.events_dropped, $a.event_queue_usage, $a.winevt_queue_usage, $a.alerts_queue_usage, $a.archives_queue_usage, $a.alerts_written
    $ch = docker exec xdr-clickhouse clickhouse-client -q "SELECT (SELECT count() FROM ndr_loadtest.siem_events), (SELECT count() FROM ndr_loadtest.siem_alerts)" 2>$null
    $row += ($ch -split "\s+")[0..1]
    $ds = docker stats xdr-clickhouse --no-stream --format "{{.CPUPerc}},{{.MemUsage}}" 2>$null
    $row += ($ds -split ",")[0], (($ds -split ",")[1] -split " / ")[0]
    ($row -join ",") | Out-File $out -Append -Encoding utf8
    Start-Sleep -Seconds ([math]::Max(1, 10 - ((Get-Date) - $now).TotalSeconds))
}
