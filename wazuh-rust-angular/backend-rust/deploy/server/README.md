# ProVigil on three PCs

PC 1 is the master (Windows): agents, the analysis services, siem-api, the console and sign-in.
PC 2 is the data lake (Ubuntu 22.04 or 24.04): ClickHouse with every event, alert, case and setting.
PC 3 is the AI node (Ubuntu, a GPU with about 16 GB of memory): a local model server.
Agents and users reach PC 1 only. PC 2 and PC 3 accept the master's address and nothing else.

| File | Runs on | Does |
| --- | --- | --- |
| `install-datalake.sh` | PC 2 | ClickHouse, the ProVigil user, the schema, the firewall, daily backups |
| `backup-datalake.sh` | PC 2 | Backup, list and restore (installed by the above, runs daily at 02:15) |
| `install-ainode.sh` | PC 3 | Ollama, the model, the firewall, a test question |
| `connect-master.ps1` | PC 1 | Points the master at PC 2, checks PC 3, opens the agent and console ports |

The data lake installer also needs `init.sql`, `ndr-cluster.xml` and `ndr-compat-profile.xml`
from the `clickhouse` folder, copied next to it.

## Setup

1. **PC 2:** `sudo ./install-datalake.sh --master-ip <PC 1 address>`. Write down the three
   `CLICKHOUSE_` lines it prints; the password is shown only once.
2. **PC 3:** `sudo ./install-ainode.sh --master-ip <PC 1 address>` (`--model` for another model).
3. **PC 1,** PowerShell as administrator:
   `.\connect-master.ps1 -DataLake <PC 2 address> -AiNode <PC 3 address>` and type the password.
4. **PC 1:** move the existing data, if there is any (next section).
5. **PC 1:** `stop-all.bat`, then `start-all.bat`. It checks the data lake and starts only Valkey locally.
6. **Console:** Admin > AI providers > add `local-ai`, type openai, base URL `http://<PC 3>:11434`,
   the model, no key, priority 1, then **Test**.
7. **Check:** Admin > Telemetry shows usage per tenant from the data lake; Copilot answers with the
   local model's name.

## Moving to the three-PC setup

The master's data stays in its local ClickHouse until it is moved. Move it once, while ProVigil is
stopped (`stop-all.bat`), so no event is written to the old copy during the move:

1. On PC 1, back up every ProVigil database into a folder named with today's date:

   ```
   $day = Get-Date -Format yyyy-MM-dd
   $dbs = docker exec xdr-clickhouse clickhouse-client -q "SELECT name FROM system.databases WHERE name = 'ndr' OR name LIKE 'ndr\_%'"
   foreach ($db in $dbs) { docker exec xdr-clickhouse clickhouse-client -q "BACKUP DATABASE ``$db`` TO File('$day/$db')" }
   docker cp "xdr-clickhouse:/var/lib/clickhouse/backups/$day" .
   ```

2. Copy that folder to PC 2 into `/var/lib/clickhouse/backups/` (for example with `scp -r`), then
   `sudo chown -R clickhouse:clickhouse /var/lib/clickhouse/backups/<day>`.
3. On PC 2: `sudo /opt/provigil/backup-datalake.sh --restore <day>`. The empty databases the
   installer made are kept as a pre-restore backup first, then replaced.
4. Start ProVigil on PC 1 and check that old alerts and cases are there.

## Backups

Every night at 02:15 PC 2 backs up each database into `/var/lib/clickhouse/backups/<day>` and keeps
14 days (`--keep-days` at install). Copy that folder to another machine or a NAS: a backup on the
same disk does not survive the disk. Restore one day: `backup-datalake.sh --restore <day> [database]`.

## Remote support (managed on-premises)

`support-tunnel.ps1` on PC 1 opens an outbound SSH tunnel to ProVigil's support server, so support
can reach this master's console without any inbound port at the client. The client switches it on
and off:

- On, for 8 hours: `.\support-tunnel.ps1 -Enable -SupportHost <support server> -User site-<client> -RemotePort <port> -HostKey '<server host key>' -Hours 8`
  (as administrator). Send ProVigil the public key it prints. `-AllowRdp` adds remote desktop.
- Off: `.\support-tunnel.ps1 -Disable`. State: `.\support-tunnel.ps1 -Status`.

On the support server the key is added as
`restrict,port-forwarding,permitlisten="localhost:<port>",command="/bin/false" <key>`: it can open
that one tunnel and nothing else. The tunnel's port listens only on the support server itself.

## Monitoring and licences

- Admin > Telemetry shows Server Health (checked every minute; changes are e-mailed to the alert
  recipients set under Settings, SMTP), the Licence, and Usage per Tenant.
- Managed service: set `HEALTH_REPORT_URL` (https), `HEALTH_REPORT_TOKEN` and `SITE_NAME` in the
  master's `.env`; it reports its health to ProVigil every 5 minutes. The receiving ProVigil sets
  `HEALTH_REPORT_ACCEPT_TOKEN` and lists the sites under Managed Sites.
- On-premises release builds carry ProVigil's public key and need a licence: Admin > Telemetry >
  Licence, paste it. New PCs are refused when it expires or is full; enrolled PCs keep working.
