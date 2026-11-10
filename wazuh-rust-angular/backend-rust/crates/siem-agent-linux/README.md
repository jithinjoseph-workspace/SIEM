# Linux agent: gap to Windows parity

Status on 2026-10-29, branch `edr`. This file lists what the Linux agent lacks compared with the Windows agent, and what to change to close the gap.

## The two agents are built differently

| | Windows agent | Linux agent (`siem-agent-linux`) |
|---|---|---|
| Code | `siem-winagent` (`wazuh-agent.exe`), a port of Wazuh 4.14.7 `src/win32`, built on `siem-agentd`, `siem-logcollector`, `siem-syscheckd`, `siem-execd`, `siem-sca` and `siem-syscollector` | Its own small agent (about 3,200 lines) that shares no code with the Wazuh port |
| Transport | Wazuh protocol: TCP/UDP 1514 to `wazuh-remoted`, encrypted with the agent key | Plain HTTP JSON to `siem-api` on port 8088 (`/api/events/ingest`) |
| Commands from the manager | Remoted AR queue → execd → `ar.conf` → AR executables | HTTP poll of `/api/agents/:id/commands` every 5 s |
| Config | `ossec.conf` served by the manager, with groups and shared config | Hardcoded in `main.rs` and the module files |
| Tests | Oracle diff tests against the C agent | 3 unit tests |

Most of the gap comes from this split. Every Windows feature added on the server (AR commands, Sysmon decoding, process tree, file reputation, YARA) assumes the Wazuh event and command path. The Linux agent uses neither, so each feature has to be built a second time for it.

## Feature comparison

| Area | Windows | Linux today | Gap |
|---|---|---|---|
| Enrollment | Enrollment API, `client.keys` | Enrollment API, `client.keys` | none |
| Transport security | AES-encrypted 1514 | Plain `http://` by default; agent key sent in clear | **high** |
| Event authentication | Every message is checked against `client.keys` | `/api/events/ingest` does not check the agent key, so anyone can post events as any agent id | **high** |
| Event buffer | Disk-backed (`siem-agentd/buffer.rs`) | In memory, 5,000 events; lost on restart or a long outage | medium |
| Log collection | Full logcollector, configured from `ossec.conf` (`<localfile>`) | Polls 16 fixed files every 4 s; no journald, so Debian 12+ and other rsyslog-less systems send no auth logs; no multi-line, no rotation by rename | **high** |
| FIM | Ported syscheckd: realtime, whodata, recursion, diff, DB | Rehashes everything every 15 s, one directory level only, no realtime, no who-changed-it | **high** |
| Rootcheck | Ported rootcheck with `rootkit_files.txt` and `rootkit_trojans.txt` | 4 hardcoded checks (/dev/shm, promiscuous NIC, trojan symlinks, hidden /tmp) | medium |
| SCA | Ported SCA engine running the real CIS YAML | **Wrong results.** `parse_cis_yaml` turns every CIS check into "is `/etc/os-release` (or a path from the title) mode ≤ 644". The scores mean nothing. | **high** |
| Inventory | Syscollector in dbsync format, feeds the Inventory and vulnerability pages | Text events (packages, ports, processes, users); verify that the Inventory and vulnerability pages pick them up | medium |
| Active response: block IP | `netsh.exe` / `route-null.exe` via AR | nft / iptables / ufw / firewalld. Always reports success even when every tool failed; `nft` assumes an `inet filter input` chain exists; fixed 600 s timeout | medium |
| EDR: kill process | `kill-process.exe`: refuses PID ≤ 4, the agent itself and critical processes; checks the image name; logs the result | `kill -9 <pid>` with no checks (PID 1, sshd, the agent itself); always reports success; **not reachable from the UI** (`edr_agent_action` rejects non-Windows agents) | **high** |
| EDR: quarantine / restore | `quarantine-file.exe`: hash record, protected-path refusal, restore by id | Moves to `/var/ossec/quarantine` and runs `chmod 000`. No hash, no protected paths, **no restore**, not in the UI | **high** |
| EDR: isolate / release host | `isolate-host.exe`: firewall allows only the manager, timed release | **Missing** | **high** |
| EDR: process telemetry | Sysmon (event IDs 1, 3, 11, 22 …) with a manager-served config | Only whatever lands in `audit.log`, which is not configured by the installer | **high** |
| EDR: process tree per alert | `process_tree.rs`, built from Sysmon ProcessGuid | Missing; the server code reads Sysmon only | **high** |
| EDR: file reputation | `file_reputation.rs` on Sysmon hashes | Missing; FIM SHA-256 values are not fed in | medium |
| EDR: YARA scan | `yara-scan.exe` triggered by `yara_edr.rs` | Missing | medium |
| Agent upgrade from manager | `upgrade.rs` (WPK) | Missing | medium |
| Groups / shared config | Yes | No | medium |
| Packaging | MSI-equivalent deploy script | `install.sh`, plus deb/rpm metadata in `Cargo.toml` | low |

## Two ways to close the gap

**Option A (recommended): ship the ported Wazuh Unix daemons as the Linux agent.**
Most of the code already exists and is checked against the C agent:
- `wazuh-agentd`, `wazuh-logcollector` and `wazuh-execd` have binaries.
- `siem-syscheckd` (including the inotify and whodata code), `siem-rootcheck`, `siem-sca` and `siem-syscollector` exist as libraries.

With this option, Linux agents use the same 1514 path as Windows. AR commands, `ar.conf`, groups, encrypted transport and the FIM/SCA/rootcheck decoders then work without new server code, and the Linux active-response binaries (`firewall-drop`, plus Linux builds of the EDR ones) plug into `AR_COMMANDS`.

Work for option A:
1. Add a `wazuh-syscheckd` binary, and an agent-side `wazuh-modulesd` that runs syscollector and SCA. Today `siem-modulesd` holds only the manager-side task manager and upgrade code.
2. Add an installer that lays out `/var/ossec` like the Wazuh agent package. It needs `ossec.conf` from the manager, systemd units for each daemon, the SCA YAML for the distro, and the `rootkit_*.txt` files.
3. Build the Linux versions of `kill-process`, `quarantine-file` and `isolate-host` in `siem-active-response`. `edr.rs` already has the argument parsing, quarantine records and isolation allow-list. `kill_refusal` and `quarantine_refusal` need Linux lists (PID 1, systemd, sshd, the agent; `/bin`, `/sbin`, `/usr`, `/etc`, `/boot`, `/var/ossec`). Isolation would use nftables, with iptables as a fallback.
4. In `siem-api`:
   - Change `agent_is_windows` checks to "agent has EDR binaries".
   - Make `WINDOWS_AGENT_FILES` per platform.
   - Show the EDR section in `agents.html` for Linux agents too.
5. Retire `siem-agent-linux` once agents are migrated, or keep it only for hosts that cannot reach port 1514.

**Option B: keep extending `siem-agent-linux`.**
This is faster for any one item, but every Windows feature has to be built twice (agent and server), and the transport, buffer, FIM and SCA problems above all still have to be fixed by hand. If this option is chosen, do the work in this order:
1. **Security:** check `X-Agent-Key` on `/api/events/ingest`, default to `https://`, and refuse to send the key over plain HTTP.
2. **Correctness:**
   - Replace `parse_cis_yaml` with the real `siem-sca` engine.
   - Make block, kill and quarantine report real success or failure.
   - Add the kill and quarantine refusals from `edr.rs`.
3. **EDR:**
   - Add isolate/release and quarantine restore.
   - Route Linux agents in `edr_agent_action` to the command queue, and show the UI section for them.
4. **Telemetry:**
   - Add journald input.
   - Have the installer set auditd rules for execve, connect and file writes in tmp/home, or use eBPF.
   - Parse audit `execve` into the same shape the process tree and YARA code expect.
5. **Server:**
   - Teach `process_tree.rs`, `file_reputation.rs` and `yara_edr.rs` the Linux event shape.
   - Feed FIM SHA-256 values into file reputation.
6. **The rest:**
   - Disk-backed buffer.
   - Recursive FIM with inotify.
   - Rootcheck using the Wazuh signature files.
   - Upgrade from the manager.
   - Manager-served config.

## What "100%" means: the acceptance checklist

On a lab VM for each distro family (Ubuntu 24.04, Debian 12, RHEL 9 / Rocky 9, Amazon Linux 2023), check each of these:

- [ ] The agent enrolls into the right tenant. Events carry the tenant, and events posted without the agent's key are refused.
- [ ] Traffic is encrypted. Kill the manager for 30 minutes, restart the agent, and confirm that no events are lost.
- [ ] Failed SSH logins raise alerts on every distro, including journald-only Debian 12.
- [ ] Writing a file under `/etc` raises a FIM alert within seconds, showing who changed it.
- [ ] The SCA score for the CIS policy matches the C Wazuh agent on the same VM.
- [ ] Packages show on the Inventory page, and a known CVE shows on the vulnerability page.
- [ ] From the Agents page, run each of block IP, kill process, quarantine and restore file, and isolate and release host. Each one works, and each one is refused for PID 1, the agent itself, and `/bin` and `/etc` paths.
- [ ] Isolation keeps the manager reachable and expires after `AGENT_ISOLATION_SECONDS`.
- [ ] A process started from `/tmp` shows in the alert's process tree. Its hash gets a reputation verdict and is YARA-scanned.
- [ ] Upgrading the agent from the manager works, as does a config change pushed from the manager.

## Notes

- `siem-agent-linux` does not build on Windows (a known, older issue). Build it in WSL or on Linux.
- The systemd unit runs the agent as `root`. That is needed for firewall, kill and quarantine actions, but the log readers and FIM could be split out to run as a less privileged user.
