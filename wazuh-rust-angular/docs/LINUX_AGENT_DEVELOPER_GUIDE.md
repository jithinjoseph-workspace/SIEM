# Linux Agent Development & Migration Guide (for Dev-2)

> **CRITICAL DIRECTIVE / ZERO-REGRESSION POLICY FOR DEV-2:**  
> **DO NOT modify, rename, or overwrite any existing Windows Agent code, Windows API routes, or Windows UI components.**  
> - Windows Agent (`wazuh-agent.exe`, `crates/siem-winagent`), its endpoints (`/downloads/windows/*`, `/downloads/wazuh-agent.exe`), and its PowerShell scripts **must remain 100% untouched**.  
> - All Linux development must be **purely additive** (e.g. extending `/downloads/linux/*`, finalizing `install.sh`, Linux packaging, and Linux daemon compilation).  
> - Both Windows and Linux agents share the exact same wire communication protocol (AES-256 on TCP 1514) and REST enrollment API (`POST /api/v1/agents/enroll`).

---

## 1. Executive Summary & Current Status

The core SIEM manager (analysisd, wazuh-db, remoted, modulesd, monitord, maild, integratord, csyslogd) and the Windows agent (`wazuh-agent.exe`) are 100% complete and verified against C Wazuh 4.14.7.

For the **Linux Agent**, the majority of the heavy lifting is already ported into faithful Rust crates and verified in WSL (`Ubuntu-20.04`). Dev-2's task is to connect the remaining Linux pieces (primarily `syscheckd` on Linux and packaging/service integration) into a seamless end-to-end deployment.

### Component-by-Component Status Matrix

| Component | Crate Location | Status for Linux | Tasks for Dev-2 |
|---|---|---|---|
| **Core Agent Networking (`wazuh-agentd`)** | `crates/siem-agentd` | **100% Complete**<br>(Verified in WSL) | Wire protocol (AES-256, TCP/UDP 1514), key exchange, counters, auto-enrollment, buffer, agcom. Ready for Linux production. |
| **Log Collector (`wazuh-logcollector`)** | `crates/siem-logcollector` | **100% Complete**<br>(Verified in WSL) | Linux text file readers, multiline regex, syslog, systemd journal (`read_journald.c` via libsystemd dlopen). Ready for Linux production. |
| **Active Response (`wazuh-execd`)** | `crates/siem-execd` | **100% Complete**<br>(Verified in WSL) | Unix AR executor matching C (6/6 oracle scenarios passed). Executes Linux scripts (e.g. `firewall-drop`, `disable-account`). |
| **System Inventory (`syscollector`)** | `crates/siem-syscollector` | **100% Complete** | Linux hardware, OS, network interfaces/ports, processes, and packages (`dpkg`, `rpm`, `pacman`, `apk`). |
| **Security Auditing (`sca`)** | `crates/siem-sca` | **100% Complete** | Evaluates Linux CIS benchmarks from YAML (`/var/ossec/ruleset/sca/*.yml`). |
| **Modules Runner (`modulesd`)** | `crates/siem-modulesd` | **100% Complete** | Runs `command`, `osquery`, and handles remote agent upgrades. |
| **File Integrity Monitoring (`syscheckd`)** | `crates/siem-syscheckd` | **Partial**<br>(Windows done; Linux needs port completion) | **Primary Dev-2 Task**: Enable Linux compilation, inotify realtime engine, Linux `whodata` (auditd netlink), and `diff -u`. |
| **Agent Packaging & Deployment** | `crates/siem-agent-linux` & `install.sh` | **Prototype Exists** | **Secondary Dev-2 Task**: Finalize `install.sh`, systemd service unit, `.deb`/`.rpm` packaging. |

---

## 2. Linux Agent Architecture

In Wazuh on Linux, agents can run in two modes:
1. **Multi-Daemon Mode (Traditional Wazuh)**:
   Independent daemons communicating through Unix domain sockets (`/var/ossec/queue/sockets/`):
   - `wazuh-agentd` (binary in `siem-agentd`)
   - `wazuh-logcollector` (binary in `siem-logcollector`)
   - `wazuh-syscheckd` (binary in `siem-syscheckd`)
   - `wazuh-execd` (binary in `siem-execd`)
   - `wazuh-modulesd` (binary in `siem-modulesd`)
   Controlled by `/var/ossec/bin/wazuh-control`.
2. **Unified Single-Binary Mode (Rust Native)**:
   The prototype in `crates/siem-agent-linux` compiles into a single binary (`siem-agent-linux`) that launches these threads in-process under one systemd service (`wazuh-rust-agent.service`), mirroring how `siem-winagent` works on Windows.

> **Recommendation for Dev-2**: Support both. The unified `siem-agent-linux` single binary is drastically easier to deploy via `curl | bash` or `.deb`, while the separate binaries allow drop-in replacement in existing Wazuh Linux directories (`/var/ossec/bin/`).

---

## 3. Primary Tasks for Dev-2

### Task 1: Complete Linux FIM in `siem-syscheckd`
Currently, `crates/siem-syscheckd` compiles on Windows for registry and `ReadDirectoryChangesW`. For Linux:
1. **Linux Build Fix**:
   - In `crates/siem-syscheckd/src/port/diff.rs`, `run_check.rs`, `create_db.rs`, ensure conditional compilation (`#[cfg(unix)]` vs `#[cfg(windows)]`) handles IPC sockets cleanly without Windows-only symbols.
2. **Realtime Inotify Engine**:
   - Port `src/syscheckd/run_realtime.c`: initialize inotify (`inotify_init1(IN_CLOEXEC)`), add watch descriptors (`inotify_add_watch`) for monitored directories, and handle events in an async/poll loop.
3. **Whodata / Audit on Linux**:
   - Connect to Linux audit subsystem via Netlink socket (`NETLINK_AUDIT`) to capture process ID (`pid`), user ID (`uid`), and command name for file modification events.
4. **Diffing (`report_changes`)**:
   - Use standard `diff -u` or pure-Rust diffing instead of Windows `fc /n`.

### Task 2: Standardize Agent IPC for Linux
- On Linux, IPC occurs over Unix domain datagram and stream sockets under `/var/ossec/queue/sockets/`:
  - `queue/sockets/queue` (`DEFAULTQUEUE`): Datagram socket where `logcollector`, `syscheckd`, and `modulesd` send alerts to `agentd`.
  - `queue/sockets/syscheck`: Stream socket for `syscheck` control and `getconfig`.
  - `queue/sockets/logcollector`: Stream socket for `logcollector` control.
- `siem-ipc` already contains the full Linux implementation (`UnixDatagram`, `UnixStream`, `framing`, and `mq_op`). Ensure all Linux binaries use `/var/ossec/` paths.

### Task 3: Packaging & Installer (`install.sh`)
1. **`crates/siem-agent-linux/install.sh`**:
   - The installer script already detects distro (`deb`, `rpm`, `apk`, `pacman`) and accepts:
     - `SIEM_MANAGER_URL`: Manager URL (e.g. `http://manager-ip:8088`).
     - `SIEM_AGENT_NAME`: Optional name (defaults to `hostname`).
     - `SIEM_AGENT_GROUP`: Group (defaults to `default`).
     - `SIEM_TENANT_KEY`: Optional tenant isolation key.
   - Test this script on Ubuntu 20.04/22.04 and RHEL/Rocky Linux 8/9.
2. **Package Serving in `siem-api`**:
   - In `crates/siem-api/src/main.rs`, the routes are already established:
     - `GET /downloads/siem-agent-linux`: Serves the compiled Linux agent binary.
     - `GET /downloads/install.sh`: Serves `crates/siem-agent-linux/install.sh`.
   - **Do not modify the Windows download routes (`/downloads/windows/*`)!**

### Task 4: Systemd Service Unit
- Deploy `init/wazuh-rust-agent.service`:
  ```ini
  [Unit]
  Description=Wazuh Next-Gen Endpoint Security Agent (Rust)
  After=network.target

  [Service]
  Type=simple
  User=root
  ExecStart=/var/ossec/bin/siem-agent-linux
  Restart=on-failure
  RestartSec=10s
  LimitNOFILE=65536

  [Install]
  WantedBy=multi-user.target
  ```

---

## 4. Backend & UI Integration (Zero Changes to Windows)

### 1. Enrollment API (`POST /api/v1/agents/enroll`)
The backend is already OS-agnostic:
- **Request**:
  ```json
  {
    "name": "linux-node-01",
    "groups": "default",
    "os_type": "linux"
  }
  ```
- **Headers**:
  - `X-Tenant-Key`: `<tenant-key>` (if multitenant)
- **Response**:
  ```json
  {
    "agent_id": "025",
    "agent_name": "linux-node-01",
    "agent_ip": "any",
    "raw_key": "MDAxIGxpbnV4LW5vZGUtMDEgYW55IGFiY2RlZjEyMzQ1..."
  }
  ```
The installer writes this key directly into `/var/ossec/etc/client.keys` as:
`025 linux-node-01 any <raw_key>`

### 2. Frontend Deploy Wizard (`ndr-ui`)
In `ndr-ui/src/pages/analyst/agents/agents.ts` and `ndr-ui/src/services/siem/agent-deploy.ts`:
- The deploy modal already has an OS selector (`'windows' | 'linux' | 'macos'`).
- When `'linux'` is selected, it outputs:
  ```bash
  curl -sSL 'http://<manager-url>/downloads/install.sh' | sudo SIEM_MANAGER_URL='http://<manager-url>' SIEM_AGENT_NAME='linux-node-xxxx' SIEM_AGENT_GROUP='default' SIEM_TENANT_KEY='<key>' bash
  ```
- **Rule for Dev-2**: Do not alter `windowsInstallScript` or any Windows-specific template logic in `agent-deploy.ts` or `agents.html`. Only enhance the Linux tab if necessary.

---

## 5. Development & Testing Workflow for Dev-2

1. **Build in Linux / WSL (`Ubuntu-20.04`)**:
   ```bash
   cd /mnt/e/wazhu-Siem-code/wazuh-rust-angular/backend-rust
   # Build the Linux daemons
   cargo build --release -p siem-agentd -p siem-logcollector -p siem-execd -p siem-agent-linux
   ```
2. **Run Oracle Verification (Diff against real C Wazuh 4.14.7)**:
   - For `agentd`:
     ```bash
     cd crates/siem-agentd/tests/oracle
     bash run_diff.sh default
     ```
   - For `logcollector`:
     ```bash
     cd crates/siem-logcollector/tests/oracle
     bash run.sh
     ```
   - For `execd`:
     ```bash
     cd crates/siem-execd/tests/oracle-unix
     bash run.sh
     ```
3. **End-to-End Live Verification**:
   - Run the manager (`run-siem-api.bat` or `cargo run -p siem-api`).
   - Run `install.sh` on a Linux VM or in a clean Docker container pointing at the host manager (`http://<host-ip>:8088`).
   - Verify the agent appears as "active" in the UI at `http://localhost:4200/analyst/agents`.
   - Verify `/var/log/syslog` messages appear in the SIEM Events page.
