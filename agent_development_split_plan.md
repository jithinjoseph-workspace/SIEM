# Wazuh Agent Parallel Porting Guide: Windows vs. Linux Division

This document defines the architecture, responsibilities, crate boundaries, and workflows for two developers working concurrently on the Wazuh Rust agent.

---

## 1. Architectural Strategy: Avoiding Merge Conflicts

In Wazuh's original architecture:
- **Windows**: All agent components (`agentd`, `logcollector`, `execd`, `syscheckd`, `modulesd`) run in **a single process** (`wazuh-agent.exe`) driven by threads and Windows service control (`WazuhSvc`).
- **Linux**: Agent components run as **separate daemon processes** (`wazuh-agentd`, `wazuh-logcollector`, `wazuh-execd`, `wazuh-modulesd`, `wazuh-syscheckd`) communicating via Unix Domain Sockets (`/var/ossec/queue/...`).

To ensure **zero merge conflicts**, the codebase is partitioned strictly by target OS and crate boundaries:

```
backend-rust/
├── crates/
│   ├── [SHARED / FROZEN - Read Only]
│   │   ├── siem-crypto/         (Keys, encryption, hashing)
│   │   ├── siem-ipc/            (Sockets, MQ abstractions)
│   │   ├── siem-njson/          (Exact nlohmann byte serialization)
│   │   ├── siem-config/         (ossec.conf parsing)
│   │   └── siem-dbsync/         (Database synchronization protocol)
│   │
│   ├── [DEVELOPER 1: WINDOWS AGENT]
│   │   ├── siem-winagent/       <-- EXCLUSIVE: wazuh-agent.exe, service.rs, components.rs
│   │   ├── siem-sysinfo/src/win/<-- EXCLUSIVE: Windows inventory providers (done)
│   │   └── siem-syscheckd/src/win/<-- EXCLUSIVE: Windows Registry & SACL Who-Data FIM
│   │
│   └── [DEVELOPER 2: LINUX AGENT]
│       ├── siem-modulesd/       <-- EXCLUSIVE: wazuh-modulesd daemon
│       ├── siem-sysinfo/src/linux/<-- EXCLUSIVE: Linux /proc & netlink providers
│       ├── siem-syscheckd/src/linux/<-- EXCLUSIVE: Linux inotify/fanotify FIM
│       └── siem-agentd/tests/oracle/<-- EXCLUSIVE: Linux daemon oracle verifications
```

---

## 2. Developer 1: Windows Agent (`dev-windows`)

### Scope of Responsibility
Developer 1 owns the Windows agent binary, Windows service lifecycle, Windows-specific FIM (Registry, SACL, ReadDirectoryChangesW), and wiring the syscollector inventory into the Windows process.

### Crate & Directory Ownership
1. [`crates/siem-winagent/`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-winagent)
   - `src/main.rs`: Command line arguments (`install-service`, `uninstall-service`, `start`).
   - `src/service.rs`: SCM Windows Service handler (`WazuhSvc`) and stop signal propagation.
   - `src/components.rs`: Thread manager orchestrating `agentd`, `logcollector`, `execd`, `syscollector`, and `syscheck`.
2. [`crates/siem-syscheckd/src/win/`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-syscheckd) *(or Windows modules)*:
   - Registry monitoring (`HKEY_LOCAL_MACHINE`, `HKEY_USERS` change notifications).
   - Real-time directory monitoring via `ReadDirectoryChangesW`.
   - Windows Who-data auditing (Security event log / SACL tracking).
3. [`crates/siem-sysinfo/src/win/`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-sysinfo/src/win):
   - All 11 inventory providers are completed and matched against `sysinfo.dll`.

### Step-by-Step Task List
1. **Task W1: Deploy and Verify Windows Service**
   - Run the install script from an elevated PowerShell.
   - Confirm agent appears as `Active` in the Angular UI (`http://localhost:4200`).
   - Emit event using `eventcreate /L APPLICATION /T ERROR /SO Test /ID 1000 /D "test"` and verify alert ingestion.
2. **Task W2: Wire Syscollector into `siem-winagent`**
   - Open [`crates/siem-winagent/src/components.rs`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-winagent/src/components.rs).
   - In `start_wmodules()`, launch the syscollector background thread calling `siem_syscollector::SyscollectorEngine` populated by `siem_sysinfo::win::SysInfo`.
   - Forward syscollector sync diffs through `agentd` message queue to `wazuh-db`.
3. **Task W3: Windows FIM (`syscheck`)**
   - Implement Windows registry watcher in `siem-syscheckd`.
   - Connect `start_syscheck` in `siem-winagent/src/components.rs`.
4. **Task W4: Service Teardown Cleanups**
   - Add graceful shutdown hooks (`wm_kill_children`, `fim_db_teardown`) to `service.rs`.

---

## 3. Developer 2: Linux Agent (`dev-linux`)

### Scope of Responsibility
Developer 2 owns Linux inventory collection (`siem-sysinfo/src/linux`), the Linux modules daemon (`wazuh-modulesd`), and Linux FIM (`inotify`/`fanotify`).

### Crate & Directory Ownership
1. [`crates/siem-sysinfo/src/linux/`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-sysinfo/src/linux) *(new directory)*:
   - `mod.rs`: Exports `SysInfo` matching the exact signature used by `win::SysInfo`.
   - `os.rs`: Reads `/etc/os-release`, kernel uname.
   - `hardware.rs`: Parses `/proc/cpuinfo`, `/proc/meminfo`, `/sys/class/dmi/id`.
   - `packages.rs`: Native package manager parser (Debian `/var/lib/dpkg/status`, RPM sqlite/BerkeleyDB, Pacman DB).
   - `network.rs`: Netlink sockets / `/proc/net/dev`, `/proc/net/route`.
   - `ports.rs`: Socket inspection via `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`.
   - `processes.rs`: `/proc/[pid]/` status, cmdline, stat parsing.
2. [`crates/siem-modulesd/`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-modulesd):
   - Standalone binary `wazuh-modulesd`.
   - Spawns and manages module tasks on Linux (syscollector timer, SCA scans).
   - Communicates with `wazuh-agentd` via `/var/ossec/queue/sockets/queue`.
3. [`crates/siem-syscheckd/src/linux/`](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-syscheckd) *(new directory)*:
   - Linux real-time file monitoring using `inotify` and `fanotify`.
   - Auditd socket integration for Linux who-data.

### Step-by-Step Task List
1. **Task L1: Create Linux SysInfo Providers**
   - Create `crates/siem-sysinfo/src/linux/`.
   - In `crates/siem-sysinfo/src/lib.rs`, add:
     ```rust
     #[cfg(target_os = "linux")]
     pub mod linux;
     #[cfg(target_os = "linux")]
     pub use linux::SysInfo;
     ```
   - Implement Linux providers using `/proc` and standard libc calls without Windows dependencies.
   - Compare output format against Wazuh Linux agent `sysinfo.so`.
2. **Task L2: `wazuh-modulesd` Linux Daemon Execution**
   - Complete `crates/siem-modulesd/src/main.rs` to start `syscollector` on schedule.
   - Send diffs to `wazuh-agentd` Unix domain socket.
3. **Task L3: Linux FIM Engine**
   - Implement `inotify` watcher inside `siem-syscheckd`.
   - Build standalone Linux binary `wazuh-syscheckd`.
4. **Task L4: Oracle Test in WSL**
   - Use the existing WSL `Ubuntu-20.04` harness to compare output with C `wazuh-modulesd` and `wazuh-syscheckd`.

---

## 4. Shared Contract: The Inventory Provider Interface

To guarantee that both developers plug into `siem-syscollector` identically, both `win::SysInfo` and `linux::SysInfo` implement the exact same methods:

```rust
// Shared signature expected by siem-syscollector
impl SysInfo {
    pub fn new() -> Self;
    pub fn os(&self) -> Result<siem_njson::Value, Error>;
    pub fn hardware(&self) -> Result<siem_njson::Value, Error>;
    pub fn packages(&self) -> Result<siem_njson::Value, Error>;
    pub fn processes(&self) -> Result<siem_njson::Value, Error>;
    pub fn ports(&self) -> Result<siem_njson::Value, Error>;
    pub fn networks(&self) -> Result<siem_njson::Value, Error>;
    pub fn accounts(&self) -> Result<siem_njson::Value, Error>;
    pub fn browser_extensions(&self) -> Result<siem_njson::Value, Error>;
}
```

Because `siem_syscollector::SyscollectorEngine` consumes this interface, the delta synchronization engine remains **100% platform-agnostic**.

---

## 5. Git & Collaboration Best Practices

1. **Branch Names**:
   - Developer 1: `git checkout -b feature/agent-windows`
   - Developer 2: `git checkout -b feature/agent-linux`
2. **File Modification Rule**:
   - Do NOT edit files outside of your designated directories without prior agreement.
   - Core shared crates (`siem-njson`, `siem-crypto`, `siem-config`, `siem-dbsync`) should be treated as read-only.
3. **Pre-commit Verification**:
   - Developer 1 checks: `cargo check -p siem-winagent --target x86_64-pc-windows-msvc` (or gnu)
   - Developer 2 checks: `cargo check -p siem-modulesd -p siem-sysinfo --target x86_64-unknown-linux-gnu` (via WSL)
