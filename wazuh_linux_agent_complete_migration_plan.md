# Wazuh C to SIEM Rust Linux Agent: Complete Migration Plan

## 1. Executive Summary & Architecture Strategy

The SIEM platform currently runs an operational all-in-one universal binary (`siem-agent-linux`) deployed on Linux endpoints (including the active test VM), communicating directly over authenticated REST/WebSocket channels with `siem-api`. In parallel, the workspace houses specialized library crates (`siem-sysinfo`, `siem-syscheckd`, `siem-logcollector`, `siem-sca`) modeled after the original Wazuh 4.14.7 C/C++ daemons.

To achieve **100% functional parity with the original Wazuh C Linux agent** while maintaining zero disruption to the active system:
- All enhancements will be implemented as modular, production-grade Rust components.
- The single universal binary runtime (`siem-agent-linux`) will integrate these engine modules directly so endpoints do not require running 6 disconnected OS daemons.
- The shared crates (`siem-sysinfo/src/linux`, `siem-syscheckd`, `siem-sca`, `siem-logcollector`) will provide reusable library APIs matching the existing Windows agent contract (`agent_development_split_plan.md`).

---

## 2. Component-by-Component Migration Breakdown

```
Wazuh C Source (wazuh-4.14.7/src/)          Rust SIEM Target (backend-rust/crates/)
├── syscheckd/                               ├── siem-agent-linux/src/syscheck.rs
│   ├── run_realtime.c (inotify)    ======>  │   ├── inotify kernel watcher
│   └── whodata/ (netlink audit)    ======>  │   └── who-data auditd netlink reader
│                                            └── siem-syscheckd/src/linux/
│
├── data_provider/ (sysinfo C++)             ├── siem-sysinfo/src/linux/
│   ├── sysInfoLinux.cpp            ======>  │   ├── os.rs, hardware.rs, network.rs
│   ├── packages/ (dpkg/rpm db)     ======>  │   ├── packages.rs, ports.rs, processes.rs
│   └── network/ & ports/           ======>  └── siem-agent-linux/src/syscollector.rs
│
├── logcollector/                            ├── siem-agent-linux/src/logcollector.rs
│   ├── read_journald.c             ======>  │   ├── systemd journal reader
│   └── read_multiline_regex.c      ======>  │   └── multiline regex accumulator
│
├── wazuh_modules/wm_sca.c                   ├── siem-sca/ (wm.rs, yaml.rs, check.rs)
│   └── dynamic .yml policy engine  ======>  └── siem-agent-linux/src/sca.rs
│
└── wazuh_modules/wm_docker.c                └── siem-agent-linux/src/docker.rs
    └── /var/run/docker.sock monitor ======>     └── Docker unix socket event listener
```

---

## 3. Detailed Implementation Phases

### Phase 1: Real-time Inotify & Who-data Linux FIM (`syscheck`)
- **Objective**: Transition Linux FIM from pure periodic disk polling to instant kernel notification with user/process attribution.
- **Reference Files**:
  - `wazuh-4.14.7/src/syscheckd/src/run_realtime.c` (24 KB)
  - `wazuh-4.14.7/src/syscheckd/src/whodata/syscheck_audit.c` (24 KB)
  - `wazuh-4.14.7/src/syscheckd/src/whodata/audit_parse.c` (43 KB)
- **Target Files**:
  - `crates/siem-agent-linux/src/syscheck.rs`
  - `crates/siem-syscheckd/src/realtime.rs`
  - `crates/siem-syscheckd/src/whodata.rs`
- **Tasks**:
  1. Implement POSIX `inotify_init1(IN_CLOEXEC | IN_NONBLOCK)` and recursive watch descriptors (`IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB`).
  2. Implement async inotify event polling inside Tokio runtime.
  3. Implement Who-data Linux Netlink socket listener (`NETLINK_AUDIT` / `auditd`) to capture `audit_log` records:
     - Match file path in audit event to resolve real user `auid`, process owner `uid`, `gid`, `pid`, `ppid`, `exe`, and `cmdline`.
  4. Implement automatic graceful fallback to polling mode if kernel watch descriptors exceed `/proc/sys/fs/inotify/max_user_watches` or `NETLINK_AUDIT` lacks root capability (`CAP_AUDIT_READ`).

---

### Phase 2: Native High-Performance Linux Inventory Provider (`siem-sysinfo/src/linux`)
- **Objective**: Implement native Linux hardware, OS, network, and package inventory without shell commands (`ps`, `dpkg-query`, `rpm`).
- **Reference Files**:
  - `wazuh-4.14.7/src/data_provider/src/sysInfoLinux.cpp` (36 KB)
  - `wazuh-4.14.7/src/data_provider/src/packages/packageLinuxDataRetriever.h`
  - `wazuh-4.14.7/src/data_provider/src/ports/portLinuxWrapper.h`
- **Target Files**:
  - `crates/siem-sysinfo/src/linux/mod.rs`
  - `crates/siem-sysinfo/src/linux/os.rs`
  - `crates/siem-sysinfo/src/linux/hardware.rs`
  - `crates/siem-sysinfo/src/linux/packages.rs`
  - `crates/siem-sysinfo/src/linux/network.rs`
  - `crates/siem-sysinfo/src/linux/ports.rs`
  - `crates/siem-sysinfo/src/linux/processes.rs`
- **Tasks**:
  1. Implement `SysInfo` matching the shared provider interface in `crates/siem-sysinfo/src/lib.rs`.
  2. Direct parser for `/var/lib/dpkg/status` (Debian/Ubuntu) and RPM database (RHEL/Rocky/CentOS).
  3. Direct `/proc/[pid]/` scanner: read `cmdline`, `stat`, `status`, `comm` in pure Rust without `ps`.
  4. Direct `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp` scanner without `netstat`/`ss`.
  5. Direct `/sys/class/net/` and `/proc/net/dev` parser for interface IPs, MAC addresses, and link states.
  6. Direct DMI/SMBIOS parser (`/sys/class/dmi/id/` for `product_name`, `product_uuid`, `sys_vendor`, `board_vendor`).

---

### Phase 3: Systemd Journald & Multiline Regex Log Collection (`logcollector`)
- **Objective**: Collect system logs directly from systemd's binary journal stream and handle multiline stack traces cleanly.
- **Reference Files**:
  - `wazuh-4.14.7/src/logcollector/read_journald.c` (8 KB)
  - `wazuh-4.14.7/src/logcollector/read_multiline_regex.c` (18 KB)
- **Target Files**:
  - `crates/siem-agent-linux/src/logcollector.rs`
  - Integration with `crates/siem-logcollector/src/journal.rs`
- **Tasks**:
  1. Support reading directly from `/var/log/journal/` or `/run/log/journal/` using systemd journal format or journal export stream.
  2. Implement regex multiline buffer (`MultilineAccumulator`): group subsequent lines (e.g., Python / Java stack traces) until matching a starting regex pattern, avoiding log fragmentation.
  3. Maintain seek offset / cursor persistence across agent restarts in `/var/ossec/queue/logcollector.state`.

---

### Phase 4: Dynamic YAML Policy SCA Engine Integration (`wm_sca`)
- **Objective**: Move from static CIS checks in `sca.rs` to evaluating full Wazuh YAML SCA benchmark policies (`/var/ossec/ruleset/sca/*.yml`).
- **Reference Files**:
  - `wazuh-4.14.7/src/wazuh_modules/wm_sca.c` (122 KB)
- **Target Files**:
  - `crates/siem-agent-linux/src/sca.rs`
  - `crates/siem-sca/src/wm.rs`
  - `crates/siem-sca/src/yaml.rs`
  - `crates/siem-sca/src/check.rs`
- **Tasks**:
  1. Connect the existing `siem-sca` YAML policy parser to `siem-agent-linux`.
  2. Implement rule evaluation conditions:
     - `c:command` (executing diagnostic commands and matching regex output)
     - `f:file` (file existence, regex content match, permissions)
     - `d:directory` (directory existence and permissions)
     - `p:process` (checking running process names and flags)
  3. Include compliance metadata in findings: CIS ID, title, description, rationale, remediation command, and compliance level.

---

### Phase 5: Docker Container Monitoring Module (`wm_docker`)
- **Objective**: Monitor container events, lifecycle changes, and security events on endpoints running Docker.
- **Reference Files**:
  - `wazuh-4.14.7/src/wazuh_modules/wm_docker.c` (5.5 KB)
- **Target Files**:
  - `crates/siem-agent-linux/src/docker.rs`
- **Tasks**:
  1. Connect to `/var/run/docker.sock` via HTTP-over-Unix-socket.
  2. Stream `/events` endpoint for `container` actions: `create`, `start`, `stop`, `die`, `kill`, `pause`.
  3. Enrich events with container ID, image name, and commandline, forwarding as high-priority security telemetry.
  4. Gracefully handle systems where Docker is not installed or the socket is not accessible.

---

## 4. Quality Assurance & Safe Execution Protocol

1. **Strict Zero-Regression Guarantee**:
   - `siem-api` and manager endpoints remain untouched.
   - Windows build (`siem-winagent`) and Windows services remain untouched.
   - Existing VM agent connection (`siem-agent-linux` on Linux VM) remains operational throughout.
2. **Compile-Time Platform Isolation**:
   - All Linux kernel-specific APIs (`inotify`, `audit`, Unix domain sockets) use `#[cfg(target_os = "linux")]` with clean fallback or abstraction stubs for Windows cross-checking.
3. **Phase-by-Phase Validation**:
   - Run `cargo check --workspace` after every phase.
   - Run unit tests for each new parser and engine component.
   - Generate release binaries and verify live event stream in the SIEM Web UI.
