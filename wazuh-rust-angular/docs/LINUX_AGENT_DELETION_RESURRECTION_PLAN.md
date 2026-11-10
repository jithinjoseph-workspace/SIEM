# Linux Agent Deletion & Resurrection Root Cause Analysis and Solution Plan

## Executive Summary

When a Linux agent (e.g. `linux-node-d322`, ID `037`) is deleted via the Provigil SIEM UI, the manager correctly deletes the agent from the registry and active fleet. However, upon page reload 15–30 seconds later, the agent reappears as **Active** with a new ID (e.g. `038`). 

In contrast, the **Windows agent** (`win-node-7a5e`, ID `039`) never reappears after deletion and functions flawlessly.

This document details the exact root cause uncovered by analyzing ClickHouse records, the Windows agent implementation, and the Linux agent lifecycle, and outlines the solution to permanently fix the issue.

---

## 1. Empirical Evidence (ClickHouse Agent Registry)

Querying `ndr.agent_registry FINAL` proves the exact timeline:

| Agent ID | Agent Name | Tenant | Deleted | Disabled | Enrolled At (UTC) | Updated At (UTC) | Action |
|---|---|---|---|---|---|---|---|
| **037** | `linux-node-d322` | `code` | **1** | **1** | 16:01:32 | 16:03:24 | User clicked Delete |
| **038** | `linux-node-d322` | `code` | **0** | **0** | **16:03:38** | 16:03:38 | **Auto-enrolled 14 seconds later!** |
| **039** | `win-node-7a5e` | `code` | **1** | **1** | 16:07:41 | 16:08:58 | User clicked Delete (Never re-enrolled) |

---

## 2. Root Cause Analysis: Windows vs. Linux Agent Logic

### A. Why the Windows Agent Works Correctly
1. **Single-Shot Enrollment at Installation**:
   - The Windows installer script (`install-${agentName}.bat` or PowerShell) runs `POST /api/v1/agents/enroll` **once** during installation.
   - It writes `C:\Program Files (x86)\ossec-agent\client.keys` and installs the Windows service `WazuhSvc`.
2. **No Autonomous Self-Re-enrollment**:
   - The Windows agent binary (`wazuh-agent.exe` from `siem-winagent`) **never deletes or renames its local `client.keys`**.
   - When the agent is deleted on the manager:
     - The manager archives its key and adds the ID (`039`) to `state.deleted_agents`.
     - The Windows agent continues running, attempts communication using its existing key (`039`), and the manager rejects its packets (HTTP 404 / decryption failure).
     - Because `client.keys` remains on disk with ID `039`, the Windows agent **never enters enrollment logic**.
     - It never calls `POST /api/v1/agents/enroll`, so no new ID is ever issued. The agent remains deleted permanently.

### B. Why the Linux Agent Resurrects
The Linux agent (`siem-agent-linux`) suffers from a **decommission-restart-re-enroll loop**:

1. **Manager Rejection**:
   - The user deletes agent `037` in the UI.
   - The manager sets `037` in `state.deleted_agents` and deletes its database row.
   - The Linux agent's buffer attempts to send an ingest event or poll state; the manager responds with `HTTP 404 NOT_FOUND`.
2. **Flawed Decommission Action**:
   - In `crates/siem-agent-linux/src/buffer.rs` (lines 84–87):
     ```rust
     Ok(res) if res.status() == reqwest::StatusCode::NOT_FOUND => {
         warn!("AgentBuffer: Manager returned 404 NOT FOUND (agent deleted from registry). Executing decommission...");
         lifecycle.set_state(crate::lifecycle::AgentLifecycleState::Decommissioned);
     }
     ```
   - In `crates/siem-agent-linux/src/lifecycle.rs` (`decommission_local`):
     ```rust
     for path in &keys_candidates {
         if path.exists() {
             let archived = path.with_extension("keys.deleted");
             let _ = std::fs::rename(path, &archived); // RENAME client.keys -> client.keys.deleted
         }
     }
     tokio::spawn(async {
         let _ = std::process::Command::new("systemctl").args(["disable", "--now", "wazuh-rust-agent"]).status();
         std::process::exit(0);
     });
     ```
3. **Systemd Unconditional Restart**:
   - In `/etc/systemd/system/wazuh-rust-agent.service` (line 16):
     ```ini
     Restart=always
     RestartSec=10
     ```
   - A process cannot reliably disable itself while in the middle of executing. Systemd intercepts the `exit(0)` and, because `Restart=always` is configured, automatically restarts the service after 10 seconds.
4. **Blind Re-Enrollment on Startup**:
   - When `siem-agent-linux` starts up again, `ClientAgent::load_config()` checks for `/var/ossec/etc/client.keys`.
   - Because step 2 renamed `client.keys` to `client.keys.deleted`, **`client.keys` does not exist**.
   - `config.agent_id` is empty (`""`).
   - In `crates/siem-agent-linux/src/main.rs` (lines 74–82):
     ```rust
     // No identity yet: enroll with the manager and keep the id in client.keys.
     if config.agent_id.is_empty() {
         let e = enroll::enroll_until_done(
             &config.manager_url,
             &config.agent_name,
             &config.agent_group,
             "linux",
             config.tenant_key.as_deref(),
         ).await;
     ```
   - The Linux agent assumes it is a brand-new un-enrolled machine, calls `POST /api/v1/agents/enroll` with its hostname (`linux-node-d322`), obtains a brand new ID (`038`), saves a new `client.keys`, and starts streaming events.
5. **UI Reload**:
   - The user refreshes the page in the browser and sees `linux-node-d322` active again with ID `038`.

---

## 3. Implementation Plan

To align the Linux agent with the robust behavior of the Windows agent and prevent resurrection permanently, the following changes will be applied:

### Phase 1: Linux Agent Decommission Guard & Systemd Unit
1. **Prevent Systemd Restart on Decommission**:
   - Update `init/wazuh-rust-agent.service` and `install.sh`:
     - Set `RestartPreventExitStatus=42` in the `[Service]` section.
     - When `decommission_local` runs, exit with code `42` (`std::process::exit(42)`). Systemd will recognize exit status 42 as a permanent stop and will **never** restart the service.
2. **Decommission Marker on Disk**:
   - In `lifecycle.rs`:
     - Create `/var/ossec/etc/.decommissioned` (or `<install_dir>/.decommissioned`) containing the timestamp and agent ID.
     - Keep `client.keys` or inspect `.decommissioned` / `client.keys.deleted`.
3. **Startup Decommission Check**:
   - In `siem-agent-linux/src/main.rs` and `client_agent.rs`:
     - Before invoking `enroll::enroll_until_done()`, check if `.decommissioned` or `client.keys.deleted` exists.
     - If detected:
       ```rust
       if Path::new("/var/ossec/etc/.decommissioned").exists() || Path::new("/var/ossec/etc/client.keys.deleted").exists() {
           tracing::warn!("This endpoint agent was permanently decommissioned by the manager. Exiting cleanly without re-enrolling.");
           std::process::exit(42);
       }
       ```
     - This guarantees that even if the daemon is manually started or restarted, it will **never auto-enroll** as a new agent.

### Phase 2: Manager-Side Enrollment Protection (`siem-api`)
1. **Guard Against Re-enrollment of Deleted Agents**:
   - In `crates/siem-api/src/main.rs` (`post_agent_enroll_handler`):
     - Before generating `next_free_agent_id`, query `ndr.agent_registry` (or in-memory registry) to check if an agent with `name` in `tenant` has `deleted == 1`.
     - If the agent was deleted, reject the enrollment request with `HTTP 403 FORBIDDEN` (`"Agent name has been deleted from this tenant. Contact administrator or deploy with a new unique name."`).
     - This stops rogue or restarting endpoints from creating new IDs if the manager previously marked them as deleted.

### Phase 3: Manager State Notification (`siem-api` & `siem-agent-linux`)
1. **Cooperative Deactivation vs. Deletion**:
   - When deactivated (HTTP 410): Agent pauses collectors and transitions to Dormant state (periodic heartbeat polling via `agent/state`, exactly like the Windows agent `wait_until_active`).
   - When permanently deleted (HTTP 404): Agent writes `.decommissioned`, stops systemd via exit code 42, and never attempts re-enrollment.

---

## 4. Verification Checklist

1. Deploy Linux Agent (`linux-node-...`) and verify Active in UI.
2. Click **Deactivate**:
   - Agent enters `DEACTIVATED AGENTS` table.
   - Linux agent daemon pauses collectors, stops transmitting events, and enters dormant sleep.
3. Click **Reactivate**:
   - Agent returns to Active fleet.
4. Click **Delete Permanently**:
   - Manager removes key, records `deleted = 1` in `agent_registry`.
   - Agent detects 404, writes `.decommissioned`, exits with status 42.
   - Systemd does **not** restart the service.
   - Agent never calls `POST /api/v1/agents/enroll`.
   - Reload browser page after 1 minute: active fleet remains clean with 0 resurrected agents.
