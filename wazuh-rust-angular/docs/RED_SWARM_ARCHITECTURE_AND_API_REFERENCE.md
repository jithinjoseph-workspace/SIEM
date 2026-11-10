# Continuous Red Agent Swarm & Perpetual Purple-Team Engine (`siem-redswarm`)
## Technical Architecture, Module Specifications & API Reference

---

## 1. Executive Summary & Core Principles

The **Continuous Red Agent Swarm (`siem-redswarm`)** transforms the next-generation Wazuh-Rust SIEM into a perpetual purple-team engine. It continuously evaluates detection posture against the MITRE ATT&CK framework, identifies coverage gaps in real time, and synthesizes candidate detection rules with human-in-the-loop governance.

### Non-Negotiable Operational Principles

| Principle | Enforcement Mechanism |
| :--- | :--- |
| **Safety First** | The default execution mode across all campaigns is strictly `SafeTelemetryOnly`. Zero endpoints execute live shell commands by default. |
| **Target Containment** | Live execution (`ControlledLive`) is strictly restricted to endpoints tagged with `lab` or `redteam-allowed`. Unapproved endpoints reject command execution. |
| **Guaranteed Rollback & Fail-Safe** | Every live technique in the catalog must specify an idempotent `cleanup` command payload that executes immediately after the probe. If cleanup fails, the execution is marked failed and the global kill-switch is engaged automatically. |
| **Never Auto-Deploy Rules** | Synthesized Wazuh XML detection rules are staged in a `PendingApproval` state. Rules are never promoted to production rulesets without explicit human analyst approval. |
| **Emergency Control & Concurrency** | A global atomic kill-switch halts all operations instantaneously. Max concurrent live executions and per-agent cooldown limits (300s) prevent endpoint fatigue. |
| **Multi-Signal Verification** | Verifier polls across configurable retries correlating MITRE ID, detection indicators, and related rule groups, capturing the exact matching or closest candidate alert. |
| **Rule Lifecycle & Rollback** | Approved rules are dynamically injected into the running correlation engine without restart, with full rollback support (`POST /api/v1/redswarm/rules/:id/rollback`). |

---

## 2. Architectural Blueprint

```
                      ┌────────────────────────────────────────┐
                      │    ndr-ui / Analyst Purple Console     │
                      │  (HUD, Matrix, Gaps, 1-Click Approval)  │
                      └───────────────────┬────────────────────┘
                                          │ HTTP REST API
                                          ▼
                      ┌────────────────────────────────────────┐
                      │      siem-api (Axum SIEM Server)       │
                      │  • State: Arc<RedSwarmService>         │
                      │  • Fleet Provider: Active & Enrolled   │
                      └───────────────────┬────────────────────┘
                                          │
            ┌─────────────────────────────┴─────────────────────────────┐
            ▼                                                           ▼
┌───────────────────────┐                                   ┌───────────────────────┐
│ SafeTelemetryOnly     │                                   │ ControlledLive        │
│ • Zero agent impact   │                                   │ • Strict tag check    │
│ • Raw event injection │                                   │ • Active-response cmd │
│ • Target OS matching  │                                   │ • Guaranteed cleanup  │
└───────────┬───────────┘                                   └───────────┬───────────┘
            │                                                           │
            └─────────────────────────────┬─────────────────────────────┘
                                          ▼
                      ┌────────────────────────────────────────┐
                      │          PurpleLoopVerifier            │
                      │  Correlates Alerts in 15s Window       │
                      └───────────────────┬────────────────────┘
                                          │
                  ┌───────────────────────┴───────────────────────┐
                  ▼                                               ▼
         [Verdict: Defended]                             [Verdict: HardGap/SoftGap]
                  │                                               │
                  ▼                                               ▼
       Metrics Heatmap Updated                       ┌─────────────────────────┐
                                                     │    RuleSynthesizer      │
                                                     │ • Generates Wazuh XML   │
                                                     │ • Stages PendingApproval│
                                                     └────────────┬────────────┘
                                                                  │
                                                                  ▼
                                                     ┌─────────────────────────┐
                                                     │  Analyst Human Approval │
                                                     │ • Appends to XML ruleset│
                                                     └─────────────────────────┘
```

---

## 3. Data Models (`siem-redswarm::models`)

All structs and enums are located in [crates/siem-redswarm/src/models.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/models.rs).

### 3.1. `SwarmExecutionMode`
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SwarmExecutionMode {
    SafeTelemetryOnly, // Default: Injects telemetry into correlation engine. Zero agent impact.
    ControlledLive,    // Opt-in: Runs reversible commands on tagged endpoints (lab/redteam-allowed).
    FullLive,          // Restricted: Scheduled, high-privilege live testing with multi-analyst ROE.
}
```

### 3.2. `RiskLevel`
```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskLevel {
    Low,      // Score: 1 - Minimal risk read-only queries or benign probes.
    Medium,   // Score: 5 - Temporary artifacts or standard persistence keys with immediate rollback.
    High,     // Score: 10 - Elevated service probes or process injection tests.
    Critical, // Score: 25 - Destructive tests; banned in automated continuous testing.
}
```

### 3.3. `CommandPayload`
Represents an executable command payload with timeout and privilege requirements.
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandPayload {
    pub command: String,          // Shell or PowerShell command string
    pub timeout_seconds: u32,      // Max execution duration before SIGKILL
    pub requires_elevation: bool,  // Whether root / Administrator privileges are mandatory
}
```

### 3.4. `AttackTechnique`
Defines an ATT&CK technique catalog item with its simulation artifacts and expectations.
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttackTechnique {
    pub id: String,                         // e.g. "T1059.001"
    pub name: String,                       // e.g. "PowerShell Encoded Command Execution"
    pub tactic: String,                     // e.g. "Execution"
    pub platforms: Vec<String>,             // e.g. ["windows"]
    pub risk_level: RiskLevel,              // Operational risk classification
    pub reversible: bool,                   // Whether a cleanup procedure exists
    pub cleanup_guaranteed: bool,           // Guaranteed rollback flag
    pub execution: CommandPayload,          // Attack payload
    pub cleanup: CommandPayload,            // Cleanup / rollback payload
    pub expected_telemetry: Vec<String>,    // Substrings expected in raw logs
    pub expected_mitre_ids: Vec<String>,    // MITRE technique IDs that should trigger
    pub banned_in_controlled_live: bool,    // Forbidden for live execution (e.g. log clearing)
    pub sample_raw_logs: Vec<String>,       // Telemetry for SafeTelemetryOnly mode
}
```

### 3.5. `DetectionVerdict` & `VerificationEvidence`
Output of the purple-team verification phase.
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DetectionVerdict {
    Defended,  // SIEM alert fired matching technique ID, IOCs, and time window
    SoftGap,   // Event was ingested and parsed, but no alert triggered
    HardGap,   // No alerts, no detections, event was entirely missed
    Blocked,   // Blocked preemptively by SafetyGatekeeper
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationEvidence {
    pub verdict: DetectionVerdict,
    pub matched_alert_id: Option<String>,
    pub matched_rule_id: Option<u32>,
    pub matched_rule_description: Option<String>,
    pub reason: String,
    pub latency_ms: u64,
}
```

### 3.6. `DraftRuleStatus` & `SynthesizedRuleDraft`
Represents candidate detection rules synthesized upon discovering detection gaps.
```rust
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftRuleStatus {
    PendingApproval,     // Staged: Awaiting SOC analyst inspection
    ApprovedAndDeployed, // Analyst approved: Committed to Wazuh custom XML ruleset
    Rejected,            // Discarded by analyst
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SynthesizedRuleDraft {
    pub id: Uuid,
    pub rule_id: u32,
    pub technique_id: String,
    pub technique_name: String,
    pub rule_xml: String,
    pub explanation: String,
    pub logtest_validated: bool,
    pub status: DraftRuleStatus,
    pub created_at: DateTime<Utc>,
    pub approved_at: Option<DateTime<Utc>>,
}
```

### 3.7. `ExecutionRecord`
Immutable record persisted in the audit store for every attack round.
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionRecord {
    pub id: Uuid,
    pub campaign_id: String,
    pub tenant_id: String,
    pub timestamp: DateTime<Utc>,
    pub technique_id: String,
    pub technique_name: String,
    pub tactic: String,
    pub mode: SwarmExecutionMode,
    pub target_agent_id: String,
    pub target_agent_name: String,
    pub target_agent_ip: String,
    pub target_os: String,
    pub execution_success: bool,
    pub execution_output: String,
    pub cleanup_status: CleanupStatus,
    pub cleanup_output: Option<String>,
    pub verification: VerificationEvidence,
    pub draft_rule: Option<SynthesizedRuleDraft>,
}
```

### 3.8. `FleetAgentTarget`
Dynamically resolved target endpoint information queried from the live fleet.
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAgentTarget {
    pub id: String,
    pub name: String,
    pub ip: String,
    pub os_type: String, // "windows" | "linux" | "macos"
    pub status: String,  // "active" | "disconnected" | "pending"
    pub tags: Vec<String>,
}
```

---

## 4. Subsystem Deep-Dive

### 4.1. Curated ATT&CK Catalog (`catalog.rs`)
Location: [crates/siem-redswarm/src/catalog.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/catalog.rs)

The catalog maintains curated techniques with strict platform constraints and reversible cleanup routines:

| Technique ID | Name | Platforms | Risk | Reversible? | Cleanup Payload |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `T1110.001` | SSH Password Guessing | Linux | Low | Yes | `true` (no-op) |
| `T1059.001` | PowerShell Encoded Command | Windows | Low | Yes | `true` (no-op) |
| `T1547.001` | Registry Run Keys Modification | Windows | Medium | Yes | `reg delete HKCU\...\Run /v ProVigil... /f` |
| `T1082` | System Information Discovery | Linux, Windows, macOS | Low | Yes | `true` (no-op) |
| `T1003.008` | Access to `/etc/shadow` | Linux | Medium | Yes | `true` (no-op) |
| `T1070.001` | Clear Windows Event Logs | Windows | High | **No** (Banned in live mode) | N/A |
| `T1543.003` | Windows Service Creation | Windows | Medium | Yes | `sc.exe delete ProVigilRedSwarm` |
| `T1053.003` | Cron Job Creation Probe | Linux | Low | Yes | `rm -f /tmp/redswarm_cron_probe` |
| `T1562.001` | Disable Security Tools Probe | Linux, Windows | Medium | Yes | `true` |
| `T1036.005` | Masquerading Process Probe | Linux, Windows | Low | Yes | `del /f C:\Temp\svchost_fake.exe` |

### 4.2. Safety Gatekeeper (`safety.rs`)
Location: [crates/siem-redswarm/src/safety.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/safety.rs)

- **Atomic Kill-Switch**: `static KILL_SWITCH: AtomicBool = AtomicBool::new(false);`
  - When set, all in-progress and scheduled executions abort immediately.
- **Target Tag Enforcement**:
  - In `ControlledLive` mode, endpoints **must** contain either `"lab"` or `"redteam-allowed"` in their tag list. Otherwise, execution is rejected.
- **Rolling Risk Budget**:
  - Tracks points used in the current 60-minute window (default: 50 points/hour).
  - Techniques consume points (`Low`=1, `Medium`=5, `High`=10, `Critical`=25). Exceeding budget halts live executions until the window resets.

### 4.3. Swarm Executor (`executor.rs`)
Location: [crates/siem-redswarm/src/executor.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/executor.rs)

1. **`SafeTelemetryOnly` Pipeline**:
   - Synthesizes `RawEvent` objects using authentic sample logs tagged with `redswarm_simulation: true`.
   - Injects them directly into `AnalysisEngine::process_event(ev, target_name, target_ip)`.
   - Creates **zero** host artifacts or processes.
2. **`ControlledLive` Pipeline**:
   - Validates target tags and ROE with `SafetyGatekeeper::validate_execution()`.
   - Dispatches `technique.execution.command` to the agent via active-response RPC.
   - Immediately dispatches `technique.cleanup.command` to guarantee rollback.
   - Records command output, cleanup status, and execution duration.

### 4.4. Purple-Loop Verifier (`verifier.rs`)
Location: [crates/siem-redswarm/src/verifier.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/verifier.rs)

Verifies whether SIEM rules caught the attack within a correlation window (15 seconds):
- **Criterion 1 (MITRE ID)**: Checks if any triggered alert has `mitre.id` or `mitre.technique` matching `technique.id` or `technique.expected_mitre_ids`.
- **Criterion 2 (IOC Match)**: Scans alert `full_log`, `rule.description`, and `rule.groups` for expected keywords (e.g. `powershell.exe`, `-EncodedCommand`, `CurrentVersion\Run`).
- **Verdict Resolution**:
  - Matched alert ➔ `DetectionVerdict::Defended`
  - Unmatched ➔ `DetectionVerdict::HardGap`
  - Calculates alert latency in milliseconds.

### 4.5. Rule Synthesizer (`synthesizer.rs`)
Location: [crates/siem-redswarm/src/synthesizer.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/synthesizer.rs)

Generates compliant Wazuh XML detection rules for detected gaps:
- Generates a custom rule ID in the 100000–999999 range.
- Escapes special characters for regex matching.
- Emits standard Wazuh XML syntax (`<group>`, `<rule id="..." level="...">`, `<match>`, `<mitre>`, `<description>`).
- Validates the rule against simulated `wazuh-logtest` patterns.
- Staged in `DraftRuleStatus::PendingApproval`.

### 4.6. Service & Dynamic Fleet Matching (`service.rs`)
Location: [crates/siem-redswarm/src/service.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-redswarm/src/service.rs)

- Autonomous background loop ticks every 60 seconds.
- Queries `get_agents_fn()` to discover the real monitored fleet.
- Dynamically derives available operating systems (`fleet_platforms`).
- Filters catalog techniques to those that match the **actual connected endpoints**.
- Binds attack telemetry and executions directly to the real agent ID, name, IP, and OS.
- Safely skips techniques for platforms not currently present in the fleet.

---

## 5. SIEM API Endpoint Specification (`siem-api`)

All endpoints are registered under `/api/v1/redswarm/*` in [crates/siem-api/src/main.rs](file:///e:/wazhu-Siem-code/wazuh-rust-angular/backend-rust/crates/siem-api/src/main.rs):

### 5.1. `GET /api/v1/redswarm/status`
Returns full engine health, kill-switch state, coverage stats, and risk budget usage.
- **Response `200 OK`**:
```json
{
  "running": true,
  "kill_switch_active": false,
  "default_mode": "safe_telemetry_only",
  "active_campaigns_count": 1,
  "attacks_last_24h": 42,
  "defense_rate_percent": 88.1,
  "open_gaps_count": 5,
  "approved_rules_count": 3,
  "current_risk_budget_used": 6,
  "max_risk_budget_per_hour": 50
}
```

### 5.2. `GET /api/v1/redswarm/campaigns`
Lists all configured swarm campaigns.

### 5.3. `POST /api/v1/redswarm/campaigns`
Creates or updates a campaign.
- **Request Body**:
```json
{
  "id": "continuous-mitre-safe",
  "name": "Continuous Windows MITRE Simulation",
  "description": "Continuous telemetry injection for Windows endpoints",
  "mode": "safe_telemetry_only",
  "enabled": true,
  "interval_seconds": 60,
  "roe": {
    "allowed_agent_ids": ["016", "017"],
    "allowed_tags": ["lab", "redteam-allowed"],
    "banned_technique_ids": ["T1529"],
    "max_risk_level": "medium"
  }
}
```

### 5.4. `POST /api/v1/redswarm/campaigns/:id/toggle`
Enables or disables an automated campaign.

### 5.5. `POST /api/v1/redswarm/run-once`
Executes an immediate single round on demand. If `target_agent_id` is omitted, the API dynamically selects the first active agent in the fleet matching the technique's platform.
- **Request Body**:
```json
{
  "technique_id": "T1059.001",
  "target_agent_id": null,
  "mode": "safe_telemetry_only"
}
```
- **Response `200 OK`**: Returns the complete `ExecutionRecord`.

### 5.6. `GET /api/v1/redswarm/history`
Returns the recent execution history ring buffer (last 100–500 executions).

### 5.7. `GET /api/v1/redswarm/gaps`
Returns all open detection gaps with their staged draft rules awaiting approval.

### 5.8. `POST /api/v1/redswarm/gaps/:id/apply-rule`
Approves a synthesized rule, changes status to `ApprovedAndDeployed`, and appends the rule XML to `data/manager/ruleset/rules/0999-redswarm-synthesized.xml`.

### 5.9. `POST /api/v1/redswarm/kill-switch`
Engages or disengages the global emergency kill-switch.
- **Request Body**:
```json
{ "engage": true }
```

### 5.10. `GET /api/v1/redswarm/heatmap`
Returns the aggregated MITRE ATT&CK coverage heatmap, grouped by tactic with defense percentages.

---

## 6. Frontend Purple-Team Console (`ndr-ui`)

The frontend console is implemented in Angular 19 at [ndr-ui/src/pages/analyst/redswarm/](file:///e:/wazhu-Siem-code/wazuh-rust-angular/ndr-ui/src/pages/analyst/redswarm/).

### Key Views & Components:
1. **Status HUD**: Real-time cards for Defense Rate, Attacks in 24h, Open Gaps, Risk Budget, and Emergency Kill-Switch.
2. **Interactive Run-Once Bar**: Select any MITRE technique, target agent, and execution mode with instant trigger and real-time result banner.
3. **Execution Live Feed**: Tabular stream with colored verdict badges (`Defended` in green, `SoftGap` in amber, `HardGap` in red), latency, and target info.
4. **Detection Gap Triage & Rule Staging**: Dedicated review cards for each gap showing evasion details, generated XML, logtest verification status, and a **"Stage & Approve Rule"** action.
5. **MITRE ATT&CK Matrix Heatmap**: Visual matrix organized by MITRE tactics (Execution, Persistence, Defense Evasion, Credential Access, Discovery) with coverage percentages and technique badges.

---

## 7. Production Operations Runbook

### Safe Deployment Checklist
1. Ensure the default mode is set to `SafeTelemetryOnly`.
2. Do not tag production endpoints with `redteam-allowed` unless authorized for controlled live testing.
3. When using `ControlledLive`, verify that the endpoints run the `siem-agent` service with active-response enabled.
4. Review draft rules in the Purple Console before approving. Approved rules are stored in `0999-redswarm-synthesized.xml` and loaded by the correlation engine.
5. In case of unexpected behavior or network disruption, immediately click **"ENGAGE KILL SWITCH"** in the UI or call `POST /api/v1/redswarm/kill-switch { "engage": true }`.
