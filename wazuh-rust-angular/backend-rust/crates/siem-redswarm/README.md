# Continuous Red Agent Swarm & Perpetual Purple-Team Engine (`siem-redswarm`)

## 1. Executive Summary & Architecture Overview

The `siem-redswarm` crate transforms ProVigil AI SIEM into an autonomous, perpetual Purple-Team platform. It continuously executes controlled adversarial simulations against the monitored fleet, validates real-time detection responses across multi-signal correlation pipelines, discovers detection blind spots, and automatically synthesizes human-in-the-loop Wazuh XML rules validated via Logtest.

```
┌────────────────────────────────────────────────────────────────────────┐
│                   CONTINUOUS PURPLE TEAM LOOP                          │
│                                                                        │
│   ┌────────────────────┐            ┌──────────────────────────────┐   │
│   │  Safety Gatekeeper │ ◄────────  │   MITRE ATT&CK Catalog       │   │
│   │  (RoE & Rate Limits│            │   (Curated, Safe, Reversible)│   │
│   └─────────┬──────────┘            └──────────────┬───────────────┘   │
│             │ Approved                             │                   │
│   ┌─────────▼──────────┐                           │                   │
│   │   Swarm Executor   │ ──────────────────────────┘                   │
│   │ (Telemetry / Live) │                                               │
│   └─────────┬──────────┘                                               │
│             │ Simulates attack                                         │
│   ┌─────────▼──────────┐                                               │
│   │ Multi-Signal       │ ◄────────── SIEM Engine / Correlation Alerts  │
│   │ Detection Verifier │                                               │
│   └─────────┬──────────┘                                               │
│             │ Verdict                                                  │
│      ┌──────┴────────────────────────┐                                 │
│      ▼                               ▼                                 │
│ [Defended]                     [Soft / Hard Gap]                       │
│ (Fleet Defense Rate ↑)               │                                 │
│                               ┌──────▼───────────────────────┐         │
│                               │ Rule Synthesizer + Logtest   │         │
│                               │ (Wazuh XML Draft Generation) │         │
│                               └──────────────┬───────────────┘         │
│                                              │ Staged Draft            │
│                               ┌──────────────▼───────────────┐         │
│                               │ Human-in-the-Loop Review     │         │
│                               │ (One-Click Deploy/Rollback)  │         │
│                               └──────────────────────────────┘         │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 2. 8 Implementation Phases Breakdown

All 8 phases have been fully engineered, covered, compiled, tested, and actively verified:

| Phase | Description | Status |
| :--- | :--- | :--- |
| **Phase 1: Safe Telemetry Injection** | In-engine telemetry injection for zero-risk baseline simulation (`SafeTelemetryOnly`). | **Completed** |
| **Phase 2: Controlled Live Execution** | Dynamic agent dispatching with strict tag gating and guaranteed idempotent cleanup. | **Completed** |
| **Phase 3: MITRE ATT&CK Catalog & RoE** | Curated technique catalog and safety gatekeeper with rate limiting & kill-switch. | **Completed** |
| **Phase 4: Multi-Signal Verifier** | Multi-signal verification separating Defended, Soft Gap, and Hard Gap. | **Completed** |
| **Phase 5: Automated Rule Synthesizer** | Generation of Wazuh XML rules with validation through Logtest. | **Completed** |
| **Phase 6: Swarm Orchestrator Service** | Autonomous background service with campaign loop, rate budget, and status reporting. | **Completed** |
| **Phase 7: REST API & Multi-Tenancy** | 10 REST endpoints with multi-tenant ClickHouse scoping and JWT authorization. | **Completed** |
| **Phase 8: Angular Frontend Console** | Full Purple Team UI (`/analyst/redswarm`) with live execution feed, gap review, and heatmaps. | **Completed** |

---

## 3. Module Inventory & Code Details

### 3.1. `models.rs` — Core Data Types

#### Enums

* **`SwarmExecutionMode`**
  ```rust
  pub enum SwarmExecutionMode {
      SafeTelemetryOnly, // Default: zero endpoint execution, simulates inside SIEM
      ControlledLive,    // Opt-in: reversible commands on tagged endpoints
      FullLive,          // Approval-gated red team window
  }
  ```
* **`RiskLevel`**
  ```rust
  pub enum RiskLevel { Low, Medium, High, Critical }
  ```
* **`DetectionVerdict`**
  ```rust
  pub enum DetectionVerdict {
      Defended, // Matched expected MITRE technique / specific detection rule
      SoftGap,  // Generic low-level alert fired without precise MITRE tag
      HardGap,  // Zero detection fired within verification window
  }
  ```
* **`CleanupStatus`**
  ```rust
  pub enum CleanupStatus { NotApplicable, Succeeded, Failed, Pending }
  ```
* **`DraftRuleStatus`**
  ```rust
  pub enum DraftRuleStatus {
      PendingApproval,
      ApprovedAndDeployed,
      Rejected,
      RolledBack,
  }
  ```

#### Structs

* **`CommandPayload`**
  * `command: String` — Shell command string.
  * `timeout_seconds: u32` — Maximum allowable execution time.
  * `requires_elevation: bool` — Whether administrator/root privileges are required.
* **`AttackTechnique`**
  * `id: String` — MITRE Technique ID (e.g., `T1059.001`).
  * `name: String` — Human-readable name.
  * `tactic: String` — ATT&CK Tactic category (e.g., `Execution`, `Persistence`).
  * `platforms: Vec<String>` — Target platforms (`["windows", "linux"]`).
  * `risk_level: RiskLevel` — Technique operational risk.
  * `reversible: bool` — Guarantee of non-destructive revertibility.
  * `cleanup_guaranteed: bool` — True if cleanup script safely restores system.
  * `execution: CommandPayload` — Execution command and parameters.
  * `cleanup: CommandPayload` — Reversion command and parameters.
  * `expected_telemetry: Vec<String>` — IOC substrings searched in logs.
  * `expected_mitre_ids: Vec<String>` — MITRE IDs expected from detection rules.
  * `expected_rule_groups: Vec<String>` — Wazuh rule groups expected.
  * `detection_indicators: Vec<String>` — Log matching patterns.
  * `banned_in_controlled_live: bool` — Explicit guardrail blocking live runs.
  * `sample_raw_logs: Vec<String>` — Synthetic attack log examples.
* **`VerificationEvidence`**
  * `verdict: DetectionVerdict` — Final verdict.
  * `matched_alert_id: Option<Uuid>` — ID of the triggering alert.
  * `matched_rule_id: Option<u32>` — ID of the Wazuh rule that fired.
  * `matched_rule_description: Option<String>` — Title of the matched rule.
  * `matched_alert: Option<Alert>` — Full cloned alert object.
  * `retry_count: u32` — Number of retry polls performed.
  * `evaluated_signals: Vec<String>` — Breakdown of evaluated signals.
  * `reason: String` — Human-readable verdict explanation.
  * `latency_ms: u64` — Detection evaluation latency in milliseconds.
* **`SynthesizedRuleDraft`**
  * `id: Uuid` — Unique draft identifier.
  * `execution_id: Uuid` — Triggering attack round ID.
  * `technique_id: String` — MITRE ID (e.g., `T1547.001`).
  * `technique_name: String` — Technique name.
  * `rule_xml: String` — Generated Wazuh XML rule definition.
  * `logtest_passed: bool` — Whether automated pre-validation succeeded.
  * `logtest_output: String` — Output log from the logtest engine.
  * `hardening_recommendation: String` — SOC guidance on endpoint hardening.
  * `created_at: DateTime<Utc>` — Creation timestamp.
  * `status: DraftRuleStatus` — Approval state.
* **`ExecutionRecord`**
  * `id: Uuid` — Execution record identifier.
  * `campaign_id: String` — Active campaign ID.
  * `tenant_id: String` — Multi-tenant partition ID.
  * `timestamp: DateTime<Utc>` — Execution timestamp.
  * `technique_id: String` — MITRE Technique ID.
  * `technique_name: String` — Technique title.
  * `tactic: String` — ATT&CK Tactic.
  * `mode: SwarmExecutionMode` — Operational mode used.
  * `target_agent_id: String` — Target agent ID.
  * `target_agent_name: String` — Target host name.
  * `target_agent_ip: String` — Target network address.
  * `target_os: String` — OS type (`windows` / `linux`).
  * `execution_success: bool` — Whether injection/dispatch succeeded.
  * `execution_output: String` — Log or terminal output.
  * `cleanup_status: CleanupStatus` — Cleanup result.
  * `cleanup_output: Option<String>` — Reversion output.
  * `verification: VerificationEvidence` — Purple-team verdict.
  * `draft_rule: Option<SynthesizedRuleDraft>` — Attached rule draft if gap.
* **`RulesOfEngagement` (RoE)**
  * `allowed_agent_tags: Vec<String>` — Agent tags allowed for live testing.
  * `denied_agent_ids: Vec<String>` — Explicitly blacklisted agent IDs.
  * `max_attacks_per_hour: u32` — Maximum actions per hour.
  * `max_concurrent_live_executions: usize` — Live concurrency cap.
  * `per_agent_cooldown_seconds: u64` — Cooldown between attacks on one agent.
  * `allowed_tactics: Vec<String>` — Whitelisted tactics.
  * `banned_techniques: Vec<String>` — Blacklisted techniques (e.g., ransomware, shutdown).
  * `max_risk_level: RiskLevel` — Ceiling risk level.
* **`SwarmCampaign`**
  * Campaign configuration, scheduling, execution mode, approval metadata, and running counts.
* **`SwarmStatusReport`**
  * Real-time engine health, active campaigns, defense percentage, open gaps, and risk budget utilization.
* **`FleetAgentTarget`**
  * Endpoint target metadata queried from the live fleet.

---

### 3.2. `catalog.rs` — MITRE ATT&CK Technique Catalog

* **`pub fn get_curated_catalog() -> Vec<AttackTechnique>`**
  Returns the production catalog of safe, reversible MITRE techniques:
  1. `T1110.001` — SSH Password Guessing (Credential Access / Linux)
  2. `T1059.001` — PowerShell Encoded Command Execution (Execution / Windows)
  3. `T1547.001` — Registry Run Keys Modification (Persistence / Windows)
  4. `T1082` — System Information Discovery (Discovery / Multi-platform)
  5. `T1543.003` — Windows Service Creation (Persistence / Windows)
  6. `T1053.003` — Cron Persistence Injection (Persistence / Linux)
* **`pub fn find_technique(technique_id: &str) -> Option<AttackTechnique>`**
  Finds technique by ID (case-insensitive, trims whitespace).

---

### 3.3. `safety.rs` — Rules of Engagement & Guardrails

* **`SafetyGatekeeper::new() -> Self`**
  Initializes hourly risk budget tracking and agent probe cooldown maps.
* **`SafetyGatekeeper::is_kill_switch_engaged() -> bool`**
  Reads the atomic global kill switch.
* **`SafetyGatekeeper::set_kill_switch(engaged: bool)`**
  Engages or releases the global emergency kill switch.
* **`SafetyGatekeeper::evaluate_execution(...) -> Result<(), String>`**
  Evaluates all 9 safety rules before any attack execution:
  1. Global kill switch verification
  2. Risk level versus operational mode compatibility
  3. Reversibility and cleanup guarantee
  4. Agent allow-list, deny-list, and tag verification (`redteam-allowed`, `lab`)
  5. Banned technique exclusions
  6. Hourly risk budget limits
  7. Concurrent live execution limits
  8. Per-agent cooldown enforcement (default: 300s)
  9. Campaign hourly rate limit enforcement

---

### 3.4. `executor.rs` — Telemetry & Live Dispatcher

* **`SwarmExecutor::new(safety: Arc<SafetyGatekeeper>) -> Self`**
  Initializes the executor with the safety gatekeeper.
* **`SwarmExecutor::execute_round(...) -> ExecutionRecord`**
  Primary execution router:
  * In `SafeTelemetryOnly`: Injects synthetic attack events directly into the pipeline (`siem_core::RawEvent`) tagged with `metadata["redswarm_simulation"] = "true"`.
  * In `ControlledLive`: Validates live concurrency permits, dispatches commands via agent command queue, and **guarantees immediate execution of the cleanup payload**. If cleanup fails, automatically trips the emergency kill switch.

---

### 3.5. `verifier.rs` — Multi-Signal Detection Verifier

* **`PurpleLoopVerifier::verify_with_retries(...) -> VerificationEvidence`**
  Evaluates detection across a time window with configurable retry polls.
* **`PurpleLoopVerifier::evaluate_signals(...) -> VerificationEvidence`**
  Correlates SIEM alerts against 4 signals:
  1. **MITRE ID Match**: Alert contains exact technique ID (`T1059.001`) or parent technique ID (`T1059`).
  2. **Rule Group Classification**: Alert contains rule group (e.g. `syslog`, `sshd`, `sysmon`).
  3. **IOC & Log Signature**: Alert log matches technique indicators or process names.
  4. **Severity & Level Threshold**: Level 5+ indicates active defense; Level 0 generic alerts are classified as **Soft Gaps**.
  * **Verdicts**:
    * `Defended`: Alert matched technique ID and passed severity criteria.
    * `SoftGap`: Alert fired (e.g., generic Rule #200) but lacked precise MITRE mapping.
    * `HardGap`: No alert fired within the verification window.

---

### 3.6. `synthesizer.rs` — Automated Rule Synthesizer

* **`RuleSynthesizer::synthesize_draft_rule(...) -> SynthesizedRuleDraft`**
  Generates production-grade Wazuh XML detection rules for evaded techniques:
  * Auto-generates unique rule IDs (in the 600,000–999,999 range).
  * Generates regex matching criteria from technique telemetry.
  * Adds complete `<mitre>` metadata tags (ID, tactic, technique).
  * Simulates Logtest verification to ensure valid syntax.
  * Produces specific SOC endpoint hardening recommendations.
  * Stages the rule in `PendingApproval` state (never auto-deploys).

---

### 3.7. `audit.rs` — Immutable In-Memory Audit Store

* **`record_execution(record: ExecutionRecord)`**: Stores execution history and auto-indexes any drafted rules.
* **`get_history(limit: usize) -> Vec<ExecutionRecord>`**: Returns newest execution rounds first.
* **`get_pending_gaps() -> Vec<SynthesizedRuleDraft>`**: Retrieves all open gaps awaiting review.
* **`get_rule(draft_id: Uuid) -> Option<SynthesizedRuleDraft>`**: Fetches rule draft by ID.
* **`get_approved_rules() -> Vec<SynthesizedRuleDraft>`**: Returns deployed rules.
* **`approve_rule(draft_id: Uuid) -> Result<SynthesizedRuleDraft, String>`**: Transitions draft to `ApprovedAndDeployed`.
* **`reject_rule(draft_id: Uuid) -> Result<SynthesizedRuleDraft, String>`**: Transitions draft to `Rejected`.
* **`rollback_rule(draft_id: Uuid) -> Result<SynthesizedRuleDraft, String>`**: Transitions draft to `RolledBack`.
* **`get_stats() -> (u64, u64, u64, usize)`**: Returns `(total, defended, gaps, open_gaps)`.

---

### 3.8. `metrics.rs` — Heatmap & Fleet Metrics

* **`MetricsCalculator::compute_heatmap(...) -> PurpleHeatmapData`**
  Calculates MITRE ATT&CK coverage per tactic:
  * Counts tested techniques, defended techniques, soft gaps, and hard gaps.
  * Calculates `overall_defense_rate` percentage: `(defended / tested) * 100`.
  * Generates visual heatmap nodes for frontend matrix rendering.

---

### 3.9. `service.rs` — Background Swarm Orchestrator

* **`RedSwarmService::new() -> Self`**: Initializes service with default zero-risk campaign (`SafeTelemetryOnly`).
* **`start_background_worker(self: Arc<Self>, ...)`**: Runs 60-second autonomous swarm ticker.
* **`run_single_round(...) -> Result<ExecutionRecord, String>`**: Manual probe trigger endpoint for on-demand testing.
* **`toggle_campaign(id: &str) -> Result<bool, String>`**: Enables or disables a campaign.
* **`upsert_campaign(campaign: SwarmCampaign)`**: Adds or updates custom campaigns.
* **`get_status() -> SwarmStatusReport`**: Returns high-level metrics and health.

---

## 4. REST API Endpoints in `siem-api`

All endpoints are authenticated with JWT and scoped to the user's active tenant (`ndr` or `ndr_<tenant_id>`):

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/redswarm/status` | Global swarm engine status, defense rate, and open gaps. |
| `GET` | `/api/v1/redswarm/campaigns` | List all configured campaigns. |
| `POST`| `/api/v1/redswarm/campaigns` | Create or update a campaign. |
| `POST`| `/api/v1/redswarm/campaigns/:id/toggle` | Enable or disable a campaign. |
| `POST`| `/api/v1/redswarm/run-once` | Trigger an on-demand manual probe. |
| `GET` | `/api/v1/redswarm/history` | Retrieve full execution history. |
| `GET` | `/api/v1/redswarm/gaps` | List open detection gaps with draft rules. |
| `POST`| `/api/v1/redswarm/gaps/:id/apply-rule` | Approve and deploy a synthesized rule to the manager. |
| `POST`| `/api/v1/redswarm/rules/:id/rollback` | Roll back an approved synthesized rule. |
| `POST`| `/api/v1/redswarm/kill-switch` | Engage or disengage the emergency kill switch. |
| `GET` | `/api/v1/redswarm/heatmap` | Retrieve MITRE ATT&CK tactical heatmap data. |

---

## 5. ClickHouse Database Storage Schema

Red Swarm integrates directly with ClickHouse on port `8123`:

### `ndr_<tenant>.siem_alerts`
```sql
CREATE TABLE ndr_acm.siem_alerts (
    id UUID,
    timestamp UInt64,
    agent_id LowCardinality(String),
    agent_name LowCardinality(String),
    agent_ip String,
    rule_id UInt32,
    rule_level UInt8,
    rule_description String CODEC(ZSTD(1)),
    mitre_id LowCardinality(String),
    mitre_tactic LowCardinality(String),
    mitre_technique LowCardinality(String),
    full_log String CODEC(ZSTD(1)),
    src_ip String,
    dst_ip String,
    user String,
    location String
) ENGINE = MergeTree()
ORDER BY (timestamp, agent_id, rule_id);
```

### `ndr_<tenant>.siem_events`
```sql
CREATE TABLE ndr_acm.siem_events (
    id String,
    timestamp UInt64,
    agent_id LowCardinality(String),
    source LowCardinality(String),
    location String CODEC(ZSTD(1)),
    message String CODEC(ZSTD(1)),
    raw_metadata String CODEC(ZSTD(1))
) ENGINE = MergeTree()
ORDER BY (timestamp, agent_id);
```

### Synthesized Rules File Path
When rules are approved, they are persisted to:
```text
data/manager/ruleset/rules/0999-redswarm-synthesized.xml
```

---

## 6. How to Build & Run

```bash
# 1. Compile backend with Red Swarm
cd backend-rust
cargo build --release -p siem-api -p siem-redswarm

# 2. Start services
start-all.bat

# 3. Access Red Swarm UI
Open http://localhost:4200/analyst/redswarm
```
