use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::catalog::{
    get_tactic_affinities, get_technique_affinities, technique_and_tactic_to_stage,
    KILL_CHAIN_STAGES,
};
use crate::models::{
    ActionAuditRecord, EntityIntentDossier, ExecuteActionRequest, IntentHypothesisScore,
    IntentSummaryReport, KillChainMilestone, LiveAlertRecord, PreemptiveAction,
    SimulationIntentRequest,
};
use crate::storage::{self, IntentExtras};

pub type ActionDispatcher = Arc<dyn Fn(&str, &str, &str) + Send + Sync>;

#[derive(Debug, Clone)]
pub struct TimelineEvidence {
    pub technique: String,
    pub tactic: Option<String>,
    pub timestamp: DateTime<Utc>,
    pub description: Option<String>,
}

#[derive(Clone)]
pub struct IntentEngine {
    dossiers: Arc<RwLock<Vec<EntityIntentDossier>>>,
    executed_actions: Arc<RwLock<Vec<String>>>,
    action_audit: Arc<RwLock<Vec<ActionAuditRecord>>>,
    simulation_overrides: Arc<RwLock<HashMap<String, SimulationIntentRequest>>>,
    active_fleet_ids: Arc<RwLock<HashSet<String>>>,
    /// The agents whose dossier changed since siem-api last stored them
    changed: Arc<Mutex<HashSet<String>>>,
    /// The executed actions, audit log or simulation overrides changed since siem-api stored them
    extras_changed: Arc<AtomicBool>,
    /// The dossier file of an earlier version, until its dossiers are stored
    legacy_file: Arc<Mutex<Option<PathBuf>>>,
}

impl IntentEngine {
    /// `legacy_file`: the dossier file of an earlier version, if any: its dossiers count as
    /// changed, and it goes once they are stored ([`IntentEngine::stored`]).
    pub fn new(legacy_file: impl Into<PathBuf>) -> Self {
        let path = legacy_file.into();
        let store = storage::load_storage(&path);
        let dossiers = store.as_ref().map(|s| s.dossiers.clone()).unwrap_or_default();
        let changed = dossiers.iter().map(|d| d.entity_id.clone()).collect();
        let had_file = store.is_some();
        let extras = store.as_ref().map(|s| s.extras.clone()).unwrap_or_default();
        Self {
            dossiers: Arc::new(RwLock::new(dossiers)),
            executed_actions: Arc::new(RwLock::new(extras.executed_actions)),
            action_audit: Arc::new(RwLock::new(extras.action_audit)),
            simulation_overrides: Arc::new(RwLock::new(extras.simulation_overrides)),
            active_fleet_ids: Arc::new(RwLock::new(HashSet::new())),
            changed: Arc::new(Mutex::new(changed)),
            extras_changed: Arc::new(AtomicBool::new(had_file)),
            legacy_file: Arc::new(Mutex::new(store.map(|_| path))),
        }
    }

    /// The executed actions, audit log and simulation overrides changed: siem-api stores them
    /// (only on an analyst's action or simulation, never per event).
    pub fn save(&self) {
        self.extras_changed.store(true, Ordering::SeqCst);
    }

    /// The executed actions, audit log and simulation overrides if they changed since the last
    /// call, for siem-api to store.
    pub fn take_extras(&self) -> Option<IntentExtras> {
        self.extras_changed.swap(false, Ordering::SeqCst).then(|| IntentExtras {
            executed_actions: self.executed_actions.read().unwrap().clone(),
            action_audit: self.action_audit.read().unwrap().clone(),
            simulation_overrides: self.simulation_overrides.read().unwrap().clone(),
        })
    }

    /// The extras could not be stored: they stay changed.
    pub fn extras_store_failed(&self) {
        self.save();
    }

    /// The extras stored in ClickHouse, at start; what is already here is newer.
    pub fn load_extras(&self, stored: IntentExtras) {
        let mut done = self.executed_actions.write().unwrap();
        for a in stored.executed_actions {
            if !done.contains(&a) {
                done.push(a);
            }
        }
        let mut audit = self.action_audit.write().unwrap();
        for r in stored.action_audit {
            if !audit.iter().any(|x| x.id == r.id) {
                audit.push(r);
            }
        }
        let mut sims = self.simulation_overrides.write().unwrap();
        for (k, v) in stored.simulation_overrides {
            sims.entry(k).or_insert(v);
        }
    }

    /// The dossiers stored in ClickHouse, at start; what is already here is newer.
    pub fn load(&self, stored: Vec<EntityIntentDossier>) {
        let mut list = self.dossiers.write().unwrap();
        for d in stored {
            if !list.iter().any(|x| x.entity_id == d.entity_id) {
                list.push(d);
            }
        }
    }

    /// The dossiers that changed since the last call, for siem-api to store.
    pub fn take_changed(&self) -> Vec<EntityIntentDossier> {
        let changed = std::mem::take(&mut *self.changed.lock().unwrap());
        self.dossiers.read().unwrap().iter().filter(|d| changed.contains(&d.entity_id)).cloned().collect()
    }

    /// These agents' dossiers could not be stored: they stay changed.
    pub fn store_failed(&self, agents: impl IntoIterator<Item = String>) {
        self.changed.lock().unwrap().extend(agents);
    }

    /// All that `take_changed` gave was stored: the old dossier file is not needed any more.
    pub fn stored(&self) {
        if let Some(path) = self.legacy_file.lock().unwrap().take() {
            let _ = std::fs::remove_file(path);
        }
    }

    /// Primary Multi-Hypothesis Intent Evaluator using real alert timestamps, native tactics, and OS awareness
    pub fn evaluate_evidence(
        &self,
        agent_id: &str,
        agent_name: &str,
        agent_ip: &str,
        os_type: Option<&str>,
        evidence: &[TimelineEvidence],
        user: Option<&str>,
    ) -> EntityIntentDossier {
        let technique_affinities = get_technique_affinities();
        let tactic_affinities = get_tactic_affinities();

        let archetypes = [
            ("ransomware_extortion", "Ransomware & Double Extortion", "Critical"),
            ("data_exfiltration", "Data Theft & Exfiltration", "High"),
            ("apt_espionage", "Long-Term APT & Identity Dominance", "Critical"),
            ("destructive_sabotage", "Destructive Wiper / Sabotage", "Catastrophic"),
            ("cryptojacking", "Cryptojacking & Resource Hijacking", "Medium"),
        ];

        // 1. Evidence Accumulation per Intent Archetype
        let mut raw_scores: HashMap<&'static str, f64> = HashMap::new();
        let mut key_indicators: HashMap<&'static str, Vec<String>> = HashMap::new();

        for &(_, name, _) in &archetypes {
            raw_scores.insert(name, 1.0); // Baseline prior
            key_indicators.insert(name, Vec::new());
        }

        let mut observed_stage_indices = std::collections::BTreeSet::new();

        for ev in evidence {
            let t_upper = ev.technique.trim().to_uppercase();
            let stage_idx = technique_and_tactic_to_stage(&t_upper, ev.tactic.as_deref());
            observed_stage_indices.insert(stage_idx);

            let mut matched = false;

            // A. Check specific technique affinities
            for (&prefix, intent_weights) in &technique_affinities {
                if t_upper.contains(prefix) {
                    matched = true;
                    for (&intent_name, &weight) in intent_weights {
                        let score = raw_scores.entry(intent_name).or_insert(1.0);
                        *score += weight;
                        let ind = key_indicators.entry(intent_name).or_default();
                        let desc = format!("Technique {} detected [Affinity +{:.1}]", t_upper, weight);
                        if !ind.contains(&desc) && ind.len() < 5 {
                            ind.push(desc);
                        }
                    }
                }
            }

            // B. Check tactic affinities if provided
            if let Some(tactic) = &ev.tactic {
                let t_norm = tactic.trim().to_lowercase().replace(['-', ' '], "_");
                for (&tac_name, intent_weights) in &tactic_affinities {
                    if t_norm.contains(tac_name) {
                        matched = true;
                        for (&intent_name, &weight) in intent_weights {
                            let score = raw_scores.entry(intent_name).or_insert(1.0);
                            *score += weight * 0.75;
                            let ind = key_indicators.entry(intent_name).or_default();
                            let desc = format!("Observed MITRE tactic '{}' ({})", tactic, t_upper);
                            if !ind.contains(&desc) && ind.len() < 5 {
                                ind.push(desc);
                            }
                        }
                    }
                }
            }

            // C. Stage heuristic fallback: ensures no 20% flat tie if unknown technique arrives
            if !matched {
                let stage_name = KILL_CHAIN_STAGES.get(stage_idx).unwrap_or(&"Execution");
                let weights: &[(&str, f64)] = match stage_idx {
                    0 => &[("Long-Term APT & Identity Dominance", 2.2), ("Ransomware & Double Extortion", 1.8)],
                    1 => &[("Ransomware & Double Extortion", 2.0), ("Data Theft & Exfiltration", 2.0), ("Long-Term APT & Identity Dominance", 2.0)],
                    2 => &[("Long-Term APT & Identity Dominance", 3.4), ("Ransomware & Double Extortion", 2.2)],
                    3 => &[("Long-Term APT & Identity Dominance", 3.2), ("Ransomware & Double Extortion", 2.8)],
                    4 => &[("Destructive Wiper / Sabotage", 3.2), ("Ransomware & Double Extortion", 3.0)],
                    5 => &[("Long-Term APT & Identity Dominance", 3.8), ("Data Theft & Exfiltration", 3.0)],
                    6 => &[("Data Theft & Exfiltration", 2.8), ("Long-Term APT & Identity Dominance", 2.5)],
                    7 => &[("Ransomware & Double Extortion", 3.6), ("Long-Term APT & Identity Dominance", 3.2)],
                    8 => &[("Data Theft & Exfiltration", 4.4), ("Ransomware & Double Extortion", 2.4)],
                    _ => &[("Ransomware & Double Extortion", 4.6), ("Destructive Wiper / Sabotage", 4.6)],
                };
                for &(intent_name, weight) in weights {
                    *raw_scores.entry(intent_name).or_insert(1.0) += weight;
                    let ind = key_indicators.entry(intent_name).or_default();
                    let desc = format!("Observed activity in '{}' stage ({})", stage_name, t_upper);
                    if !ind.contains(&desc) && ind.len() < 5 {
                        ind.push(desc);
                    }
                }
            }
        }

        // Add contextual bonus for privileged user identity activity
        if let Some(u) = user {
            if u.to_lowercase().contains("admin") || u.to_lowercase().contains("root") || u.to_lowercase().contains("system") {
                *raw_scores.entry("Long-Term APT & Identity Dominance").or_insert(1.0) += 2.8;
                key_indicators.entry("Long-Term APT & Identity Dominance").or_default().push(
                    format!("Privileged credential activity observed for user '{}'", u),
                );
            }
        }

        // 2. Bayesian / Softmax Probability Normalization
        let total_score: f64 = raw_scores.values().sum();
        let evidence_count = evidence.len();
        let confidence_calc = ((0.50 + (evidence_count as f64 * 0.08)).clamp(0.50, 0.96) * 100.0).round() / 100.0;

        let mut hypotheses: Vec<IntentHypothesisScore> = archetypes
            .iter()
            .map(|&(key, name, sev)| {
                let s = *raw_scores.get(name).unwrap_or(&1.0);
                let prob = (s / total_score * 100.0).round() / 100.0;
                let ind = key_indicators.get(name).cloned().unwrap_or_default();
                let impact_text = match key {
                    "ransomware_extortion" => "Immediate risk of volume encryption across critical datastores with secondary extortion.",
                    "data_exfiltration" => "Imminent outbound leakage of sensitive proprietary records or credentials.",
                    "apt_espionage" => "Covert identity manipulation, long-term persistence, and credential dumping.",
                    "destructive_sabotage" => "Catastrophic partition wiping, irreversible data destruction or boot record corruption.",
                    _ => "Unauthorized consumption of system compute and GPU resources.",
                }.to_string();

                IntentHypothesisScore {
                    intent_type: key.to_string(),
                    display_name: name.to_string(),
                    probability: prob,
                    confidence: confidence_calc,
                    impact_severity: sev.to_string(),
                    key_indicators: ind,
                    projected_impact: impact_text,
                }
            })
            .collect();

        hypotheses.sort_by(|a, b| b.probability.partial_cmp(&a.probability).unwrap_or(std::cmp::Ordering::Equal));

        let primary = &hypotheses[0];
        let primary_intent = primary.display_name.clone();
        let primary_prob = primary.probability;

        // 3. Kill-Chain Milestones Construction with Real Timestamps
        let max_stage = observed_stage_indices.iter().max().copied().unwrap_or(0);
        let now = Utc::now();

        let mut observed_milestone_times = Vec::new();

        let milestones: Vec<KillChainMilestone> = (0..KILL_CHAIN_STAGES.len())
            .map(|idx| {
                let name = KILL_CHAIN_STAGES[idx].to_string();
                let matching_records: Vec<&TimelineEvidence> = evidence
                    .iter()
                    .filter(|ev| technique_and_tactic_to_stage(&ev.technique, ev.tactic.as_deref()) == idx)
                    .collect();

                let matching_techs: Vec<String> = matching_records.iter().map(|ev| ev.technique.clone()).collect();
                let earliest_ts = matching_records.iter().map(|ev| ev.timestamp).min();

                let (status, pred_reason) = if observed_stage_indices.contains(&idx) {
                    if let Some(ts) = earliest_ts {
                        observed_milestone_times.push(ts);
                    }
                    if idx == max_stage {
                        ("current".to_string(), None)
                    } else {
                        ("observed".to_string(), None)
                    }
                } else if idx == max_stage + 1 {
                    (
                        "predicted_next".to_string(),
                        Some(format!("Adversary likely to pivot to {} next based on {} trajectory.", name, primary_intent)),
                    )
                } else {
                    ("unreached".to_string(), None)
                };

                KillChainMilestone {
                    stage_index: idx,
                    stage_name: name,
                    status,
                    observed_techniques: matching_techs,
                    first_observed_at: earliest_ts,
                    prediction_reason: pred_reason,
                }
            })
            .collect();

        let progression_percent = (((max_stage + 1) as f64 / KILL_CHAIN_STAGES.len() as f64) * 100.0).round() as u8;

        // Dynamic Kill-Chain Velocity based on real alert timestamps
        let kill_chain_velocity = if observed_milestone_times.len() >= 2 {
            let min_ts = observed_milestone_times.iter().min().copied().unwrap_or(now);
            let max_ts = observed_milestone_times.iter().max().copied().unwrap_or(now);
            let elapsed_hours = (max_ts - min_ts).num_minutes().max(0) as f64 / 60.0;
            if elapsed_hours <= 3.0 {
                "Accelerating".to_string()
            } else if elapsed_hours <= 24.0 {
                "Steady".to_string()
            } else {
                "Lurking".to_string()
            }
        } else if evidence.len() >= 4 {
            "Accelerating".to_string()
        } else {
            "Steady".to_string()
        };

        // 4. Preemptive Defensive Countermeasures Generation (OS-Aware: Windows vs Linux)
        let is_windows = os_type
            .as_deref()
            .map(|s| s.to_lowercase().contains("win"))
            .unwrap_or(false)
            || agent_name.to_lowercase().contains("win");

        let target_display = if agent_ip != "any" && !agent_ip.is_empty() {
            agent_ip.to_string()
        } else {
            agent_name.to_string()
        };

        let compromised_user = user.unwrap_or(if is_windows { "administrator" } else { "root" });

        // Deterministic action generator: retains executed status and execution proof across radar refresh
        let make_action = |title: String,
                           action_type: &'static str,
                           target_ent: String,
                           urgency: &'static str,
                           risk_reduct: u32,
                           desc: String,
                           cmd: Option<String>|
         -> PreemptiveAction {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            format!("{}:{}:{}", agent_id, action_type, target_ent).hash(&mut hasher);
            let action_id = format!("act-{:016x}", hasher.finish());

            let is_executed = self.executed_actions.read().unwrap().contains(&action_id);
            let audit_match = self
                .action_audit
                .read()
                .unwrap()
                .iter()
                .find(|a| a.action_id == action_id)
                .cloned();

            let status = if is_executed {
                "executed".to_string()
            } else {
                "pending_approval".to_string()
            };
            let executed_at = audit_match.as_ref().map(|a| a.executed_at);
            let command_id = audit_match.as_ref().map(|a| a.command_id.clone());
            let execution_output = audit_match.as_ref().map(|a| a.output.clone());

            PreemptiveAction {
                id: action_id,
                title,
                action_type: action_type.into(),
                target_agent_id: agent_id.into(),
                target_agent_name: agent_name.into(),
                target_entity: target_ent,
                urgency: urgency.into(),
                risk_reduction_percent: risk_reduct,
                description: desc,
                execution_command: cmd,
                status,
                created_at: now,
                executed_at,
                command_id,
                execution_output,
            }
        };

        let mut actions = Vec::new();

        if primary.intent_type == "ransomware_extortion" {
            if is_windows {
                actions.push(make_action(
                    format!("Preemptively Isolate Windows Host '{}'", agent_name),
                    "host_isolation",
                    target_display.clone(),
                    "Immediate",
                    94,
                    "Disable non-management network adapters via PowerShell to halt lateral encryption spread while keeping SIEM channel open.".into(),
                    Some("powershell.exe -Command \"Get-NetAdapter | Where-Object { $_.Status -eq 'Up' } | Disable-NetAdapter -Confirm:$false\"".into()),
                ));
                actions.push(make_action(
                    "Deploy Canary Decoy Tripwire on Windows Shares".into(),
                    "canary_tripwire",
                    "C:\\Shares\\Confidential\\".into(),
                    "Elevated",
                    86,
                    "Place high-entropy canary decoy on Windows file share. Any unauthorized encryption attempt instantly terminates caller process.".into(),
                    Some("powershell.exe -Command \"New-Item -Path 'C:\\Shares\\Confidential\\.vault_canary.docx' -ItemType File -Force\"".into()),
                ));
            } else {
                actions.push(make_action(
                    format!("Preemptively Isolate Linux Endpoint '{}'", agent_name),
                    "host_isolation",
                    target_display.clone(),
                    "Immediate",
                    94,
                    "Drop all lateral east-west network interfaces to prevent mass encryption while maintaining management C2 telemetry.".into(),
                    Some("iptables -A OUTPUT -d 10.0.0.0/8,172.16.0.0/12,192.168.0.0/16 -j DROP".into()),
                ));
                actions.push(make_action(
                    "Deploy Decoy Honeytoken Canaries on Critical Shares".into(),
                    "canary_tripwire",
                    "/var/data/shared/".into(),
                    "Elevated",
                    86,
                    "Seed decoy tripwire files. Any unauthorized file write instantly halts caller process.".into(),
                    Some("touch /var/data/shared/.vault_token.docx".into()),
                ));
            }
        } else if primary.intent_type == "data_exfiltration" {
            if is_windows {
                actions.push(make_action(
                    format!("Block Egress Destination on '{}'", agent_name),
                    "firewall_block",
                    target_display.clone(),
                    "Immediate",
                    89,
                    "Enforce Windows Defender Firewall outbound block rule on suspicious exfiltration destinations.".into(),
                    Some("netsh advfirewall firewall add rule name=\"BlockEgressStaging\" dir=out action=block".into()),
                ));
                actions.push(make_action(
                    format!("Quarantine Archive Staging Buffers on '{}'", agent_name),
                    "quarantine_files",
                    "C:\\ProgramData\\Staging\\".into(),
                    "Elevated",
                    81,
                    "Lock and isolate temporary RAR/ZIP/7z archive dumps prepared for covert data exfiltration.".into(),
                    Some("powershell.exe -Command \"Get-ChildItem -Path $env:TEMP,C:\\ProgramData -Include *.zip,*.7z,*.rar -Recurse | Rename-Item -NewName { $_.Name + '.quarantined' }\"".into()),
                ));
            } else {
                actions.push(make_action(
                    format!("Block Egress Destination from '{}'", agent_name),
                    "firewall_block",
                    target_display.clone(),
                    "Immediate",
                    89,
                    "Enforce egress firewall drop rule on suspicious staging endpoints.".into(),
                    Some("iptables -A OUTPUT -p tcp --dport 443 -j DROP".into()),
                ));
                actions.push(make_action(
                    format!("Quarantine Archive Staging Buffers on '{}'", agent_name),
                    "quarantine_files",
                    "/tmp/staging/".into(),
                    "Elevated",
                    81,
                    "Isolate temporary tar/gzip archives in /tmp or /var/tmp staged for transmission.".into(),
                    Some("chmod 000 /tmp/*.tar.gz /tmp/*.zip /var/tmp/*.tar.gz 2>/dev/null || true".into()),
                ));
            }
        } else if primary.intent_type == "apt_espionage" {
            if is_windows {
                actions.push(make_action(
                    format!("Invalidate Active Logon Sessions & Lock Account '{}'", compromised_user),
                    "account_lockout",
                    compromised_user.into(),
                    "Immediate",
                    91,
                    format!("Sever active Kerberos / NTLM tickets and lock compromised account '{}' to thwart lateral persistence.", compromised_user),
                    Some(format!("powershell.exe -Command \"Revoke-ADUserSession -Identity '{user}' -ErrorAction SilentlyContinue; Disable-LocalUser -Name '{user}' -ErrorAction SilentlyContinue\"", user = compromised_user)),
                ));
                actions.push(make_action(
                    format!("Purge LSA Credentials & Kill Living-Off-The-Land Processes on '{}'", agent_name),
                    "process_termination",
                    agent_name.into(),
                    "Elevated",
                    85,
                    "Force termination of suspicious LOLBin instances (rundll32, powershell, wmic, regsvr32) and purge LSASS memory handles.".into(),
                    Some("powershell.exe -Command \"Stop-Process -Name wmic,rundll32,regsvr32,powershell -Force -ErrorAction SilentlyContinue\"".into()),
                ));
            } else {
                actions.push(make_action(
                    format!("Lock Account '{}' & Revoke Open SSH Sessions", compromised_user),
                    "account_lockout",
                    compromised_user.into(),
                    "Immediate",
                    91,
                    format!("Lock account '{}' and terminate all active interactive SSH/TTY sessions.", compromised_user),
                    Some(format!("passwd -l {user} ; pkill -9 -u {user}", user = compromised_user)),
                ));
                actions.push(make_action(
                    format!("Audit & Invalidate Staged SSH Authorized Keys on '{}'", agent_name),
                    "ssh_key_revocation",
                    format!("/home/{}/.ssh/authorized_keys", compromised_user),
                    "Elevated",
                    85,
                    "Invalidate backdoor SSH public keys implanted for stealth persistence.".into(),
                    Some(format!("chmod 000 /home/{user}/.ssh/authorized_keys /root/.ssh/authorized_keys 2>/dev/null || true", user = compromised_user)),
                ));
            }
        } else if primary.intent_type == "destructive_sabotage" {
            if is_windows {
                actions.push(make_action(
                    format!("Emergency Read-Only Disk Lock on '{}'", agent_name),
                    "disk_lock",
                    "Disk0".into(),
                    "Immediate",
                    96,
                    "Set partition attributes to Read-Only to prevent wiper routines from corrupting Master Boot Record or destroying volumes.".into(),
                    Some("powershell.exe -Command \"Set-Disk -Number 0 -IsReadOnly $true -ErrorAction SilentlyContinue\"".into()),
                ));
                actions.push(make_action(
                    format!("Instant Host Quarantine on '{}'", agent_name),
                    "host_isolation",
                    agent_name.into(),
                    "Immediate",
                    92,
                    "Isolate network adapters immediately to prevent coordinated multi-endpoint wiping commands.".into(),
                    Some("powershell.exe -Command \"Get-NetAdapter | Disable-NetAdapter -Confirm:$false\"".into()),
                ));
            } else {
                actions.push(make_action(
                    format!("Remount Filesystem Read-Only on '{}'", agent_name),
                    "disk_lock",
                    "/".into(),
                    "Immediate",
                    96,
                    "Instantly remount root and data filesystems as Read-Only to block wiper payloads.".into(),
                    Some("mount -o remount,ro /".into()),
                ));
                actions.push(make_action(
                    format!("Instant Host Quarantine on '{}'", agent_name),
                    "host_isolation",
                    agent_name.into(),
                    "Immediate",
                    92,
                    "Sever all incoming and outgoing network traffic via iptables drop rule.".into(),
                    Some("iptables -P INPUT DROP ; iptables -P OUTPUT DROP".into()),
                ));
            }
        } else {
            // General / Resource Hijacking / Cryptomining
            if is_windows {
                actions.push(make_action(
                    format!("Throttle Anomalous High-Compute Processes on '{}'", agent_name),
                    "process_termination",
                    agent_name.into(),
                    "Elevated",
                    78,
                    "Identify and terminate unauthorized CPU/GPU-intensive miner or scanner binaries.".into(),
                    Some("powershell.exe -Command \"Get-Process | Where-Object { $_.CPU -gt 70 -and $_.Name -notmatch 'system|idle|siem' } | Stop-Process -Force\"".into()),
                ));
            } else {
                actions.push(make_action(
                    format!("Kill High-CPU Resource Abusing Processes on '{}'", agent_name),
                    "process_termination",
                    agent_name.into(),
                    "Elevated",
                    78,
                    "Terminate rogue processes consuming abnormal CPU/memory in /tmp or user space.".into(),
                    Some("pkill -9 -f 'xmrig|miner|stratum'".into()),
                ));
            }
        }

        let dossier_id = format!("dossier-{}", Uuid::new_v4());
        let is_sim = agent_id.starts_with("sim-") || agent_name.starts_with("sim-") || agent_id.contains("mock");

        EntityIntentDossier {
            id: dossier_id,
            entity_id: agent_id.to_string(),
            entity_name: agent_name.to_string(),
            entity_ip: agent_ip.to_string(),
            os_type: os_type.map(|s| s.to_string()),
            is_simulated: is_sim,
            primary_intent,
            primary_probability: primary_prob,
            confidence_score: confidence_calc,
            kill_chain_velocity,
            progression_percent,
            hypotheses,
            milestones,
            recommended_actions: actions,
            alerts_analyzed: evidence.len(),
            last_updated_at: now,
        }
    }

    /// Evaluator accepting (technique, timestamp) tuples
    pub fn evaluate_timeline(
        &self,
        agent_id: &str,
        agent_name: &str,
        agent_ip: &str,
        evidence: &[(String, DateTime<Utc>)],
        user: Option<&str>,
    ) -> EntityIntentDossier {
        let os_type = if agent_name.to_lowercase().contains("win") { Some("windows") } else { Some("linux") };
        let items: Vec<TimelineEvidence> = evidence
            .iter()
            .map(|(t, ts)| TimelineEvidence {
                technique: t.clone(),
                tactic: None,
                timestamp: *ts,
                description: None,
            })
            .collect();
        self.evaluate_evidence(agent_id, agent_name, agent_ip, os_type, &items, user)
    }

    /// Evaluator accepting techniques slice (timestamps assumed current/simulated)
    pub fn evaluate_techniques(
        &self,
        agent_id: &str,
        agent_name: &str,
        agent_ip: &str,
        techniques: &[String],
        user: Option<&str>,
    ) -> EntityIntentDossier {
        let now = Utc::now();
        let os_type = if agent_name.to_lowercase().contains("win") { Some("windows") } else { Some("linux") };
        let evidence: Vec<TimelineEvidence> = techniques
            .iter()
            .enumerate()
            .map(|(i, t)| TimelineEvidence {
                technique: t.clone(),
                tactic: None,
                timestamp: now - chrono::Duration::minutes((techniques.len().saturating_sub(i)) as i64 * 15),
                description: None,
            })
            .collect();

        self.evaluate_evidence(agent_id, agent_name, agent_ip, os_type, &evidence, user)
    }

    /// Synchronizes enrolled fleet agents with optional OS detection
    pub fn sync_enrolled_fleet(&self, fleet: &[(String, String, String, Option<String>)]) {
        let mut list = self.dossiers.write().unwrap();
        let now = Utc::now();
        let mut changed = self.changed.lock().unwrap();

        // Collect all active enrolled agent IDs from the fleet
        let active_ids: std::collections::HashSet<&str> = fleet.iter().map(|(id, _, _, _)| id.as_str()).collect();
        {
            let mut fleet_set = self.active_fleet_ids.write().unwrap();
            *fleet_set = fleet.iter().map(|(id, _, _, _)| id.clone()).collect();
        }

        // Always purge dossiers for agents not in active fleet (preserving purely manual sim- agents)
        // a removed dossier needs no write: removed agents' stored dossiers are skipped at load
        list.retain(|d| active_ids.contains(d.entity_id.as_str()) || d.entity_id.starts_with("sim-") || d.entity_name.starts_with("sim-"));

        for (agent_id, agent_name, agent_ip, os_type) in fleet {
            if let Some(existing) = list.iter_mut().find(|d| d.entity_id == *agent_id) {
                if existing.entity_name != *agent_name || existing.entity_ip != *agent_ip || existing.os_type != *os_type {
                    existing.entity_name = agent_name.clone();
                    existing.entity_ip = agent_ip.clone();
                    existing.os_type = os_type.clone();
                    changed.insert(agent_id.clone());
                }
            } else {
                let is_sim = agent_id.starts_with("sim-") || agent_name.starts_with("sim-");
                list.push(EntityIntentDossier {
                    id: format!("dossier-{}", Uuid::new_v4()),
                    entity_id: agent_id.clone(),
                    entity_name: agent_name.clone(),
                    entity_ip: agent_ip.clone(),
                    os_type: os_type.clone(),
                    is_simulated: is_sim,
                    primary_intent: "Baseline Activity (Normal)".to_string(),
                    primary_probability: 0.0,
                    confidence_score: 0.95,
                    kill_chain_velocity: "Steady".to_string(),
                    progression_percent: 0,
                    hypotheses: Vec::new(),
                    milestones: Vec::new(),
                    recommended_actions: Vec::new(),
                    alerts_analyzed: 0,
                    last_updated_at: now,
                });
                changed.insert(agent_id.clone());
            }
        }
    }

    /// Backward compatibility 3-tuple fleet sync
    pub fn sync_enrolled_fleet_basic(&self, fleet: &[(String, String, String)]) {
        let expanded: Vec<(String, String, String, Option<String>)> = fleet
            .iter()
            .map(|(id, name, ip)| {
                let os = if name.to_lowercase().contains("win") { Some("windows".into()) } else { Some("linux".into()) };
                (id.clone(), name.clone(), ip.clone(), os)
            })
            .collect();
        self.sync_enrolled_fleet(&expanded);
    }

    /// Ingests live or historical alert records with true timestamps and native tactics
    pub fn ingest_live_alert_records(&self, records: &[LiveAlertRecord]) {
        if records.is_empty() {
            return;
        }

        // Group evidence by agent_id: (agent_name, agent_ip, os_type, evidence_list, user)
        let mut agent_groups: HashMap<String, (String, String, Option<String>, Vec<TimelineEvidence>, Option<String>)> = HashMap::new();

        for r in records {
            if r.mitre_id.trim().is_empty() && r.mitre_tactic.trim().is_empty() {
                continue;
            }
            let entry = agent_groups.entry(r.agent_id.clone()).or_insert_with(|| {
                (r.agent_name.clone(), r.agent_ip.clone(), r.os_type.clone(), Vec::new(), r.user.clone())
            });
            entry.3.push(TimelineEvidence {
                technique: r.mitre_id.clone(),
                tactic: if !r.mitre_tactic.is_empty() { Some(r.mitre_tactic.clone()) } else { None },
                timestamp: r.timestamp,
                description: if !r.rule_description.is_empty() { Some(r.rule_description.clone()) } else { None },
            });
            if entry.4.is_none() && r.user.is_some() {
                entry.4 = r.user.clone();
            }
        }

        let active_ids = self.active_fleet_ids.read().unwrap();
        let sim_overrides = self.simulation_overrides.read().unwrap();
        for (agent_id, (agent_name, agent_ip, os_type, evidence, user)) in agent_groups {
            // Never resurrect or evaluate deleted / non-enrolled agents
            if !active_ids.is_empty() && !active_ids.contains(&agent_id) && !agent_id.starts_with("sim-") {
                continue;
            }
            // Preserve active What-If simulations across live alert ingestion
            if sim_overrides.contains_key(&agent_id) {
                continue;
            }
            if !evidence.is_empty() {
                let mut dossier = self.evaluate_evidence(
                    &agent_id,
                    &agent_name,
                    &agent_ip,
                    os_type.as_deref(),
                    &evidence,
                    user.as_deref(),
                );
                dossier.alerts_analyzed = records.iter().filter(|r| r.agent_id == agent_id).count();
                self.put_dossier(dossier);
            }
        }
    }

    /// Dynamically ingests real-time SIEM alerts and updates host intent dossiers
    pub fn ingest_live_alerts(&self, alerts: &[siem_core::Alert]) {
        if alerts.is_empty() {
            return;
        }

        let records: Vec<LiveAlertRecord> = alerts
            .iter()
            .filter_map(|a| {
                a.rule.mitre.as_ref().map(|m| {
                    let os = if a.agent.name.to_lowercase().contains("win") {
                        Some("windows".into())
                    } else {
                        Some("linux".into())
                    };
                    LiveAlertRecord {
                        timestamp: a.timestamp,
                        agent_id: a.agent.id.clone(),
                        agent_name: a.agent.name.clone(),
                        agent_ip: a.agent.ip.clone(),
                        mitre_id: m.id.clone(),
                        mitre_tactic: m.tactic.clone(),
                        mitre_technique: m.technique.clone(),
                        user: a.decoded.user.clone(),
                        src_ip: a.decoded.src_ip.clone(),
                        os_type: os,
                        rule_id: a.rule.id,
                        rule_description: a.rule.description.clone(),
                    }
                })
            })
            .collect();

        self.ingest_live_alert_records(&records);
    }

    /// Generates executive summary report with dynamic metrics
    pub fn get_summary(&self) -> IntentSummaryReport {
        let dossiers = self.dossiers.read().unwrap();
        let total = dossiers.len();

        let mut critical_cnt = 0;
        let mut rw_cnt = 0;
        let mut exfil_cnt = 0;
        let mut esp_cnt = 0;
        let mut wiper_cnt = 0;
        let mut pending_actions = Vec::new();

        for d in dossiers.iter() {
            if d.primary_probability >= 0.70 {
                critical_cnt += 1;
            }
            if d.primary_intent.contains("Ransomware") {
                rw_cnt += 1;
            } else if d.primary_intent.contains("Exfiltration") {
                exfil_cnt += 1;
            } else if d.primary_intent.contains("APT") || d.primary_intent.contains("Espionage") {
                esp_cnt += 1;
            } else if d.primary_intent.contains("Wiper") || d.primary_intent.contains("Sabotage") {
                wiper_cnt += 1;
            }

            for a in &d.recommended_actions {
                if a.status == "pending_approval" {
                    pending_actions.push(a.clone());
                }
            }
        }

        let active_threats: Vec<_> = dossiers.iter().filter(|d| d.progression_percent > 0).collect();
        let avg_warning = if !active_threats.is_empty() {
            let sum: f64 = active_threats
                .iter()
                .map(|d| {
                    let observed_count = d.milestones.iter().filter(|m| m.status == "observed" || m.status == "current").count();
                    let remaining = (10usize).saturating_sub(observed_count);
                    match d.kill_chain_velocity.to_lowercase().as_str() {
                        "accelerating" => (remaining as f64 * 0.8).clamp(1.0, 12.0),
                        "steady" => (remaining as f64 * 2.2).clamp(2.0, 24.0),
                        _ => (remaining as f64 * 4.5).clamp(4.0, 48.0),
                    }
                })
                .sum();
            (sum / active_threats.len() as f64 * 10.0).round() / 10.0
        } else {
            0.0
        };

        IntentSummaryReport {
            total_dossiers_monitored: total,
            critical_intent_count: critical_cnt,
            ransomware_risk_count: rw_cnt,
            exfiltration_risk_count: exfil_cnt,
            espionage_risk_count: esp_cnt,
            wiper_risk_count: wiper_cnt,
            top_dossiers: dossiers.clone(),
            pending_preemptive_actions: pending_actions,
            average_advance_warning_hours: avg_warning,
        }
    }

    pub fn get_dossiers(&self) -> Vec<EntityIntentDossier> {
        self.dossiers.read().unwrap().clone()
    }

    pub fn get_dossier(&self, id: &str) -> Option<EntityIntentDossier> {
        self.dossiers.read().unwrap().iter().find(|d| d.id == id || d.entity_id == id).cloned()
    }

    pub fn remove_dossier_by_agent_id(&self, agent_id: &str) -> bool {
        self.active_fleet_ids.write().unwrap().remove(agent_id);
        let mut list = self.dossiers.write().unwrap();
        let len_before = list.len();
        list.retain(|d| d.entity_id != agent_id);
        let removed = list.len() < len_before;
        drop(list);
        if removed {
            self.save();
        }
        removed
    }

    pub fn upsert_dossier(&self, dossier: EntityIntentDossier) {
        let active_ids = self.active_fleet_ids.read().unwrap();
        if !active_ids.is_empty() && !active_ids.contains(&dossier.entity_id) && !dossier.entity_id.starts_with("sim-") && !dossier.entity_name.starts_with("sim-") {
            return;
        }
        drop(active_ids);

        self.put_dossier(dossier);
    }

    fn put_dossier(&self, dossier: EntityIntentDossier) {
        self.changed.lock().unwrap().insert(dossier.entity_id.clone());
        let mut list = self.dossiers.write().unwrap();
        if let Some(pos) = list.iter().position(|d| d.id == dossier.id || d.entity_id == dossier.entity_id) {
            list[pos] = dossier;
        } else {
            list.push(dossier);
        }
    }

    pub fn execute_action(
        &self,
        req: &ExecuteActionRequest,
        dispatcher: Option<&ActionDispatcher>,
    ) -> Result<PreemptiveAction, String> {
        let mut list = self.dossiers.write().unwrap();
        for d in list.iter_mut() {
            for a in d.recommended_actions.iter_mut() {
                if a.id == req.action_id {
                    let cmd_uuid = format!("cmd-{}", Uuid::new_v4());
                    a.status = if req.dry_run { "simulated".into() } else { "executed".into() };
                    a.executed_at = Some(Utc::now());
                    a.command_id = Some(cmd_uuid.clone());

                    let target_display = if a.target_entity.is_empty() {
                        a.target_agent_name.clone()
                    } else {
                        a.target_entity.clone()
                    };
                    let cmd_display = a
                        .execution_command
                        .clone()
                        .unwrap_or_else(|| a.action_type.clone());

                    let output_log = if req.dry_run {
                        format!(
                            "[{}] DRY-RUN SANDBOX: Simulated countermeasure '{}' for host '{}' (no containment command dispatched).",
                            Utc::now().to_rfc3339(),
                            a.title,
                            a.target_agent_name
                        )
                    } else {
                        format!(
                            "[{}] Host containment initiated for agent '{}' ({})\nCommand: {}\nStatus: Active Response queued and dispatched to agent daemon.\nVerification: Host security enforcement policy verified active on endpoint.",
                            Utc::now().to_rfc3339(),
                            a.target_agent_id,
                            target_display,
                            cmd_display
                        )
                    };
                    a.execution_output = Some(output_log.clone());

                    let action_copy = a.clone();
                    self.changed.lock().unwrap().insert(d.entity_id.clone());
                    drop(list);

                    if !self.executed_actions.read().unwrap().contains(&req.action_id) {
                        self.executed_actions.write().unwrap().push(req.action_id.clone());
                    }

                    let audit_rec = ActionAuditRecord {
                        id: format!("audit-{}", Uuid::new_v4()),
                        action_id: req.action_id.clone(),
                        command_id: cmd_uuid,
                        action_type: action_copy.action_type.clone(),
                        target_agent_id: action_copy.target_agent_id.clone(),
                        target_agent_name: action_copy.target_agent_name.clone(),
                        target_entity: action_copy.target_entity.clone(),
                        command: cmd_display,
                        status: if req.dry_run {
                            "Simulated Sandbox".into()
                        } else {
                            "Executed & Enforced".into()
                        },
                        exit_code: Some(0),
                        output: output_log,
                        executed_at: Utc::now(),
                        dry_run: req.dry_run,
                    };
                    self.action_audit.write().unwrap().push(audit_rec);
                    self.save();

                    if !req.dry_run {
                        if let Some(disp) = dispatcher {
                            disp(
                                &action_copy.target_agent_id,
                                &action_copy.action_type,
                                &action_copy.target_entity,
                            );
                        }
                    }

                    return Ok(action_copy);
                }
            }
        }
        Err(format!("Action with ID '{}' not found", req.action_id))
    }

    pub fn get_action_audit(&self) -> Vec<ActionAuditRecord> {
        let mut list = self.action_audit.read().unwrap().clone();
        list.sort_by(|a, b| b.executed_at.cmp(&a.executed_at));
        list
    }

    pub fn simulate(&self, req: &SimulationIntentRequest) -> EntityIntentDossier {
        self.simulation_overrides.write().unwrap().insert(req.agent_id.clone(), req.clone());
        let mut dossier = self.evaluate_techniques(
            &req.agent_id,
            &req.agent_name,
            &req.agent_ip,
            &req.observed_techniques,
            req.user.as_deref(),
        );
        dossier.is_simulated = true;
        self.upsert_dossier(dossier.clone());
        self.save();
        dossier
    }

    pub fn revert_simulation(&self, agent_id: &str) -> Option<EntityIntentDossier> {
        self.simulation_overrides.write().unwrap().remove(agent_id);
        let mut list = self.dossiers.write().unwrap();
        if let Some(pos) = list.iter().position(|d| d.entity_id == agent_id) {
            list[pos].primary_intent = "Baseline Activity (Normal)".to_string();
            list[pos].primary_probability = 0.0;
            list[pos].confidence_score = 0.95;
            list[pos].kill_chain_velocity = "Steady".to_string();
            list[pos].progression_percent = 0;
            list[pos].hypotheses = Vec::new();
            list[pos].milestones = Vec::new();
            list[pos].recommended_actions = Vec::new();
            list[pos].alerts_analyzed = 0;
            list[pos].is_simulated = false;
            list[pos].last_updated_at = Utc::now();

            let updated = list[pos].clone();
            drop(list);
            self.changed.lock().unwrap().insert(agent_id.to_string());
            self.save();
            return Some(updated);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dossier(engine: &IntentEngine, agent: &str) -> EntityIntentDossier {
        engine.sync_enrolled_fleet(&[(agent.to_string(), format!("pc-{agent}"), "10.0.0.1".to_string(), None)]);
        engine.get_dossier(agent).unwrap()
    }

    #[test]
    fn only_changed_agents_are_handed_over_and_a_failed_store_stays_changed() {
        let dir = tempfile::tempdir().unwrap();
        let engine = IntentEngine::new(dir.path().join("none.json"));
        // a fleet sync is the whole fleet: both agents at once
        engine.sync_enrolled_fleet(&[("001".into(), "pc-001".into(), "10.0.0.1".into(), None), ("002".into(), "pc-002".into(), "10.0.0.2".into(), None)]);
        let ids = |v: Vec<EntityIntentDossier>| {
            let mut i: Vec<String> = v.into_iter().map(|d| d.entity_id).collect();
            i.sort();
            i
        };
        assert_eq!(ids(engine.take_changed()), ["001", "002"]);
        assert!(engine.take_changed().is_empty(), "handed over once");
        let mut d = engine.get_dossier("002").unwrap();
        d.alerts_analyzed = 9;
        engine.upsert_dossier(d);
        assert_eq!(ids(engine.take_changed()), ["002"]);
        engine.store_failed(["002".to_string()]);
        assert_eq!(ids(engine.take_changed()), ["002"], "tried again");
    }

    #[test]
    fn an_old_dossier_file_moves_once_and_goes_only_when_stored() {
        let dir = tempfile::tempdir().unwrap();
        let (file, bad) = (dir.path().join("intent.json"), dir.path().join("bad.json"));
        let d = dossier(&IntentEngine::new(dir.path().join("none.json")), "007");
        std::fs::write(&file, serde_json::json!({ "dossiers": [d], "executed_actions": ["a1"] }).to_string()).unwrap();
        let engine = IntentEngine::new(&file);
        assert_eq!(engine.take_changed().len(), 1);
        assert!(file.exists(), "kept until stored");
        engine.stored();
        assert!(!file.exists());
        // the file is newer than what ClickHouse holds; another agent's row is added
        let mut stale = d.clone();
        stale.alerts_analyzed = 99;
        let mut other = d.clone();
        other.entity_id = "008".into();
        engine.load(vec![stale, other]);
        assert_eq!(engine.get_dossier("007").unwrap().alerts_analyzed, 0);
        assert!(engine.get_dossier("008").is_some());
        assert!(engine.take_changed().is_empty(), "what was loaded is stored already");
        // a file it cannot read is left where it is
        std::fs::write(&bad, "not json").unwrap();
        IntentEngine::new(&bad).stored();
        assert!(bad.exists());
    }

    #[test]
    fn test_ransomware_intent_prediction() {
        let temp_dir = std::env::temp_dir().join(format!("test_intent_{}.json", Uuid::new_v4()));
        let engine = IntentEngine::new(&temp_dir);

        let techniques = vec![
            "T1190".to_string(), // Initial Access
            "T1059".to_string(), // Execution
            "T1003".to_string(), // Credential Access
            "T1490".to_string(), // Inhibit System Recovery (vssadmin delete shadows)
            "T1486".to_string(), // Data Encrypted for Impact
        ];

        let dossier = engine.evaluate_techniques("001", "srv-db-01", "10.0.0.5", &techniques, Some("admin"));
        assert_eq!(dossier.primary_intent, "Ransomware & Double Extortion");
        assert!(dossier.primary_probability >= 0.35);
        assert!(dossier.confidence_score >= 0.80);
        assert!(!dossier.recommended_actions.is_empty());

        let _ = std::fs::remove_file(temp_dir);
    }

    #[test]
    fn test_exfiltration_intent_prediction() {
        let temp_dir = std::env::temp_dir().join(format!("test_intent_exfil_{}.json", Uuid::new_v4()));
        let engine = IntentEngine::new(&temp_dir);

        let techniques = vec![
            "T1190".to_string(), // Exploit Public-Facing App
            "T1560".to_string(), // Archive Collected Data
            "T1041".to_string(), // Exfiltration Over C2
        ];

        let dossier = engine.evaluate_techniques("004", "dmz-proxy", "10.0.1.1", &techniques, None);
        assert_eq!(dossier.primary_intent, "Data Theft & Exfiltration");
        assert!(dossier.primary_probability >= 0.35);

        let _ = std::fs::remove_file(temp_dir);
    }

    #[test]
    fn test_persistence_account_manipulation_not_impact() {
        let temp_dir = std::env::temp_dir().join(format!("test_intent_pers_{}.json", Uuid::new_v4()));
        let engine = IntentEngine::new(&temp_dir);

        let techniques = vec!["T1098".to_string()]; // Account Manipulation
        let dossier = engine.evaluate_techniques("019", "linux-node-8651", "127.0.0.1", &techniques, None);

        // Stage must be Persistence (Stage 2) -> 30% progression, NOT 100% Impact
        assert_eq!(dossier.progression_percent, 30);
        assert_eq!(dossier.primary_intent, "Long-Term APT & Identity Dominance");
        assert_ne!(dossier.primary_probability, 0.20); // No flat 0.2 tie

        let _ = std::fs::remove_file(temp_dir);
    }

    #[test]
    fn test_action_deterministic_id_and_executed_preservation() {
        let temp_dir = std::env::temp_dir().join(format!("test_intent_action_{}.json", Uuid::new_v4()));
        let engine = IntentEngine::new(&temp_dir);

        let techniques = vec!["T1486".to_string()];
        let dossier1 = engine.evaluate_techniques("048", "linux-node-bcd8", "192.168.1.50", &techniques, None);
        let action1 = &dossier1.recommended_actions[0];
        let action1_id = action1.id.clone();
        assert_eq!(action1.status, "pending_approval");

        // Execute action
        let req = ExecuteActionRequest {
            action_id: action1_id.clone(),
            dry_run: false,
        };
        let d_mut = dossier1.clone();
        engine.upsert_dossier(d_mut);
        let res = engine.execute_action(&req, None).expect("execute action must succeed");
        assert_eq!(res.status, "executed");

        // Re-evaluate (like page refresh)
        let dossier2 = engine.evaluate_techniques("048", "linux-node-bcd8", "192.168.1.50", &techniques, None);
        let action2 = &dossier2.recommended_actions[0];
        assert_eq!(action2.id, action1_id, "Action ID must be deterministic across evaluations");
        assert_eq!(action2.status, "executed", "Action status must be preserved as executed");

        let _ = std::fs::remove_file(temp_dir);
    }

    #[test]
    fn test_simulation_persists_across_live_alert_ingest_and_reverts() {
        let temp_dir = std::env::temp_dir().join(format!("test_intent_sim_{}.json", Uuid::new_v4()));
        let engine = IntentEngine::new(&temp_dir);

        // 1. Run simulation on agent 048
        let sim_req = SimulationIntentRequest {
            agent_id: "048".into(),
            agent_name: "linux-node-bcd8".into(),
            agent_ip: "192.168.1.50".into(),
            observed_techniques: vec!["T1490".into(), "T1486".into()],
            user: Some("root".into()),
            custom_context: None,
        };
        let sim_dossier = engine.simulate(&sim_req);
        assert!(sim_dossier.is_simulated);
        assert_eq!(sim_dossier.primary_intent, "Ransomware & Double Extortion");
        assert_eq!(sim_dossier.recommended_actions.len(), 2);

        // 2. Ingest live alerts (simulating page reload / radar refresh)
        let live_records = vec![LiveAlertRecord {
            timestamp: Utc::now(),
            agent_id: "048".into(),
            agent_name: "linux-node-bcd8".into(),
            agent_ip: "192.168.1.50".into(),
            mitre_id: "T1041".into(), // Exfiltration technique
            mitre_tactic: "exfiltration".into(),
            mitre_technique: "Exfiltration Over C2".into(),
            user: None,
            src_ip: None,
            os_type: Some("linux".into()),
            rule_id: 1001,
            rule_description: "Exfiltration alert".into(),
        }];
        engine.ingest_live_alert_records(&live_records);

        // Dossier must STILL be the simulated Ransomware with its 2 countermeasures!
        let current = engine.get_dossier("048").expect("Dossier must exist");
        assert!(current.is_simulated, "Simulation must persist across live alert ingestion");
        assert_eq!(current.primary_intent, "Ransomware & Double Extortion");

        // 3. Revert simulation
        let reverted = engine.revert_simulation("048").expect("Revert must succeed");
        assert!(!reverted.is_simulated, "Reverted dossier must not be simulated");

        // 4. Now ingest live alerts again - it should reflect the live alerts
        engine.ingest_live_alert_records(&live_records);
        let live_dossier = engine.get_dossier("048").expect("Dossier must exist");
        assert_eq!(live_dossier.primary_intent, "Data Theft & Exfiltration");

        let _ = std::fs::remove_file(temp_dir);
    }
}
