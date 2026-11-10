//! analysisd configuration: `AR_ReadConfig` (CAR), `GlobalConf`
//! (CGLOBAL | CRULES | CALERTS | CCLUSTER | CANDSOCKET, then CLABELS), the
//! `<rule_test>` block (CLOGTEST) and the internal options `main()` reads.

use std::path::{Path, PathBuf};

use siem_config::active_response::{read_active_commands, read_active_responses, ArConfig, AR_CONF_HEADER};
use siem_config::cluster::{read_cluster, ClusterSettings};
use siem_config::global::{read_global, read_global_sk, GlobalConfig};
use siem_config::internal_options::InternalOptions;
use siem_config::labels::{read_labels, Label};
use siem_config::logtest::{read_logtest, LogtestConfig as LogtestConf};
use siem_config::socket::{read_socket, SocketForwarder};
use siem_config::{modules, read_config, ConfigContext, ConfigError, ConfigHandler, Platform, Section};
use siem_xml::{OsXml, XmlNode};

use crate::logmsg::LogList;
use crate::ruleset::{read_alerts, read_rules, RulesetConfig};

/// The analysisd internal options read at start-up.
#[derive(Debug, Clone)]
pub struct Internal {
    pub debug: i32,
    pub decoder_order_size: i32,
    pub log_fw: i32,
    pub label_cache_maxage: i32,
    pub show_hidden_labels: i32,
    pub min_rotate_interval: i32,
    pub default_timeframe: i32,
    pub fts_list_size: i32,
    pub fts_min_size_for_str: i32,
    pub rule_matching_threads: i32,
    pub stats_maxdiff: i32,
    pub stats_mindiff: i32,
    pub stats_percent_diff: i32,
    pub rlimit_nofile: i32,
    pub state_interval: i32,
    pub event_threads: i32,
    pub geoip_jsonout: i32,
    pub syscheck_threads: i32,
    pub syscollector_threads: i32,
    pub rootcheck_threads: i32,
    pub sca_threads: i32,
    pub hostinfo_threads: i32,
    pub winevt_threads: i32,
    pub dbsync_threads: i32,
    pub q: QueueSizes,
}

/// Sizes of analysisd's internal queues (`queue_init` arguments).
#[derive(Debug, Clone, Default)]
pub struct QueueSizes {
    pub archives: usize,
    pub alerts: usize,
    pub statistical: usize,
    pub firewall: usize,
    pub fts: usize,
    pub syscheck: usize,
    pub syscollector: usize,
    pub rootcheck: usize,
    pub sca: usize,
    pub hostinfo: usize,
    pub winevt: usize,
    pub event: usize,
    pub output: usize,
    pub dbsync: usize,
    pub upgrade: usize,
}

impl Internal {
    pub fn load(o: &InternalOptions) -> Result<Self, ConfigError> {
        let g = |k: &str, min: i32, max: i32| o.get_int("analysisd", k, min, max);
        Ok(Internal {
            debug: g("debug", 0, 2)?,
            decoder_order_size: g("decoder_order_size", 32, 1024)?,
            log_fw: g("log_fw", 0, 1)?,
            label_cache_maxage: g("label_cache_maxage", 0, 60)?,
            show_hidden_labels: g("show_hidden_labels", 0, 1)?,
            min_rotate_interval: g("min_rotate_interval", 10, 86400)?,
            default_timeframe: g("default_timeframe", 60, 3600)?,
            fts_list_size: g("fts_list_size", 12, 512)?,
            fts_min_size_for_str: g("fts_min_size_for_str", 6, 128)?,
            rule_matching_threads: g("rule_matching_threads", 0, 32)?,
            stats_maxdiff: g("stats_maxdiff", 10, 999999)?,
            stats_mindiff: g("stats_mindiff", 10, 999999)?,
            stats_percent_diff: g("stats_percent_diff", 5, 9999)?,
            rlimit_nofile: g("rlimit_nofile", 1024, 1048576)?,
            state_interval: g("state_interval", 0, 86400)?,
            event_threads: g("event_threads", 0, 32)?,
            geoip_jsonout: g("geoip_jsonout", 0, 1)?,
            syscheck_threads: g("syscheck_threads", 0, 32)?,
            syscollector_threads: g("syscollector_threads", 0, 32)?,
            rootcheck_threads: g("rootcheck_threads", 0, 32)?,
            sca_threads: g("sca_threads", 0, 32)?,
            hostinfo_threads: g("hostinfo_threads", 0, 32)?,
            winevt_threads: g("winevt_threads", 0, 32)?,
            dbsync_threads: g("dbsync_threads", 0, 32)?,
            q: {
                let q = |k: &str| g(k, 128, 2000000).map(|v| v as usize);
                QueueSizes {
                    archives: q("archives_queue_size")?,
                    alerts: q("alerts_queue_size")?,
                    statistical: q("statistical_queue_size")?,
                    firewall: q("firewall_queue_size")?,
                    fts: q("fts_queue_size")?,
                    syscheck: q("decode_syscheck_queue_size")?,
                    syscollector: q("decode_syscollector_queue_size")?,
                    rootcheck: q("decode_rootcheck_queue_size")?,
                    sca: q("decode_sca_queue_size")?,
                    hostinfo: q("decode_hostinfo_queue_size")?,
                    winevt: q("decode_winevt_queue_size")?,
                    event: q("decode_event_queue_size")?,
                    output: q("decode_output_queue_size")?,
                    dbsync: q("dbsync_queue_size")?,
                    upgrade: q("upgrade_queue_size")?,
                }
            },
        })
    }
}

/// Everything analysisd reads from `ossec.conf`.
#[derive(Debug, Clone)]
pub struct AnalysisdConfig {
    pub home: PathBuf,
    pub global: GlobalConfig,
    pub ruleset: RulesetConfig,
    pub cluster: ClusterSettings,
    pub labels: Vec<Label>,
    pub sockets: Vec<SocketForwarder>,
    pub ar: ArConfig,
    pub logtest: LogtestConf,
    pub internal: Internal,
    pub warnings: Vec<String>,
}

struct Handler<'a> {
    global: &'a mut GlobalConfig,
    ruleset: &'a mut RulesetConfig,
    cluster: &'a mut ClusterSettings,
    labels: &'a mut Vec<Label>,
    sockets: &'a mut Vec<SocketForwarder>,
    ar: &'a mut ArConfig,
    logtest: &'a mut LogtestConf,
    home: &'a Path,
    log: &'a mut LogList,
}

impl ConfigHandler for Handler<'_> {
    fn section(
        &mut self,
        ctx: &mut ConfigContext,
        xml: &OsXml,
        s: Section,
        _node: &XmlNode,
        ch: Option<&[XmlNode]>,
    ) -> siem_config::Result<()> {
        let ch = ch.unwrap_or(&[]);
        match s {
            Section::Global => read_global(ctx, xml, ch, Some(self.global), None, false, false),
            Section::GlobalSyscheck => read_global_sk(self.global, Some(ch)),
            Section::Ruleset => read_rules(ch, self.ruleset, self.home, self.log)
                .map_err(|_| ConfigError::new(self.log.msgs.last().map(|m| m.msg.clone()).unwrap_or_default())),
            Section::Alerts => read_alerts(ch, self.ruleset, self.log)
                .map_err(|_| ConfigError::new(self.log.msgs.last().map(|m| m.msg.clone()).unwrap_or_default())),
            Section::Cluster => read_cluster(ctx, xml, ch, self.cluster),
            Section::AnalysisdSocket => read_socket(ch, self.sockets),
            Section::Labels => read_labels(ctx, ch, self.labels),
            Section::Command => read_active_commands(ch, self.ar),
            Section::ActiveResponse => read_active_responses(ch, self.ar),
            Section::RuleTest => read_logtest(ctx, ch, self.logtest, nproc()),
            _ => Ok(()),
        }
    }
}

pub fn nproc() -> u16 {
    std::thread::available_parallelism().map(|n| n.get() as u16).unwrap_or(1)
}

impl AnalysisdConfig {
    /// `AR_ReadConfig` + `GlobalConf` + the checks of analysisd's `main()`.
    /// Also (re)writes `etc/shared/ar.conf` like `AR_ReadConfig`.
    pub fn load(home: &Path, cfgfile: &Path, write_ar_conf: bool) -> Result<Self, ConfigError> {
        let opts = InternalOptions::from_home(home);
        let internal = Internal::load(&opts)?;
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        let mut log = LogList::default();

        // GlobalConf defaults
        let mut global = GlobalConfig::default();
        global.stats = 4;
        global.integrity = 8;
        global.rootcheck = 8;
        global.hostinfo = 8;
        global.jsonout_output = 1;
        global.alerts_log = 1;
        global.memorysize = 8192;
        global.mailnotify = -1;
        global.syscheck_alert_new = 1;
        global.syscheck_ignore_frequency = 10;
        global.syscheck_ignore_time = 3600;
        global.mailbylevel = 7;
        global.logbylevel = 1;
        global.label_cache_maxage = 10;
        global.hide_cluster_info = 1;

        let mut ruleset = RulesetConfig::default();
        let mut cluster = ClusterSettings { hide_cluster_info: true, ..Default::default() };
        let mut labels = Vec::new();
        let mut sockets = Vec::new();
        let mut ar = ArConfig { ar_conf: AR_CONF_HEADER.to_string(), ..Default::default() };
        let mut logtest = LogtestConf::default();

        // AR_ReadConfig
        {
            let mut h = Handler {
                global: &mut global,
                ruleset: &mut ruleset,
                cluster: &mut cluster,
                labels: &mut labels,
                sockets: &mut sockets,
                ar: &mut ar,
                logtest: &mut logtest,
                home,
                log: &mut log,
            };
            read_config(&mut ctx, modules::CAR, cfgfile, None, &mut h)?;
        }
        if write_ar_conf {
            let p = home.join("etc/shared/ar.conf");
            if let Some(d) = p.parent() {
                let _ = std::fs::create_dir_all(d);
            }
            std::fs::write(&p, ar.ar_conf.as_bytes())
                .map_err(|e| ConfigError::new(format!("(1103): Could not open file '{}' due to [({})-({})].", p.display(), e.raw_os_error().unwrap_or(0), e)))?;
        }

        // GlobalConf: CGLOBAL | CRULES | CALERTS | CCLUSTER | CANDSOCKET, then CLABELS
        {
            let mut h = Handler {
                global: &mut global,
                ruleset: &mut ruleset,
                cluster: &mut cluster,
                labels: &mut labels,
                sockets: &mut sockets,
                ar: &mut ar,
                logtest: &mut logtest,
                home,
                log: &mut log,
            };
            read_config(
                &mut ctx,
                modules::CGLOBAL | modules::CRULES | modules::CALERTS | modules::CCLUSTER | modules::CANDSOCKET,
                cfgfile,
                None,
                &mut h,
            )?;
            read_config(&mut ctx, modules::CLABELS, cfgfile, None, &mut h)?;
            // w_logtest_init_parameters: ReadConfig(CLOGTEST)
            read_config(&mut ctx, modules::CLOGTEST, cfgfile, None, &mut h)?;
        }

        // Alert levels read by Read_Alerts override the global defaults.
        if let Some(v) = ruleset.mailbylevel {
            global.mailbylevel = v;
        }
        if let Some(v) = ruleset.logbylevel {
            global.logbylevel = v;
        }
        global.min_rotate_interval = internal.min_rotate_interval;
        if global.memorysize < 2048 {
            global.memorysize = 2048;
        }
        if global.rotate_interval != 0
            && (global.rotate_interval < global.min_rotate_interval || global.rotate_interval > 86400)
        {
            return Err(ConfigError::new(format!(
                "Rotate interval setting must be between {} seconds and one day.",
                global.min_rotate_interval
            )));
        }
        if global.max_output_size != 0 && (global.max_output_size < 1_000_000 || global.max_output_size > 1_099_511_627_776) {
            return Err(ConfigError::new("Maximum output size must be between 1 MiB and 1 TiB."));
        }
        // If no <ruleset> was given, Read_Rules(NULL) loads the defaults.
        if ruleset.includes.is_empty() || ruleset.decoders.is_empty() {
            let mut def = RulesetConfig::default();
            let _ = read_rules(&[], &mut def, home, &mut log);
            if ruleset.decoders.is_empty() {
                ruleset.decoders = def.decoders;
            }
            if ruleset.includes.is_empty() {
                ruleset.includes = def.includes;
            }
        }
        global.cluster_name = cluster.cluster_name.clone();
        global.node_name = cluster.node_name.clone();
        global.node_type = cluster.node_type.clone();
        global.hide_cluster_info = cluster.hide_cluster_info as u8;
        global.label_cache_maxage = internal.label_cache_maxage;
        global.show_hidden_labels = internal.show_hidden_labels;
        global.ar = if ar.ar_flag == -1 { 0 } else { ar.ar_flag };

        let mut warnings = ctx.warnings.clone();
        warnings.extend(log.msgs.iter().map(|m| m.msg.clone()));
        Ok(AnalysisdConfig {
            home: home.to_path_buf(),
            global,
            ruleset,
            cluster,
            labels,
            sockets,
            ar,
            logtest,
            internal,
            warnings,
        })
    }
}
