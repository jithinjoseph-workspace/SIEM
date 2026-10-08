//! The wazuh-db configuration: the `wazuh_db.*` internal options read by
//! main.c and the `<wdb>` section (config/wazuh_db-config.c).

use std::path::Path;

use siem_config::cluster::{read_cluster, ClusterSettings};
use siem_config::internal_options::InternalOptions;
use siem_config::messages::{xml_invattr, xml_invelem, xml_valueerr, xml_valuenull, XML_ELEMNULL};
use siem_config::modules::{CCLUSTER, WAZUHDB};
use siem_config::util::{atoi, parse_time, str_is_num};
use siem_config::{read_config, ConfigContext, ConfigError, ConfigHandler, Platform, Section};
use siem_xml::{OsXml, XmlNode};

use super::{WdbConfig, WDB_GLOBAL_BACKUP};

/// Everything main.c reads before starting the threads.
pub struct WdbDaemonConfig {
    pub wdb: WdbConfig,
    /// `nofile` (`wazuh_db.rlimit_nofile`)
    pub nofile: i32,
    /// `wazuh_db.debug`
    pub debug: i32,
    pub cluster: ClusterSettings,
    /// Configuration warnings (logged with mwarn by ReadConfig).
    pub warnings: Vec<String>,
}

/// Where a configuration failure comes from: main.c reports them differently.
pub enum LoadError {
    /// `getDefine_Int` failed (merror_exit with the message).
    Internal(ConfigError),
    /// `ReadConfig` failed: merror(message), then
    /// merror_exit("Invalid configuration block for Wazuh-DB.").
    Config(ConfigError),
}

/// `eval_bool`
fn eval_bool(s: &str) -> Option<bool> {
    match s {
        "yes" => Some(true),
        "no" => Some(false),
        _ => None,
    }
}

/// `Read_WazuhDB`: only the first child of `<wdb>` is looked at.
pub fn read_wazuh_db(xml: &OsXml, children: &[XmlNode], cfg: &mut WdbConfig) -> siem_config::Result<()> {
    let Some(node) = children.first() else {
        return Err(ConfigError::new(XML_ELEMNULL));
    };
    if node.element != "backup" {
        return Err(ConfigError::new(xml_invelem(&node.element)));
    }
    match node.attributes.first() {
        Some(a) if a == "database" => {}
        a => return Err(ConfigError::new(xml_invattr(a.map(String::as_str).unwrap_or(""), &node.element))),
    }
    match node.values.first() {
        Some(v) if v == "global" => {}
        v => return Err(ConfigError::new(xml_valueerr(&node.attributes[0], v.map(String::as_str).unwrap_or("")))),
    }
    read_wazuh_db_backup(xml, node, WDB_GLOBAL_BACKUP, cfg)
}

/// `Read_WazuhDB_Backup`
pub fn read_wazuh_db_backup(xml: &OsXml, node: &XmlNode, backup_node: usize, cfg: &mut WdbConfig) -> siem_config::Result<()> {
    let Some(chld) = xml.get_elements_by_node(Some(node)) else {
        return Err(ConfigError::new(XML_ELEMNULL));
    };
    for c in &chld {
        let Some(content) = c.content.as_deref() else {
            return Err(ConfigError::new(xml_valuenull(&c.element)));
        };
        match c.element.as_str() {
            "enabled" => match eval_bool(content) {
                Some(b) => cfg.backup[backup_node].enabled = b,
                None => return Err(ConfigError::new(xml_valueerr(&c.element, content))),
            },
            "interval" => {
                let t = parse_time(content);
                if t > 0 {
                    cfg.backup[backup_node].interval = t;
                } else {
                    return Err(ConfigError::new(xml_valueerr(&c.element, content)));
                }
            }
            "max_files" => {
                if !str_is_num(content) {
                    return Err(ConfigError::new(xml_valueerr(&c.element, content)));
                }
                cfg.backup[backup_node].max_files = atoi(content);
                if cfg.backup[backup_node].max_files <= 0 {
                    return Err(ConfigError::new(xml_valueerr(&c.element, content)));
                }
            }
            _ => return Err(ConfigError::new(xml_invelem(&c.element))),
        }
    }
    Ok(())
}

struct Handler<'a> {
    wdb: &'a mut WdbConfig,
    cluster: &'a mut ClusterSettings,
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
            Section::WazuhDb => read_wazuh_db(xml, ch, self.wdb),
            Section::Cluster => read_cluster(ctx, xml, ch, self.cluster),
            _ => Ok(()),
        }
    }
}

impl WdbDaemonConfig {
    /// main.c: the internal options, `w_is_worker`, `wdb_init_conf` and
    /// `ReadConfig(WAZUHDB | CCLUSTER, OSSECCONF)`. `home` is the base the
    /// relative paths resolve against (empty after the chdir).
    pub fn load(home: &Path, cfgfile: &Path) -> Result<Self, LoadError> {
        let opts = InternalOptions::from_home(home);
        let g = |k: &str, min: i32, max: i32| opts.get_int("wazuh_db", k, min, max).map_err(LoadError::Internal);
        let mut wdb = WdbConfig {
            worker_pool_size: g("worker_pool_size", 1, 32)?,
            commit_time_min: g("commit_time_min", 1, 3600)?,
            commit_time_max: g("commit_time_max", 1, 3600)?,
            open_db_limit: g("open_db_limit", 1, 4096)?,
            ..WdbConfig::default()
        };
        let nofile = g("rlimit_nofile", 1024, 1048576)?;
        wdb.fragmentation_threshold = g("fragmentation_threshold", 0, 100)?;
        wdb.fragmentation_delta = g("fragmentation_delta", 0, 100)?;
        wdb.free_pages_percentage = g("free_pages_percentage", 0, 99)?;
        wdb.max_fragmentation = g("max_fragmentation", 0, 100)?;
        wdb.check_fragmentation_interval = g("check_fragmentation_interval", 1, 30758400)?;
        // w_is_worker() == 1
        wdb.is_worker_node = siem_config::cluster::is_worker(&home.join(cfgfile)) == Some(true);

        let mut cluster = ClusterSettings::default();
        let mut ctx = ConfigContext::new(Platform::MANAGER);
        read_config(&mut ctx, WAZUHDB | CCLUSTER, home.join(cfgfile), None, &mut Handler { wdb: &mut wdb, cluster: &mut cluster })
            .map_err(LoadError::Config)?;
        let debug = g("debug", 0, 2)?;
        Ok(WdbDaemonConfig { wdb, nofile, debug, cluster, warnings: ctx.warnings.clone() })
    }
}
