//! Port of wazuh-modulesd (Wazuh 4.14.7 `src/wazuh_modules/`), the
//! manager side. Ported modules: `database` (`wm_database.c`),
//! `agent-upgrade` (manager), `task-manager` and `download`.

pub mod agent_upgrade;
pub mod database;
pub mod download;
pub mod task_general;
pub mod task_manager;
pub mod wdb;
