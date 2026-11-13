# provigil-db: the on-disk layout the new code must create (from the old implementation, 13 Nov 2026)

## GLOBAL
- table `agent`: `CREATE TABLE agent ( id INTEGER PRIMARY KEY, name TEXT NOT NULL, ip TEXT, register_ip TEXT, internal_key TEXT, os_name TEXT, os_version TEXT, os_major TEXT, os_minor TEXT, os_codename TEXT, os_build TEXT, os_platform TEXT, os_uname TEXT, os_arch TEXT, version TEXT, config_sum TEXT, merged_sum TEXT, manager_host TEXT, node_name TEXT DEFAULT 'unknown', date_add INTEGER NOT NULL, last_keepalive INTEGER, `group` TEXT DEFAULT 'default', group_hash TEXT default NULL, group_sync_status TEXT NOT NULL CHECK (group_sync_status IN ('synced', 'syncreq')) DEFAULT 'synced', sync_status TEXT NOT NULL CHECK (sync_status IN ('synced', 'syncreq', 'syncreq_status', 'syncreq_keepalive')) DEFAULT 'synced', connection_status TEXT NOT NULL CHECK (connection_status IN ('pending', 'never_connected', 'active', 'disconnected')) DEFAULT 'never_connected', disconnection_time INTEGER DEFAULT 0, group_config_status TEXT NOT NULL CHECK (group_config_status IN ('synced', 'not synced')) DEFAULT 'not synced', status_code INTEGER DEFAULT 0)`
- index `agent_name`: `CREATE INDEX agent_name ON agent (name)`
- index `agent_ip`: `CREATE INDEX agent_ip ON agent (ip)`
- index `agent_group_hash`: `CREATE INDEX agent_group_hash ON agent (group_hash)`
- table `labels`: `CREATE TABLE labels ( id INTEGER REFERENCES agent (id) ON DELETE CASCADE, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (id,key))`
- index `sqlite_autoindex_labels_1` (automatic)
- table `info`: `CREATE TABLE info ( key TEXT PRIMARY KEY, value TEXT)`
- index `sqlite_autoindex_info_1` (automatic)
- table `group`: `CREATE TABLE `group` ( id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, UNIQUE (name))`
- index `sqlite_autoindex_group_1` (automatic)
- table `sqlite_sequence`: `CREATE TABLE sqlite_sequence(name,seq)`
- index `group_name`: `CREATE INDEX group_name ON `group` (name)`
- table `belongs`: `CREATE TABLE belongs ( id_agent INTEGER REFERENCES agent (id) ON DELETE CASCADE, id_group INTEGER REFERENCES `group` (id) ON DELETE CASCADE, priority INTEGER NOT NULL DEFAULT 0, UNIQUE (id_agent, priority), PRIMARY KEY (id_agent, id_group))`
- index `sqlite_autoindex_belongs_1` (automatic)
- index `sqlite_autoindex_belongs_2` (automatic)
- index `belongs_id_agent`: `CREATE INDEX belongs_id_agent ON belongs (id_agent)`
- index `belongs_id_group`: `CREATE INDEX belongs_id_group ON belongs (id_group)`
- table `metadata`: `CREATE TABLE metadata ( key TEXT PRIMARY KEY, value TEXT)`
- index `sqlite_autoindex_metadata_1` (automatic)

## AGENT
- table `fim_entry`: `CREATE TABLE fim_entry ( full_path TEXT NOT NULL PRIMARY KEY, file TEXT, type TEXT NOT NULL CHECK (type IN ('file', 'registry_key', 'registry_value')), date INTEGER NOT NULL DEFAULT (strftime('%s', 'now')), changes INTEGER NOT NULL DEFAULT 1, arch TEXT CHECK (arch IN (NULL, '[x64]', '[x32]')), value_name TEXT, value_type TEXT, size INTEGER, perm TEXT, uid TEXT, gid TEXT, md5 TEXT, sha1 TEXT, uname TEXT, gname TEXT, mtime INTEGER, inode INTEGER, sha256 TEXT, attributes TEXT, symbolic_path TEXT, checksum TEXT)`
- index `sqlite_autoindex_fim_entry_1` (automatic)
- index `fim_full_path_index`: `CREATE INDEX fim_full_path_index ON fim_entry (full_path)`
- index `fim_file_index`: `CREATE INDEX fim_file_index ON fim_entry (file)`
- index `fim_date_index`: `CREATE INDEX fim_date_index ON fim_entry (date)`
- index `fim_type_full_path_index`: `CREATE INDEX fim_type_full_path_index ON fim_entry (type, full_path)`
- index `fim_type_file_index`: `CREATE INDEX fim_type_file_index ON fim_entry (type, file)`
- index `fim_type_full_path_checksum_index`: `CREATE INDEX fim_type_full_path_checksum_index ON fim_entry(type,full_path,checksum)`
- index `fim_type_file_checksum_index`: `CREATE INDEX fim_type_file_checksum_index ON fim_entry(type,file,checksum)`
- table `pm_event`: `CREATE TABLE pm_event ( id INTEGER PRIMARY KEY AUTOINCREMENT, date_first INTEGER, date_last INTEGER, log TEXT, pci_dss TEXT, cis TEXT)`
- table `sqlite_sequence`: `CREATE TABLE sqlite_sequence(name,seq)`
- index `pm_event_log`: `CREATE INDEX pm_event_log ON pm_event (log)`
- index `pm_event_date`: `CREATE INDEX pm_event_date ON pm_event (date_last)`
- table `sys_netiface`: `CREATE TABLE sys_netiface ( scan_id INTEGER, scan_time TEXT, name TEXT, adapter TEXT, type TEXT, state TEXT, mtu INTEGER CHECK (mtu > 0), mac TEXT, tx_packets INTEGER, rx_packets INTEGER, tx_bytes INTEGER, rx_bytes INTEGER, tx_errors INTEGER, rx_errors INTEGER, tx_dropped INTEGER, rx_dropped INTEGER, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (scan_id, name))`
- index `sqlite_autoindex_sys_netiface_1` (automatic)
- index `netiface_id`: `CREATE INDEX netiface_id ON sys_netiface (scan_id)`
- table `sys_netproto`: `CREATE TABLE sys_netproto ( scan_id INTEGER REFERENCES sys_netiface (scan_id), iface TEXT REFERENCES sys_netiface (name), type TEXT, gateway TEXT, dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown', metric INTEGER, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (scan_id, iface, type))`
- index `sqlite_autoindex_sys_netproto_1` (automatic)
- index `netproto_id`: `CREATE INDEX netproto_id ON sys_netproto (scan_id)`
- table `sys_netaddr`: `CREATE TABLE sys_netaddr ( scan_id INTEGER REFERENCES sys_netproto (scan_id), iface TEXT REFERENCES sys_netproto (iface), proto TEXT REFERENCES sys_netproto (type), address TEXT, netmask TEXT, broadcast TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (scan_id, iface, proto, address))`
- index `sqlite_autoindex_sys_netaddr_1` (automatic)
- index `netaddr_id`: `CREATE INDEX netaddr_id ON sys_netaddr (scan_id)`
- table `sys_osinfo`: `CREATE TABLE sys_osinfo ( scan_id INTEGER, scan_time TEXT, hostname TEXT, architecture TEXT, os_name TEXT, os_version TEXT, os_codename TEXT, os_major TEXT, os_minor TEXT, os_patch TEXT, os_build TEXT, os_platform TEXT, sysname TEXT, release TEXT, version TEXT, os_release TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), os_display_version TEXT, reference TEXT NOT NULL DEFAULT '', PRIMARY KEY (scan_id, os_name))`
- index `sqlite_autoindex_sys_osinfo_1` (automatic)
- table `sys_hwinfo`: `CREATE TABLE sys_hwinfo ( scan_id INTEGER, scan_time TEXT, board_serial TEXT, cpu_name TEXT, cpu_cores INTEGER, cpu_mhz REAL, ram_total INTEGER, ram_free INTEGER, ram_usage INTEGER, checksum TEXT NOT NULL CHECK (checksum <> ''), PRIMARY KEY (scan_id, board_serial))`
- index `sqlite_autoindex_sys_hwinfo_1` (automatic)
- table `sys_ports`: `CREATE TABLE sys_ports ( scan_id INTEGER, scan_time TEXT, protocol TEXT, local_ip TEXT, local_port INTEGER CHECK (local_port >= 0), remote_ip TEXT, remote_port INTEGER CHECK (remote_port >= 0), tx_queue INTEGER, rx_queue INTEGER, inode INTEGER, state TEXT, PID INTEGER, process TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (protocol, local_ip, local_port, inode))`
- index `sqlite_autoindex_sys_ports_1` (automatic)
- index `ports_id`: `CREATE INDEX ports_id ON sys_ports (scan_id)`
- table `sys_programs`: `CREATE TABLE sys_programs ( scan_id INTEGER, scan_time TEXT, format TEXT, name TEXT, priority TEXT, section TEXT, size INTEGER CHECK (size >= 0), vendor TEXT, install_time TEXT, version TEXT, architecture TEXT, multiarch TEXT, source TEXT, description TEXT, location TEXT, cpe TEXT, msu_name TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (scan_id, name, version, architecture, format, location))`
- index `sqlite_autoindex_sys_programs_1` (automatic)
- index `programs_id`: `CREATE INDEX programs_id ON sys_programs (scan_id)`
- table `sys_hotfixes`: `CREATE TABLE sys_hotfixes ( scan_id INTEGER, scan_time TEXT, hotfix TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), PRIMARY KEY (scan_id, hotfix))`
- index `sqlite_autoindex_sys_hotfixes_1` (automatic)
- index `hotfix_id`: `CREATE INDEX hotfix_id ON sys_hotfixes (scan_id)`
- table `sys_processes`: `CREATE TABLE sys_processes ( scan_id INTEGER, scan_time TEXT, pid TEXT, name TEXT, state TEXT, ppid INTEGER, utime INTEGER, stime INTEGER, cmd TEXT, argvs TEXT, euser TEXT, ruser TEXT, suser TEXT, egroup TEXT, rgroup TEXT, sgroup TEXT, fgroup TEXT, priority INTEGER, nice INTEGER, size INTEGER, vm_size INTEGER, resident INTEGER, share INTEGER, start_time INTEGER, pgrp INTEGER, session INTEGER, nlwp INTEGER, tgid INTEGER, tty INTEGER, processor INTEGER, checksum TEXT NOT NULL CHECK (checksum <> ''), PRIMARY KEY (scan_id, pid))`
- index `sqlite_autoindex_sys_processes_1` (automatic)
- index `processes_id`: `CREATE INDEX processes_id ON sys_processes (scan_id)`
- table `sys_users`: `CREATE TABLE sys_users ( scan_id INTEGER, scan_time TEXT, user_name TEXT, user_full_name TEXT, user_home TEXT, user_id INTEGER, user_uid_signed INTEGER, user_uuid TEXT, user_groups TEXT, user_group_id INTEGER, user_group_id_signed INTEGER, user_created REAL, user_roles TEXT, user_shell TEXT, user_type TEXT, user_is_hidden INTEGER, user_is_remote INTEGER, user_last_login INTEGER, user_auth_failed_count INTEGER, user_auth_failed_timestamp REAL, user_password_last_change REAL, user_password_expiration_date INTEGER, user_password_hash_algorithm TEXT, user_password_inactive_days INTEGER, user_password_max_days_between_changes INTEGER, user_password_min_days_between_changes INTEGER, user_password_status TEXT, user_password_warning_days_before_expiration INTEGER, process_pid INTEGER, host_ip TEXT, login_status INTEGER, login_tty TEXT, login_type TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), PRIMARY KEY (user_name))`
- index `sqlite_autoindex_sys_users_1` (automatic)
- table `sys_groups`: `CREATE TABLE sys_groups ( scan_id INTEGER, scan_time TEXT, group_id INTEGER, group_name TEXT, group_description TEXT, group_id_signed INTEGER, group_uuid TEXT, group_is_hidden INTEGER, group_users TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), PRIMARY KEY (group_name))`
- index `sqlite_autoindex_sys_groups_1` (automatic)
- table `sys_browser_extensions`: `CREATE TABLE sys_browser_extensions ( scan_id INTEGER, scan_time TEXT, browser_name TEXT, user_id TEXT, package_name TEXT, package_id TEXT, package_version TEXT, package_description TEXT, package_vendor TEXT, package_build_version TEXT, package_path TEXT, browser_profile_name TEXT, browser_profile_path TEXT, package_reference TEXT, package_permissions TEXT, package_type TEXT, package_enabled INTEGER, package_visible INTEGER, package_autoupdate INTEGER, package_persistent INTEGER, package_from_webstore INTEGER, browser_profile_referenced INTEGER, package_installed TEXT, file_hash_sha256 TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (browser_name, user_id, browser_profile_path, package_name, package_version))`
- index `sqlite_autoindex_sys_browser_extensions_1` (automatic)
- table `sys_services`: `CREATE TABLE sys_services ( scan_id INTEGER, scan_time TEXT, service_id TEXT, service_name TEXT, service_description TEXT, service_type TEXT, service_state TEXT, service_sub_state TEXT, service_enabled TEXT, service_start_type TEXT, service_restart TEXT, service_frequency INTEGER, service_starts_on_mount INTEGER, service_starts_on_path_modified TEXT, service_starts_on_not_empty_directory TEXT, service_inetd_compatibility INTEGER, process_pid INTEGER, process_executable TEXT, process_args TEXT, process_user_name TEXT, process_group_name TEXT, process_working_directory TEXT, process_root_directory TEXT, file_path TEXT, service_address TEXT, log_file_path TEXT, error_log_file_path TEXT, service_exit_code INTEGER, service_win32_exit_code INTEGER, service_following TEXT, service_object_path TEXT, service_target_ephemeral_id INTEGER, service_target_type TEXT, service_target_address TEXT, checksum TEXT NOT NULL CHECK (checksum <> ''), item_id TEXT, PRIMARY KEY (service_id, file_path))`
- index `sqlite_autoindex_sys_services_1` (automatic)
- index `services_id`: `CREATE INDEX services_id ON sys_services (scan_id)`
- table `ciscat_results`: `CREATE TABLE ciscat_results ( id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, scan_time TEXT, benchmark TEXT, profile TEXT, pass INTEGER, fail INTEGER, error INTEGER, notchecked INTEGER, unknown INTEGER, score INTEGER)`
- index `ciscat_id`: `CREATE INDEX ciscat_id ON ciscat_results (scan_id)`
- table `metadata`: `CREATE TABLE metadata ( key TEXT PRIMARY KEY, value TEXT)`
- index `sqlite_autoindex_metadata_1` (automatic)
- table `scan_info`: `CREATE TABLE scan_info ( module TEXT PRIMARY KEY, first_start INTEGER DEFAULT 0, first_end INTEGER DEFAULT 0, start_scan INTEGER DEFAULT 0, end_scan INTEGER DEFAULT 0, fim_first_check INTEGER DEFAULT 0, fim_second_check INTEGER DEFAULT 0, fim_third_check INTEGER DEFAULT 0)`
- index `sqlite_autoindex_scan_info_1` (automatic)
- table `sca_policy`: `CREATE TABLE sca_policy ( name TEXT, file TEXT, id TEXT, description TEXT, `references` TEXT, hash_file TEXT)`
- table `sca_scan_info`: `CREATE TABLE sca_scan_info ( id INTEGER PRIMARY KEY, start_scan INTEGER, end_scan INTEGER, policy_id TEXT REFERENCES sca_policy (id), pass INTEGER, fail INTEGER, invalid INTEGER, total_checks INTEGER, score INTEGER, hash TEXT)`
- table `sca_check`: `CREATE TABLE sca_check ( scan_id INTEGER REFERENCES sca_scan_info (id), id INTEGER PRIMARY KEY, policy_id TEXT REFERENCES sca_policy (id), title TEXT, description TEXT, rationale TEXT, remediation TEXT, file TEXT, process TEXT, directory TEXT, registry TEXT, command TEXT, `references` TEXT, result TEXT, reason TEXT, condition TEXT)`
- index `policy_id_index`: `CREATE INDEX policy_id_index ON sca_check (policy_id)`
- table `sca_check_rules`: `CREATE TABLE sca_check_rules ( id_check INTEGER REFERENCES sca_check (id), `type` TEXT, rule TEXT, PRIMARY KEY (id_check, `type`, rule))`
- index `sqlite_autoindex_sca_check_rules_1` (automatic)
- index `rules_id_check_index`: `CREATE INDEX rules_id_check_index ON sca_check_rules (id_check)`
- table `sca_check_compliance`: `CREATE TABLE sca_check_compliance ( id_check INTEGER REFERENCES sca_check (id), `key` TEXT, `value` TEXT, PRIMARY KEY (id_check, `key`, `value`))`
- index `sqlite_autoindex_sca_check_compliance_1` (automatic)
- index `comp_id_check_index`: `CREATE INDEX comp_id_check_index ON sca_check_compliance (id_check)`
- table `sync_info`: `CREATE TABLE sync_info ( component TEXT PRIMARY KEY, last_attempt INTEGER DEFAULT 0, last_completion INTEGER DEFAULT 0, n_attempts INTEGER DEFAULT 0, n_completions INTEGER DEFAULT 0, last_manager_checksum TEXT NOT NULL DEFAULT '', last_agent_checksum TEXT NOT NULL DEFAULT '')`
- index `sqlite_autoindex_sync_info_1` (automatic)

## TASK
- table `TASKS`: `CREATE TABLE TASKS ( TASK_ID INTEGER PRIMARY KEY AUTOINCREMENT, AGENT_ID INT NOT NULL, NODE TEXT NOT NULL, MODULE TEXT NOT NULL, COMMAND TEXT NOT NULL, CREATE_TIME INTEGER NOT NULL, LAST_UPDATE_TIME INTEGER, STATUS TEXT NOT NULL, ERROR_MESSAGE TEXT DEFAULT NULL)`
- table `sqlite_sequence`: `CREATE TABLE sqlite_sequence(name,seq)`
- index `IN_TASK_ID`: `CREATE INDEX IN_TASK_ID ON TASKS (TASK_ID)`
- index `IN_TASK_AGENT`: `CREATE INDEX IN_TASK_AGENT ON TASKS (AGENT_ID)`
- index `IN_TASK_NODE`: `CREATE INDEX IN_TASK_NODE ON TASKS (NODE)`
- index `IN_TASK_MODULE`: `CREATE INDEX IN_TASK_MODULE ON TASKS (MODULE)`
- index `IN_TASK_COMMAND`: `CREATE INDEX IN_TASK_COMMAND ON TASKS (COMMAND)`
- index `IN_TASK_CREATE_TIME`: `CREATE INDEX IN_TASK_CREATE_TIME ON TASKS (CREATE_TIME)`
- index `IN_TASK_LAST_UPDATE_TIME`: `CREATE INDEX IN_TASK_LAST_UPDATE_TIME ON TASKS (LAST_UPDATE_TIME)`
- index `IN_TASK_STATUS`: `CREATE INDEX IN_TASK_STATUS ON TASKS (STATUS)`
- index `IN_TASK_ERROR_MESSAGE`: `CREATE INDEX IN_TASK_ERROR_MESSAGE ON TASKS (ERROR_MESSAGE)`
- table `METADATA`: `CREATE TABLE METADATA ( key TEXT PRIMARY KEY, value TEXT)`
- index `sqlite_autoindex_METADATA_1` (automatic)

## GLOBAL-META
- row `{"key": "db_version", "value": "7"}`

## AGENT-META
- row `{"key": "db_version", "value": "16"}`

## AGENT-ROWS
- row `{"t": "sync_info", "component": "fim", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "fim_file", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "fim_registry", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "fim_registry_key", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "fim_registry_value", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-processes", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-packages", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-hotfixes", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-ports", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-netproto", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-netaddress", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-netinfo", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-hwinfo", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-osinfo", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-users", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-groups", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-browser-extensions", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`
- row `{"t": "sync_info", "component": "syscollector-services", "last_attempt": 0, "last_completion": 0, "n_attempts": 0, "n_completions": 0, "last_manager_checksum": "", "last_agent_checksum": ""}`

## GLOBAL-ROWS
- row `{"id": 0, "name": "localhost", "ip": "127.0.0.1", "register_ip": "127.0.0.1", "node_name": "unknown", "date_add": 1794534252, "last_keepalive": 253402300799, "group_sync_status": "synced", "sync_status": "synced", "connection_status": "active", "disconnection_time": 0, "group_config_status": "not synced", "status_code": 0}`
- row `{"id": 1, "name": "a", "node_name": "unknown", "date_add": 1, "group_sync_status": "synced", "sync_status": "synced", "connection_status": "never_connected", "disconnection_time": 0, "group_config_status": "not synced", "status_code": 0}`
