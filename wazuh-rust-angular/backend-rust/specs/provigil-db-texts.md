# provigil-db: every text of the old crate (answers, errors, log lines)

Generated 13 Nov 2026 from crates/siem-wdb/src (string literals of 6+ characters; identifiers
and plain table/column names left out, they are in the schema section). The review ticks each
line: same text in the new code, or a written reason.

### fim_store.rs `test_fim_upsert_added_and_modified`
- [ ] `Should generate Added delta`
- [ ] `Should generate Modified delta`
- [ ] `Should generate Deleted delta`

### global_db.rs `insert_agent`
- [ ] `Agent ID already exists`

### integrity.rs `compute_range_checksum`
- [ ] `{:02x}`

### lib.rs `test_global_db_agent_lifecycle`
- [ ] `Agent 0 must exist`
- [ ] `Agent 1 must exist`
- [ ] `.to_string(), `
- [ ] `.to_string(), `

### lib.rs `test_rootcheck_store`
- [ ] `Trojan /usr/bin/netstat modified`
- [ ] `Trojan /usr/bin/netstat modified`

### lib.rs `test_wire_protocol_commands`
- [ ] `global insert-agent 10 app-srv-01 192.168.1.100 key123 prod`
- [ ] `global update-keepalive 10 active`
- [ ] `global get-agent-info 10`
- [ ] `agent 010 fim save /etc/hosts 1024 0644 0 0 md5_hosts sha256_hosts 1710000000 12345`
- [ ] `agent 010 fim get /etc/hosts`
- [ ] `agent 010 rootcheck save Unexpected_hidden_file 1710000000 PCI-1 CIS-2`
- [ ] `agent 010 sca save cis_ubuntu_24 100 Disable_root_ssh passed`

### sca_store.rs `test_sca_compliance_score`
- [ ] `Ensure /tmp is configured with nodev`
- [ ] `Check fstab for /tmp mount options`
- [ ] `Ensure root login via SSH is disabled`
- [ ] `Check sshd_config PermitRootLogin no`
- [ ] `Ensure legacy rsh-server is not installed`
- [ ] `Check rsh-server package absence`

### wire_protocol.rs `execute_command`
- [ ] `err Empty command`
- [ ] `err Missing agent id`
- [ ] `err Unknown target (must be 'global' or 'agent')`

### wire_protocol.rs `handle_global_command`
- [ ] `err Missing global command`
- [ ] `err Usage: global insert-agent <id> <name> [ip] [key] [group]`
- [ ] `err Invalid agent id`
- [ ] `err {e}`
- [ ] `err Usage: global update-keepalive <id> <status>`
- [ ] `err Invalid agent id`
- [ ] `err Agent not found`
- [ ] `err Usage: global get-agent-info <id>`
- [ ] `err Invalid agent id`
- [ ] `err Agent not found`
- [ ] `ok Disconnected {count} agents`
- [ ] `err Unknown global action '{}'`

### wire_protocol.rs `handle_agent_command`
- [ ] `err Missing agent command`
- [ ] `ok Action: {:?}`
- [ ] `ok Unchanged`
- [ ] `err File not found`
- [ ] `err Invalid fim command`
- [ ] `err Invalid rootcheck command`
- [ ] `err Invalid check_id`
- [ ] `err Invalid sca command`
- [ ] `err Unknown agent action '{}'`

### bin/provigil-db.rs `early_exit`
- [ ] `{ts} {ARGV0}: CRITICAL: {msg}`

### bin/provigil-db.rs `main`
- [ ] `(1133): Unable to chdir to directory '{}' due to [({n})-({t})].`
- [ ] ` || a == `
- [ ] `{ARGV0}: invalid option -- '{c}'`
- [ ] `Invalid configuration block for provigil-db.`
- [ ] `ProVigil home directory: {}`
- [ ] `Template file removed: {}`
- [ ] `(1212): Unable to create PID file.`
- [ ] `Started (pid: {}).`
- [ ] `Failed to create router handle for 'wdb-agent-events'.`
- [ ] `Failed to create router handle for 'wdb-inventory-events'.`
- [ ] `Couldn't create threads: Resource temporarily unavailable`
- [ ] `Graceful process shutdown.`

### bin/provigil-db.rs `print_header`
- [ ] `ProVigil v4.14.7`

### bin/provigil-db.rs `print_version`
- [ ] `ProVigil v4.14.7`

### bin/provigil-db.rs `wdb_help`
- [ ] `  {ARGV0}: -[Vhdtf]`
- [ ] `    -V          Version and license message.`
- [ ] `    -h          This help message.`
- [ ] `    -d          Debug mode. Use this parameter multiple times to increase the debug level.`
- [ ] `    -t          Test configuration.`
- [ ] `    -f          Run in foreground.`

### bin/provigil-db.rs `early_exit`
- [ ] `{ts} {ARGV0}: CRITICAL: {msg}`

### bin/provigil-db.rs `main`
- [ ] `(1133): Unable to chdir to directory '{}' due to [({n})-({t})].`
- [ ] `{ARGV0}: invalid option -- '{c}'`
- [ ] `Invalid configuration block for provigil-db.`
- [ ] `ProVigil home directory: {}`
- [ ] `Template file removed: {}`
- [ ] `(1212): Unable to create PID file.`
- [ ] `Started (pid: {}).`
- [ ] `Failed to create router handle for 'wdb-agent-events'.`
- [ ] `Failed to create router handle for 'wdb-inventory-events'.`
- [ ] `at run_dealer(): wnotify_init(): {t} ({n})`
- [ ] `Couldn't create 'run_dealer' thread: Resource temporarily unavailable`
- [ ] `Couldn't create 'run_worker' {} thread: {e}`
- [ ] `Couldn't create 'run_gc' thread: Resource temporarily unavailable`
- [ ] `Couldn't create 'run_backup' thread: {e}`
- [ ] `{WDB2_DIR}/{WDB_PROF_NAME}`
- [ ] `Template file removed again: {path_template}`
- [ ] `Graceful process shutdown.`

### bin/provigil-mitredb.rs `(top)`
- [ ] `DROP TABLE IF EXISTS phase`
- [ ] `DROP TABLE IF EXISTS mitigate`
- [ ] `DROP TABLE IF EXISTS data_source`
- [ ] `DROP TABLE IF EXISTS defense_bypassed`
- [ ] `DROP TABLE IF EXISTS effective_permission`
- [ ] `DROP TABLE IF EXISTS impact`
- [ ] `DROP TABLE IF EXISTS permission`
- [ ] `DROP TABLE IF EXISTS system_requirement`
- [ ] `DROP TABLE IF EXISTS metadata`
- [ ] `DROP TABLE IF EXISTS technique`
- [ ] `DROP TABLE IF EXISTS \"group\"`
- [ ] `DROP TABLE IF EXISTS software`
- [ ] `DROP TABLE IF EXISTS mitigation`
- [ ] `DROP TABLE IF EXISTS alias`
- [ ] `DROP TABLE IF EXISTS contributor`
- [ ] `DROP TABLE IF EXISTS platform`
- [ ] `DROP TABLE IF EXISTS reference`
- [ ] `DROP TABLE IF EXISTS use`
- [ ] `DROP TABLE IF EXISTS tactic`
- [ ] `CREATE TABLE metadata (\n\t\"key\" VARCHAR NOT NULL, \n\tvalue VARCHAR NOT NULL, \n\tPRIMARY KEY (\"key\")\n)`
- [ ] `CREATE TABLE technique (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\tmitre_detection VARCHAR, \n\tnetwork_requirements BOOLEAN, \n\tremote_support BOOLEAN, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tsubtechnique_of VARCHAR, \n\tPRIMARY KEY (id)\n)`
- [ ] `CREATE TABLE \"group\" (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tPRIMARY KEY (id)\n)`
- [ ] `CREATE TABLE software (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tPRIMARY KEY (id)\n)`
- [ ] `CREATE TABLE mitigation (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tmitre_version VARCHAR, \n\trevoked_by VARCHAR, \n\tdeprecated BOOLEAN, \n\tPRIMARY KEY (id)\n)`
- [ ] `CREATE TABLE alias (\n\tid VARCHAR NOT NULL, \n\talias VARCHAR NOT NULL, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, alias)\n)`
- [ ] `CREATE TABLE contributor (\n\tid VARCHAR NOT NULL, \n\tcontributor VARCHAR NOT NULL, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, contributor)\n)`
- [ ] `CREATE TABLE platform (\n\tid VARCHAR NOT NULL, \n\tplatform VARCHAR NOT NULL, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, platform)\n)`
- [ ] `CREATE TABLE reference (\n\tid VARCHAR NOT NULL, \n\tsource VARCHAR NOT NULL, \n\texternal_id VARCHAR, \n\turl VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\ttype VARCHAR NOT NULL, \n\tPRIMARY KEY (id, source, url)\n)`
- [ ] `CREATE TABLE use (\n\tid VARCHAR NOT NULL, \n\tsource_id VARCHAR NOT NULL, \n\tsource_type VARCHAR NOT NULL, \n\ttarget_id VARCHAR NOT NULL, \n\ttarget_type VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tPRIMARY KEY (id)\n)`
- [ ] `CREATE TABLE tactic (\n\tid VARCHAR NOT NULL, \n\tname VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tshort_name VARCHAR, \n\tPRIMARY KEY (id)\n)`
- [ ] `CREATE TABLE data_source (\n\tid VARCHAR NOT NULL, \n\tsource VARCHAR NOT NULL, \n\tPRIMARY KEY (id, source), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)`
- [ ] `CREATE TABLE defense_bypassed (\n\tid VARCHAR NOT NULL, \n\tdefense VARCHAR NOT NULL, \n\tPRIMARY KEY (id, defense), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)`
- [ ] `CREATE TABLE effective_permission (\n\tid VARCHAR NOT NULL, \n\tpermission VARCHAR NOT NULL, \n\tPRIMARY KEY (id, permission), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)`
- [ ] `CREATE TABLE impact (\n\tid VARCHAR NOT NULL, \n\timpact VARCHAR NOT NULL, \n\tPRIMARY KEY (id, impact), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)`
- [ ] `CREATE TABLE permission (\n\tid VARCHAR NOT NULL, \n\tpermission VARCHAR NOT NULL, \n\tPRIMARY KEY (id, permission), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)`
- [ ] `CREATE TABLE system_requirement (\n\tid VARCHAR NOT NULL, \n\trequirement VARCHAR NOT NULL, \n\tPRIMARY KEY (id, requirement), \n\tFOREIGN KEY(id) REFERENCES technique (id) ON DELETE CASCADE\n)`
- [ ] `CREATE TABLE mitigate (\n\tid VARCHAR NOT NULL, \n\tsource_id VARCHAR NOT NULL, \n\ttarget_id VARCHAR NOT NULL, \n\tdescription VARCHAR, \n\tcreated_time DATETIME, \n\tmodified_time DATETIME, \n\tPRIMARY KEY (id), \n\tFOREIGN KEY(source_id) REFERENCES mitigation (id), \n\tFOREIGN KEY(target_id) REFERENCES technique (id)\n)`
- [ ] `CREATE TABLE phase (\n\ttactic_id VARCHAR NOT NULL, \n\ttech_id VARCHAR NOT NULL, \n\tPRIMARY KEY (tactic_id, tech_id), \n\tFOREIGN KEY(tactic_id) REFERENCES tactic (id) ON DELETE CASCADE, \n\tFOREIGN KEY(tech_id) REFERENCES technique (id) ON DELETE CASCADE\n)`

### bin/provigil-mitredb.rs `die`
- [ ] `Deleting {}`

### bin/provigil-mitredb.rs `utc_strptime`
- [ ] `%Y-%m-%dT%H:%M:%S%.fZ`
- [ ] `%Y-%m-%d %H:%M:%S%.6f`
- [ ] `time data '{s}' does not match format '%Y-%m-%dT%H:%M:%S.%fZ'`

### bin/provigil-mitredb.rs `parse_common_tables`
- [ ] `, V::Text(parent_id.into())), (`
- [ ] `, val(a)), (`
- [ ] `, V::Text(parent_id.into())), (`
- [ ] `, val(c)), (`
- [ ] `, V::Text(parent_id.into())), (`
- [ ] `, val(p)), (`
- [ ] `, val(&r[`

### bin/provigil-mitredb.rs `parse_table`
- [ ] `, val(get(database, o, `

### bin/provigil-mitredb.rs `parse_json_techniques`
- [ ] `, val(get(database, o, `

### bin/provigil-mitredb.rs `parse_json_mitigate_use`
- [ ] `, val(get(database, o, `

### bin/provigil-mitredb.rs `exec`
- [ ] `{e}: {sql}`

### bin/provigil-mitredb.rs `insert`
- [ ] `\"group\"`
- [ ] `INSERT INTO {quoted} ({}) VALUES ({})`
- [ ] `), vec![`
- [ ] `; cols.len()].join(`
- [ ] `{}: {sql}`
- [ ] `(sqlite3.IntegrityError) {}`

### bin/provigil-mitredb.rs `main`
- [ ] `usage: provigil-mitredb [-h] [--database DATABASE] [--json JSON]`
- [ ] `This script installs mitre.db in a directory.`
- [ ] `provigil-mitredb: error: unrecognized arguments: {other}`
- [ ] `Exception: Error: Directory not found.`
- [ ] `TypeError: expected str, bytes or os.PathLike object, not NoneType`
- [ ] `(sqlite3.OperationalError) unable to open database file`
- [ ] `FileNotFoundError: {e}: '{}'`
- [ ] `json.decoder.JSONDecodeError: {e}`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, Default::Null), (`
- [ ] `, V::Text(`
- [ ] `.into())), (`
- [ ] `, V::Text(`
- [ ] `, V::Text(`
- [ ] `.into())), (`
- [ ] `, val(get(&database, &datajson, `
- [ ] ` => softwares.rows.push(parse_table(&database, &mut l, `
- [ ] `AttributeError: 'NoneType' object has no attribute 'id'`
- [ ] `\"group\"`
- [ ] `UPDATE {table} SET revoked_by=? WHERE {table}.id = ?`
- [ ] `UPDATE technique SET subtechnique_of=? WHERE technique.id = ?`

### bin/provigil-mitredb.rs `update`
- [ ] `{}: {sql}`
- [ ] `AttributeError: 'NoneType' object has no attribute 'revoked_by'`

### wdb/agentdb.rs `ciscat_save`
- [ ] `at wdb_ciscat_save(): cannot begin transaction`

### wdb/agentdb.rs `ciscat_insert`
- [ ] `at wdb_ciscat_insert(): cannot cache statement`
- [ ] `SQLite: `

### wdb/agentdb.rs `ciscat_del`
- [ ] `at wdb_ciscat_del(): cannot cache statement`
- [ ] `Deleting old information from 'ciscat_results' table: `

### wdb/agentdb.rs `rootcheck_insert`
- [ ] `, wdb.id, `
- [ ] `{PCI_DSS: `
- [ ] `{CIS: `

### wdb/agentdb.rs `rootcheck_update`
- [ ] `, wdb.id, `

### wdb/agentdb.rs `rootcheck_delete`
- [ ] `, wdb.id, `

### wdb/agentdb.rs `agents_get_sys_osinfo`
- [ ] `wdb_exec_stmt(): `

### wdb/agentdb.rs `agents_find_package`
- [ ] `, wdb.id, `

### wdb/daemon.rs `install_signals`
- [ ] `(1225): SIGNAL [({s})-({name})] Received. Exit Cleaning...`

### wdb/daemon.rs `run_dealer`
- [ ] `Unable to bind to socket '`
- [ ] `'. Closing local server.`
- [ ] `Cannot set close-on-exec flag to socket: `
- [ ] `at run_dealer(): select(): `
- [ ] `at run_dealer(): select(): `
- [ ] `at run_dealer(): accept(): `
- [ ] `at run_dealer(): accept(): `
- [ ] `at run_dealer(): wnotify_add(`
- [ ] `New client connected (`

### wdb/daemon.rs `run_worker`
- [ ] `at run_worker(): wnotify_wait(): `
- [ ] `at run_worker(): wnotify_wait(): `
- [ ] `at run_worker(): wnotify_delete(`
- [ ] `at run_worker(): received string size is bigger than `
- [ ] ` bytes`
- [ ] `at run_worker(): at recv(): `
- [ ] `Client `
- [ ] ` disconnected.`
- [ ] `at run_worker(): OS_SendSecureTCP(`
- [ ] `at run_worker(): wnotify_add(`

### wdb/daemon_portable.rs `port_file`
- [ ] `{path}.port`

### wdb/daemon_portable.rs `bind_local`
- [ ] `127.0.0.1:0`

### wdb/daemon_portable.rs `run_dealer`
- [ ] `Unable to bind to socket '`
- [ ] `'. Closing local server.`
- [ ] `at run_dealer(): accept(): `
- [ ] `New client connected (`

### wdb/daemon_portable.rs `run_peer`
- [ ] `at run_worker(): received string size is bigger than `
- [ ] ` bytes`
- [ ] `at run_worker(): at recv(): `
- [ ] `Client `
- [ ] ` disconnected.`
- [ ] `at run_worker(): OS_SendSecureTCP(`

### wdb/delta.rs `is_valid_value`
- [ ] `user_password_warning_days_before_expiration`

### wdb/delta.rs `upsert_dbsync`
- [ ] `INSERT INTO {} VALUES( `
- [ ] `Exceeding maximum query size of `
- [ ] ` bytes adding values placeholders.`
- [ ] `Exceeding maximum query size of `
- [ ] ` bytes adding conflict clause.`
- [ ] `) ON CONFLICT DO UPDATE SET `
- [ ] `Exceeding maximum query size of `
- [ ] ` bytes adding first field.`
- [ ] `Exceeding maximum query size of `
- [ ] ` bytes adding subsequent fields.`
- [ ] `(5214): Null statement on internal cache.`
- [ ] `(5216): DB(`
- [ ] `) Could not bind delta field '`
- [ ] `' from '`
- [ ] `' scan.`
- [ ] `(5216): DB(`
- [ ] `) Could not bind delta field '`
- [ ] `' from '`
- [ ] `' scan.`

### wdb/delta.rs `delete_dbsync`
- [ ] `DELETE FROM {} WHERE `
- [ ] `Exceeding maximum query size of `
- [ ] ` bytes adding first pk.`
- [ ] `Exceeding maximum query size of `
- [ ] ` bytes adding subsequent pks.`
- [ ] ` AND {}=?`
- [ ] `(5214): Null statement on internal cache.`
- [ ] `(5216): DB(`
- [ ] `) Could not bind delta field '`
- [ ] `' from '`
- [ ] `' scan.`

### wdb/fim.rs `scan_info_update`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `scan_info_get`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `scan_info_fim_checks_control`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `syscheck_load`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `syscheck_save`
- [ ] `Checksum: `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `syscheck_save2`
- [ ] `, wdb.id, `
- [ ] `, cstr(payload), `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_find_entry`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_insert_entry`
- [ ] `, wdb.id, `
- [ ] `, ftype, `
- [ ] `, wdb.id, `
- [ ] `{:06o}`
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_insert_entry2`
- [ ] `).or_else(|| data.get(`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `(null)`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, path_escaped, `
- [ ] `, wdb.id, `
- [ ] `, item_type, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, item_type, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_update_entry`
- [ ] `, wdb.id, `
- [ ] `{:06o}`
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_delete`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_update_date_entry`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, cstr(path), `
- [ ] `, self.time(), `
- [ ] `, wdb.id, `

### wdb/fim.rs `fim_clean_old_entries`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `) Cleaning FIM DDBB. Deleting entry '`
- [ ] `' date<tscheck3 '`
- [ ] `, wdb.id, `
- [ ] `, file, `

### wdb/global.rs `(top)`
- [ ] `:config_sum`
- [ ] `:manager_host`
- [ ] `:merged_sum`
- [ ] `:node_name`
- [ ] `:os_arch`
- [ ] `:os_build`
- [ ] `:os_codename`
- [ ] `:os_major`
- [ ] `:os_minor`
- [ ] `:os_name`
- [ ] `:os_platform`
- [ ] `:os_uname`
- [ ] `:os_version`
- [ ] `:version`
- [ ] `:last_keepalive`
- [ ] `:connection_status`
- [ ] `:disconnection_time`
- [ ] `:group_config_status`
- [ ] `:status_code`

### wdb/global.rs `sha256_sized`
- [ ] `{b:02x}`

### wdb/global.rs `w_get_timestamp`
- [ ] `{}/{:02}/{:02} {:02}:{:02}:{:02}`

### wdb/global.rs `bind_int`
- [ ] `, wdb.id, `

### wdb/global.rs `bind_int64`
- [ ] `, wdb.id, `

### wdb/global.rs `bind_text`
- [ ] `, wdb.id, `

### wdb/global.rs `exec_logged`
- [ ] `wdb_exec_stmt(): `

### wdb/global.rs `global_insert_agent`
- [ ] `Invalid group name '`
- [ ] `' in multigroup '`
- [ ] `' for agent `

### wdb/global.rs `global_update_agent_groups_hash`
- [ ] `Unable to get group column for agent '`
- [ ] `'. The groups_hash column won't be updated`

### wdb/global.rs `global_adjust_v4`
- [ ] `SQLite: `
- [ ] `, wdb.id, `

### wdb/global.rs `global_insert_agent_group`
- [ ] `Cannot insert '`

### wdb/global.rs `global_select_group_belong`
- [ ] `The agent's groups exceed the socket maximum response size.`
- [ ] `Failed to get agent groups: `

### wdb/global.rs `global_insert_agent_belong`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`

### wdb/global.rs `global_delete_group`
- [ ] `Couldn't recalculate hash group for agent: '`
- [ ] `{agent_id:03}`
- [ ] `SQLite: `

### wdb/global.rs `global_select_groups`
- [ ] `The groups exceed the socket maximum response size.`
- [ ] `Failed to get groups: `

### wdb/global.rs `global_validate_sync_status`
- [ ] `Failed to get old sync_status for agent '`

### wdb/global.rs `global_get_sync_status`
- [ ] `sqlite3_step(): `

### wdb/global.rs `global_sync_agent_info_get`
- [ ] `Cannot begin transaction`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`
- [ ] `Cannot cache statement`
- [ ] `, wdb.id, `
- [ ] `Cannot bind sql statement`
- [ ] `Cannot set sync_status for agent `
- [ ] `Cannot set sync_status for agent `

### wdb/global.rs `global_calculate_agent_group_csv`
- [ ] `Group hash is NULL`
- [ ] `The agent's groups exceed the socket maximum response size.`
- [ ] `SQL statement execution failed`

### wdb/global.rs `global_set_agent_group_context`
- [ ] `Error executing setting the agent group context: `

### wdb/global.rs `global_set_agent_group_hash`
- [ ] `Error executing setting the agent group hash: `

### wdb/global.rs `global_get_groups_integrity`
- [ ] `, wdb.id, `

### wdb/global.rs `global_get_agent_max_group_priority`
- [ ] `wdb_exec_stmt(): `

### wdb/global.rs `global_assign_agent_group`
- [ ] `Invalid groups set information`
- [ ] `Unable to create agent '`
- [ ] `' in never_connected state`
- [ ] `Unable to insert group '`
- [ ] `' for agent '`
- [ ] `', retry failed after creating agent in never_connected state.`
- [ ] `Unable to insert group '`
- [ ] `' for agent '`
- [ ] `', agent already exists, groups not synced.`
- [ ] `Unable to insert group '`
- [ ] `' for agent '`
- [ ] `', undefined error.`
- [ ] `Unable to insert group '`
- [ ] `' for agent '`
- [ ] `', agent not found.`
- [ ] `Invalid response from wdb_global_find_group.`
- [ ] `Unable to find the id of the group '`

### wdb/global.rs `global_unassign_agent_group`
- [ ] `Invalid groups remove information`
- [ ] `Unable to delete group '`
- [ ] `' for agent '`
- [ ] `Invalid response from wdb_global_find_group.`
- [ ] `Unable to find the id of the group '`

### wdb/global.rs `global_if_empty_set_default_agent_group`
- [ ] `Agent '`
- [ ] `{id:03}`
- [ ] `' reassigned to 'default' group`
- [ ] `There was an error assigning the agent '`
- [ ] `{id:03}`
- [ ] `' to default group`

### wdb/global.rs `global_groups_number_get`
- [ ] `wdb_exec_stmt(): `

### wdb/global.rs `global_validate_group_name`
- [ ] `Invalid group name. The group '`
- [ ] `' exceeds the maximum length of `
- [ ] ` characters permitted`
- [ ] `Invalid group name. '`
- [ ] `' contains invalid characters`
- [ ] `Invalid group name. '.' represents the current directory in unix systems`
- [ ] `Invalid group name. '..' represents the parent directory in unix systems`

### wdb/global.rs `global_validate_groups`
- [ ] `The groups assigned to agent `
- [ ] `{agent_id:03}`
- [ ] ` exceed the maximum of `
- [ ] ` permitted.`

### wdb/global.rs `global_set_agent_groups`
- [ ] `), j_group_info.get(`
- [ ] `Invalid groups set information`
- [ ] `There was an error un-assigning the groups to agent '`
- [ ] `{agent_id:03}`
- [ ] `There was an error cleaning the previous agent groups`
- [ ] `Agent group set in empty_only mode ignored because the agent already contains groups`
- [ ] `Agent name is required when overriding groups for agent '`
- [ ] `{agent_id:03}`
- [ ] `Agent name is not provided for agent '`
- [ ] `{agent_id:03}`
- [ ] `', the agent not will not be created if it does not exist`
- [ ] `There was an error assigning the groups to agent '`
- [ ] `{agent_id:03}`
- [ ] `Couldn't recalculate hash group for agent: '`
- [ ] `{agent_id:03}`

### wdb/global.rs `global_recalculate_agent_groups_hash`
- [ ] `The groups were empty right after the set for agent '`
- [ ] `{agent_id:03}`
- [ ] `There was an error assigning the groups context to agent '`
- [ ] `{agent_id:03}`

### wdb/global.rs `global_recalculate_agent_groups_hash_without_sync_status`
- [ ] `No groups in belongs table for agent '`
- [ ] `{agent_id:03}`
- [ ] `There was an error assigning the groups hash to agent '`
- [ ] `{agent_id:03}`

### wdb/global.rs `global_recalculate_all_agent_groups_hash`
- [ ] `Couldn't recalculate hash group for agent: '`
- [ ] `{id:03}`
- [ ] `SQL statement execution failed`

### wdb/global.rs `global_sync_agent_groups_get`
- [ ] `Invalid groups sync condition`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `Cannot set group_sync_status for agent `

### wdb/global.rs `global_add_global_group_hash_to_response`
- [ ] `Invalid JSON object.`
- [ ] `Cannot obtain the global group hash`

### wdb/global.rs `global_sync_agent_info_set`
- [ ] `:sync_status`

### wdb/global.rs `global_get_agents_to_disconnect`
- [ ] `Cannot set connection_status for agent `
- [ ] `Invalid element returned by disconnect query`

### wdb/global.rs `global_agent_exists`
- [ ] `, wdb.id, `

### wdb/global.rs `global_reset_agents_connection`
- [ ] `, wdb.id, `

### wdb/global.rs `global_get_agents_by_connection_status`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`

### wdb/global.rs `global_create_backup`
- [ ] `).replace('/', `
- [ ] `{WDB_BACKUP_FOLDER}/{WDB_GLOB_BACKUP_NAME}-{timestamp}{}`
- [ ] `err Cannot commit current transaction to create backup`
- [ ] `VACUUM INTO ?;`
- [ ] `err DB(`
- [ ] `) sqlite3_prepare_v2(): `
- [ ] `err DB(`
- [ ] `) sqlite3_bind_text(): `
- [ ] `err SQLite: `
- [ ] `{rel}.gz`
- [ ] `Created Global database backup \"`
- [ ] `err Failed during database backup compression`

### wdb/global.rs `global_remove_old_backups`
- [ ] `Unable to open backup directory '`
- [ ] `{WDB_BACKUP_FOLDER}/{n}`
- [ ] `Deleted Global database backup: \"`

### wdb/global.rs `global_get_backups`
- [ ] `Unable to open backup directory '`

### wdb/global.rs `global_restore_backup`
- [ ] `{WDB2_DIR}/{WDB_GLOB_NAME}.db`
- [ ] `Creating pre-restore Global DB snapshot failed. Backup restore stopped: `
- [ ] `Unable to found a snapshot to restore`
- [ ] `err Unable to found a snapshot to restore`
- [ ] `{WDB2_DIR}/{WDB_GLOB_NAME}.db.back`
- [ ] `Renaming `
- [ ] `, global_rel, `
- [ ] `Failed during backup decompression`
- [ ] `err Failed during backup decompression`

### wdb/global.rs `global_get_most_recent_backup`
- [ ] `Unable to open backup directory '`

### wdb/global.rs `global_get_oldest_backup`
- [ ] `Unable to open backup directory '`

### wdb/global.rs `compress_gzfile`
- [ ] `in w_compress_gzfile(): fopen error `
- [ ] `in w_compress_gzfile(): gzopen error `
- [ ] `in w_compress_gzfile(): Compression error: `

### wdb/global.rs `uncompress_gzfile`
- [ ] `in w_uncompress_gzfile(): fopen error `
- [ ] `in w_uncompress_gzfile(): gzopen error `
- [ ] `in w_uncompress_gzfile(): gzread error: '`

### wdb/http.rs `log`
- [ ] `:router`

### wdb/http.rs `new`
- [ ] `Unspecified empty statement`

### wdb/http.rs `json_str`
- [ ] `' => out.extend_from_slice(b`
- [ ] `\\u{c:04x}`

### wdb/http.rs `get_v1_agents_ids`
- [ ] `SELECT id FROM agent WHERE id > 0`

### wdb/http.rs `get_v1_agents_ids_groups`
- [ ] `SELECT b.id_agent AS id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE b.id_agent > 0;`

### wdb/http.rs `get_v1_agents_ids_groups_param`
- [ ] `Missing parameter: name`
- [ ] `Missing parameter: name`
- [ ] `SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > 0;`

### wdb/http.rs `get_v1_agents_param_groups`
- [ ] `Missing parameter: agent id`
- [ ] `Missing parameter: id`
- [ ] `SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority`

### wdb/http.rs `get_v1_agents_sync`
- [ ] `SELECT COUNT(*) FROM agent WHERE id > 0 AND sync_status = ?;`
- [ ] `SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > 0 AND sync_status = 'syncreq';`
- [ ] `SELECT key, value FROM labels WHERE id = ?;`
- [ ] `SELECT id, version FROM agent WHERE id > 0 AND sync_status = 'syncreq_keepalive';`
- [ ] `SELECT id, version, connection_status, disconnection_time, status_code FROM agent WHERE id > 0 AND sync_status = 'syncreq_status';`
- [ ] `UPDATE agent SET sync_status = 'synced' WHERE id > 0;`

### wdb/http.rs `jid`
- [ ] `Missing required key.`

### wdb/http.rs `post_v1_agents_sync`
- [ ] `UPDATE agent SET config_sum = ?, ip = ?, manager_host = ?, merged_sum = ?, name = ?, node_name = ?, os_arch = ?, os_build = ?, os_codename = ?, os_major = ?, os_minor = ?, os_name = ?, os_platform = ?, os_uname = ?, os_version = ?, version = ?, last_keepalive = ?, connection_status = ?, disconnection_time = ?, group_config_status = ?, status_code= ?, sync_status = 'synced' WHERE id = ?;`
- [ ] `DELETE FROM labels WHERE id = ?;`
- [ ] `INSERT INTO labels (id, key, value) VALUES (?, ?, ?);`
- [ ] `Cannot set label for agent: {id}, `
- [ ] `UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'),sync_status = 'synced',connection_status = 'active',disconnection_time = 0,status_code = 0, version = ? WHERE id = ?;`
- [ ] `UPDATE agent SET connection_status = ?, sync_status = 'synced', disconnection_time = ?, status_code = ?, version = ? WHERE id = ?;`

### wdb/http.rs `post_v1_agents_summary`
- [ ] `SELECT COUNT(*) as quantity, connection_status AS status FROM agent WHERE id > 0 GROUP BY status ORDER BY status ASC limit 5;`
- [ ] `SELECT COUNT(*) as q, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '' GROUP BY b.id_group ORDER BY q DESC LIMIT 5;`
- [ ] `SELECT COUNT(*) as quantity, os_platform AS platform FROM agent WHERE id > 0 AND os_platform IS NOT NULL AND os_platform <> '' GROUP BY platform ORDER BY quantity DESC limit 5;`
- [ ] `SELECT id, connection_status AS status FROM agent WHERE id > 0;`
- [ ] `SELECT b.id_agent, g.name AS group_name FROM belongs b JOIN 'group' g ON b.id_group=g.id WHERE b.id_agent > 0 AND g.name IS NOT NULL AND g.name <> '';`
- [ ] `SELECT id, os_platform AS platform FROM agent WHERE id > 0 AND os_platform IS NOT NULL AND os_platform <> '';`

### wdb/http.rs `post_v1_agents_restart_info`
- [ ] `SELECT id, version FROM agent WHERE connection_status = 'active'`
- [ ] `) && body.at(`
- [ ] `)?.is_array() && body.at(`
- [ ] ` } else { `
- [ ] ` AND id `
- [ ] `IN ({select_ids})`

### wdb/http.rs `global_pre`
- [ ] `Couldn't open DB global: `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `Database disabled: `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `Cannot begin transaction`

### wdb/http.rs `redirect`
- [ ] `Database connection failed`
- [ ] `/v1/agents/ids/groups/:name`
- [ ] `/v1/agents/:agent_id/groups`
- [ ] `, _) => Err(b`
- [ ] `, _) => Err(b`
- [ ] `Method not implemented`
- [ ] `/v1/agents/ids/groups/:name`
- [ ] `/v1/agents/:agent_id/groups`

### wdb/http.rs `stop`
- [ ] `Stopping server thread`

### wdb/http.rs `start_api`
- [ ] `, format!(`
- [ ] `GET: {endpoint} request parameters: `
- [ ] `, format!(`
- [ ] ` on endpoint: `
- [ ] `Error starting API. Failed to listen on socket`
- [ ] `API socket permissions set to 0660`
- [ ] `, format!(`
- [ ] `API started successfully`

### wdb/httplib.rs `parse_range_header`
- [ ] `bytes=`

### wdb/httplib.rs `status_message`
- [ ] `Switching Protocol`
- [ ] `Early Hints`
- [ ] `Non-Authoritative Information`
- [ ] `No Content`
- [ ] `Reset Content`
- [ ] `Partial Content`
- [ ] `Already Reported`
- [ ] `IM Used`
- [ ] `Multiple Choice`
- [ ] `Moved Permanently`
- [ ] `See Other`
- [ ] `Not Modified`
- [ ] `Use Proxy`
- [ ] `Temporary Redirect`
- [ ] `Permanent Redirect`
- [ ] `Bad Request`
- [ ] `Payment Required`
- [ ] `Not Found`
- [ ] `Method Not Allowed`
- [ ] `Not Acceptable`
- [ ] `Proxy Authentication Required`
- [ ] `Request Timeout`
- [ ] `Length Required`
- [ ] `Precondition Failed`
- [ ] `Payload Too Large`
- [ ] `URI Too Long`
- [ ] `Unsupported Media Type`
- [ ] `Range Not Satisfiable`
- [ ] `Expectation Failed`
- [ ] `I'm a teapot`
- [ ] `Misdirected Request`
- [ ] `Unprocessable Entity`
- [ ] `Failed Dependency`
- [ ] `Too Early`
- [ ] `Upgrade Required`
- [ ] `Precondition Required`
- [ ] `Too Many Requests`
- [ ] `Request Header Fields Too Large`
- [ ] `Unavailable For Legal Reasons`
- [ ] `Not Implemented`
- [ ] `Bad Gateway`
- [ ] `Service Unavailable`
- [ ] `Gateway Timeout`
- [ ] `HTTP Version Not Supported`
- [ ] `Variant Also Negotiates`
- [ ] `Insufficient Storage`
- [ ] `Loop Detected`
- [ ] `Not Extended`
- [ ] `Network Authentication Required`
- [ ] `Internal Server Error`

### wdb/httplib.rs `parse`
- [ ] `content-type:`
- [ ] `content-disposition:`
- [ ] `form-data;`
- [ ] `' && s[s.len() - 1] == b'`
- [ ] `filename*`
- [ ] `utf-8''`

### wdb/httplib.rs `parse_multipart_boundary`
- [ ] `boundary=`
- [ ] `' && b[b.len() - 1] == b'`

### wdb/httplib.rs `process_request`
- [ ] `HTTP/1.1 {} {}\r\n\r\n`

### wdb/httplib.rs `read_content`
- [ ] ` || encoding == b`
- [ ] ` || encoding.windows(2).any(|w| w == b`

### wdb/httplib.rs `write_response`
- [ ] `timeout={KEEPALIVE_TIMEOUT_SECOND}, max={KEEPALIVE_MAX_COUNT}`
- [ ] `HTTP/1.1 {} {}\r\n`

### wdb/httplib.rs `apply_ranges`
- [ ] `multipart/byteranges; boundary=`
- [ ] `Content-Type: `
- [ ] `Content-Range: `

### wdb/httplib.rs `make_content_range_header_field`
- [ ] `bytes `

### wdb/httplib.rs `make_multipart_data_boundary`
- [ ] `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`

### wdb/integrity.rs `sha1_hex`
- [ ] `{b:02x}`

### wdb/integrity.rs `report_removed`
- [ ] `Router handle not available.`
- [ ] `Invalid handle to send delete message. Agent `

### wdb/integrity.rs `wdbi_remove_by_pk`
- [ ] `PK value is NULL during the removal of the component '`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/integrity.rs `calculate_stmt_checksum`
- [ ] `, wdb.id, `
- [ ] `, name(component), `
- [ ] ` component has more than one element with the same PK value '`

### wdb/integrity.rs `wdbi_checksum`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`

### wdb/integrity.rs `wdbi_checksum_range`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`

### wdb/integrity.rs `wdbi_delete`
- [ ] `Cannot begin transaction`
- [ ] `, wdb.id, `

### wdb/integrity.rs `wdbi_update_attempt`
- [ ] `Cannot begin transaction`
- [ ] `, wdb.id, `

### wdb/integrity.rs `wdbi_update_completion`
- [ ] `Cannot begin transaction`
- [ ] `, wdb.id, `

### wdb/integrity.rs `wdbi_set_last_completion`
- [ ] `Cannot begin transaction`
- [ ] `, wdb.id, `

### wdb/integrity.rs `wdbi_query_checksum`
- [ ] `, wdb.id, `
- [ ] `, cstr(payload), `
- [ ] `No such string 'begin' in JSON payload.`
- [ ] `No such string 'end' in JSON payload.`
- [ ] `No such string 'checksum' in JSON payload.`
- [ ] `No such string 'id' in JSON payload.`
- [ ] `Agent '`
- [ ] `, name(component), `
- [ ] `Agent '`
- [ ] `, name(component), `
- [ ] `, format!(`

### wdb/integrity.rs `wdbi_query_clear`
- [ ] `, wdb.id, `
- [ ] `, cstr(payload), `
- [ ] `No such string 'id' in JSON payload.`
- [ ] `Cannot begin transaction`
- [ ] `, wdb.id, `

### wdb/integrity.rs `wdbi_get_last_manager_checksum`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`
- [ ] `wdb_exec_stmt(): `

### wdb/integrity.rs `wdbi_check_sync_status`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`
- [ ] `wdb_exec_stmt(): `
- [ ] `Failed to get agent's sync status data`

### wdb/integrity.rs `get_global_group_hash`
- [ ] `Using global group hash from cache`
- [ ] `Database structure not initialized. Unable to calculate global group hash.`
- [ ] `New global group hash calculated and stored in cache.`
- [ ] `No group hash was found to calculate the global group hash.`

### wdb/metadata.rs `metadata_get_entry`
- [ ] `SELECT value FROM metadata WHERE key = ?;`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/metadata.rs `count_tables_with_name`
- [ ] `SELECT count(name) FROM sqlite_master WHERE type='table' AND name=?;`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `

### wdb/mod.rs `errmsg`
- [ ] `out of memory`

### wdb/mod.rs `st`
- [ ] `statement cached`

### wdb/mod.rs `wdb_step`
- [ ] `Maximum attempts exceeded for sqlite3_step()`

### wdb/mod.rs `wdb_prepare`
- [ ] `Maximum attempts exceeded for sqlite3_prepare_v2()`

### wdb/mod.rs `open_global`
- [ ] `{WDB2_DIR}/{WDB_GLOB_NAME}.db`
- [ ] `Global database not found, creating.`
- [ ] `Couldn't create SQLite database '`
- [ ] `Can't open SQLite database '`

### wdb/mod.rs `open_mitre`
- [ ] `{WDB_DIR}/{WDB_MITRE_NAME}.db`
- [ ] `Can't open SQLite database '`

### wdb/mod.rs `open_agent2`
- [ ] `{agent_id:03}`
- [ ] `{WDB2_DIR}/{sagent_id}.db`
- [ ] `No SQLite database found for agent '`
- [ ] `', creating.`
- [ ] `Couldn't create SQLite database '`
- [ ] `Can't open SQLite database '`

### wdb/mod.rs `open_tasks`
- [ ] `{WDB_TASK_DIR}/{WDB_TASK_NAME}.db`
- [ ] `Tasks database not found, creating.`
- [ ] `Couldn't create SQLite database '`
- [ ] `Can't open SQLite database '`

### wdb/mod.rs `create_agent_db2`
- [ ] `Profile database not found, creating.`
- [ ] `Couldn't open profile '`
- [ ] `{WDB2_DIR}/{agent_id}.db`
- [ ] `{rel}.new`
- [ ] `Couldn't create database '`
- [ ] `(1124): Could not rename file '`
- [ ] `' to '`
- [ ] `' due to [(`

### wdb/mod.rs `any_transaction`
- [ ] `sqlite3_prepare_v2(): `
- [ ] `SQLite: `

### wdb/mod.rs `begin`
- [ ] `BEGIN;`

### wdb/mod.rs `commit`
- [ ] `COMMIT;`

### wdb/mod.rs `rollback`
- [ ] `ROLLBACK;`

### wdb/mod.rs `create_file`
- [ ] `Couldn't create SQLite database '`
- [ ] `Preparing statement: `
- [ ] `Stepping statement: `
- [ ] `Ignoring chown when creating file from SQL.`

### wdb/mod.rs `vacuum`
- [ ] `VACUUM;`
- [ ] `SQLite: `

### wdb/mod.rs `get_db_state`
- [ ] `CREATE TEMP TABLE IF NOT EXISTS s(rowid INTEGER PRIMARY KEY, pageno INT);`
- [ ] `Error creating temporary table.`
- [ ] `DELETE FROM s;`
- [ ] `Error truncate temporary table.`
- [ ] `INSERT INTO s(pageno) SELECT pageno FROM dbstat ORDER BY path;`
- [ ] `Error in select from temporary table.`
- [ ] `Error inserting into temporary table.`

### wdb/mod.rs `get_db_free_pages_percentage`
- [ ] `SELECT page_count FROM pragma_page_count();`
- [ ] `Error getting total_pages for '`
- [ ] `' database.`
- [ ] `SELECT freelist_count FROM pragma_freelist_count();`
- [ ] `Error getting free_pages for '`
- [ ] `' database.`

### wdb/mod.rs `execute_single_int_select_query`
- [ ] `sqlite3_prepare_v2(): `
- [ ] `SQLite: `

### wdb/mod.rs `execute_non_select_query`
- [ ] `sqlite3_prepare_v2(): `
- [ ] `SQLite: `

### wdb/mod.rs `select_from_temp_table`
- [ ] `SELECT sum(s1.pageno+1==s2.pageno)*1.0/count(*) FROM s AS s1, s AS s2 WHERE s1.rowid+1=s2.rowid;`
- [ ] `sqlite3_prepare_v2(): `
- [ ] `SQLite: `

### wdb/mod.rs `insert_info`
- [ ] `{WDB2_DIR}/{WDB_GLOB_NAME}.db`
- [ ] `Couldn't open SQLite database '`
- [ ] `INSERT INTO info (key, value) VALUES (?, ?);`
- [ ] `SQLite: `

### wdb/mod.rs `commit_old`
- [ ] `Agent '`
- [ ] `' database commited. Time: `
- [ ] `{ms:.3}`

### wdb/mod.rs `check_fragmentation`
- [ ] `Couldn't get current state for the database '`
- [ ] `Couldn't get last vacuum info for the database '`
- [ ] `Couldn't execute commit statement, before vacuum, for the database '`
- [ ] `Couldn't execute vacuum for the database '`
- [ ] `Vacuum executed on the '`
- [ ] `' database. Time: `
- [ ] `{ms:.3}`
- [ ] `Couldn't get fragmentation after vacuum for the database '`
- [ ] `Couldn't update last vacuum info for the database '`
- [ ] `After vacuum, the database '`
- [ ] `' has become just as fragmented or worse`

### wdb/mod.rs `get_last_vacuum_data`
- [ ] `SELECT key, value FROM metadata WHERE key in ('last_vacuum_time', 'last_vacuum_value');`
- [ ] `No vacuum data in metadata table.`
- [ ] `), item.get(`
- [ ] `It was not possible to get key or value from database response.`
- [ ] `Missing field last_vacuum_time or last_vacuum_value from metadata table.`

### wdb/mod.rs `update_last_vacuum_data`
- [ ] `INSERT INTO metadata (key, value) VALUES ('last_vacuum_time', ?), ('last_vacuum_value', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value;`
- [ ] `sqlite3_prepare_v2(): `
- [ ] `(5211): SQL error: '`

### wdb/mod.rs `close_old`
- [ ] `Closing database for agent `

### wdb/mod.rs `exec_stmt_silent`
- [ ] `SQL statement execution failed`

### wdb/mod.rs `exec_row_stmt_multi_column`
- [ ] `SQL statement execution failed`

### wdb/mod.rs `exec_stmt_sized`
- [ ] `Invalid SQL statement.`

### wdb/mod.rs `exec_stmt_send`
- [ ] `Invalid SQL statement.`
- [ ] `Socket `
- [ ] ` error setting timeout: `
- [ ] `Socket `
- [ ] ` error: `
- [ ] `SQL row response for statement `
- [ ] ` is too big to be sent`

### wdb/mod.rs `exec_stmt`
- [ ] `Invalid SQL statement.`

### wdb/mod.rs `exec_row_stmt_single_column`
- [ ] `Invalid SQL statement.`
- [ ] `SQL statement execution failed`

### wdb/mod.rs `exec`
- [ ] `sqlite3_prepare_v2(): `
- [ ] `wdb_exec_stmt(): `

### wdb/mod.rs `stmt_cache`
- [ ] `, wdb.id, `
- [ ] `, index, `
- [ ] `, wdb.id, `
- [ ] `, index, `

### wdb/mod.rs `sql_exec`
- [ ] `, wdb.id, `

### wdb/mod.rs `remove_database`
- [ ] `{WDB2_DIR}/{agent_id}.db`
- [ ] `(1129): Could not unlink file '`
- [ ] `' due to [(`

### wdb/mod.rs `remove_multiple_agents`
- [ ] `Invalid agent ID when deleting database '`
- [ ] `Invalid agent ID`
- [ ] `Can't close`
- [ ] `Removing db for agent '`
- [ ] `Can't delete`
- [ ] `Deleting databases. JSON output: `

### wdb/mod.rs `journal_wal`
- [ ] `Cannot set database journaling mode to WAL: '`

### wdb/mod.rs `enable_foreign_keys`
- [ ] `Cannot enable foreign keys: '`

### wdb/mod.rs `set_synchronous_normal`
- [ ] `Cannot set synchronous mode: '`

### wdb/mod.rs `init_stmt_in_cache`
- [ ] `Cannot begin transaction`
- [ ] `Cannot cache statement`

### wdb/mod.rs `get_cache_stmt`
- [ ] `, wdb.id, `
- [ ] `, st.sql(), `
- [ ] `, wdb.id, `

### wdb/mod.rs `errno_text`
- [ ] ` (os error`

### wdb/parser.rs `near`
- [ ] `, near '`

### wdb/parser.rs `parse`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query: `
- [ ] `err Invalid DB query syntax`
- [ ] `DB(000) Invalid DB query actor: `
- [ ] `err Invalid DB query actor: '`

### wdb/parser.rs `parse_agent`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid DB query syntax`
- [ ] `Invalid agent ID '`
- [ ] `err Invalid agent ID '`
- [ ] `{agent_id:03}`
- [ ] `Agent `
- [ ] ` query: `
- [ ] `Couldn't open DB global: `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `err Couldn't open DB global`
- [ ] `Database disabled: `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `err DB global disabled.`
- [ ] `No agent with id `
- [ ] ` found.`
- [ ] `err Agent not found`
- [ ] `Couldn't open DB for agent '`
- [ ] `err Couldn't open DB for agent `
- [ ] `, sagent_id, `
- [ ] `, sagent_id, `
- [ ] `err Invalid DB query syntax`
- [ ] `Invalid DB query syntax.`
- [ ] `, sagent_id, `
- [ ] `, $what, `
- [ ] `, sagent_id, `
- [ ] `, $what, `
- [ ] `err Invalid Syscheck query syntax`
- [ ] `FIM file`
- [ ] `FIM registry`
- [ ] `FIM registry key`
- [ ] `FIM registry value`
- [ ] `, sagent_id, `
- [ ] `, sagent_id, `
- [ ] `err Invalid Rootcheck query syntax`
- [ ] `Invalid DB query syntax.`
- [ ] `, sagent_id, `
- [ ] `, sagent_id, `
- [ ] `err Cannot execute SQL query`
- [ ] `, sagent_id, `
- [ ] `err Cannot close database`
- [ ] `err Cannot remove database`
- [ ] `, sagent_id, `
- [ ] `err Cannot begin transaction`
- [ ] `, sagent_id, `
- [ ] `err Cannot end transaction`
- [ ] `, sagent_id, `
- [ ] `err Cannot close database`
- [ ] `, sagent_id, `
- [ ] `, sagent_id, `
- [ ] `err Invalid Syscollector query syntax`
- [ ] `DB({sagent_id})`
- [ ] `DB({sagent_id})`
- [ ] `DB({sagent_id})`
- [ ] `, sagent_id, `
- [ ] `, sagent_id, `
- [ ] `err Invalid DB query syntax`

### wdb/parser.rs `check_db_file`
- [ ] `{WDB2_DIR}/{}.db`
- [ ] `, rel, `

### wdb/parser.rs `vacuum_command`
- [ ] ` Cannot end transaction.`
- [ ] `err Cannot end transaction`
- [ ] ` Cannot vacuum database.`
- [ ] `err Cannot vacuum database`
- [ ] ` Couldn't get fragmentation after vacuum for the database.`
- [ ] `err Vacuum performed, but couldn't get fragmentation information after vacuum`
- [ ] ` Couldn't update last vacuum info for the database.`
- [ ] `err Vacuum performed, but last vacuum information couldn't be updated in the metadata table`

### wdb/parser.rs `fragmentation_command`
- [ ] ` Cannot get database fragmentation.`
- [ ] `err Cannot get database fragmentation`

### wdb/parser.rs `sleep_command`
- [ ] ` Invalid DB query syntax.`
- [ ] ` query error near: `
- [ ] `err Invalid DB query syntax`

### wdb/parser.rs `parse_provigildb`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid DB query syntax`
- [ ] `(null)`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err No agents id provided`

### wdb/parser.rs `parse_mitre`
- [ ] `Mitre query: `
- [ ] `Couldn't open DB mitre: `
- [ ] `, WDB_MITRE_NAME, `
- [ ] `err Couldn't open DB mitre`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid DB query syntax`
- [ ] `Mitre DB Cannot execute SQL query; err database `
- [ ] `Mitre DB SQL query: `
- [ ] `err Cannot execute Mitre database query; `
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid DB query syntax`

### wdb/parser.rs `parse_global_actor`
- [ ] `Global query: `
- [ ] `Couldn't open DB global: `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `err Couldn't open DB global`
- [ ] `Database disabled: `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `err DB global disabled.`

### wdb/parser.rs `parse_task_actor`
- [ ] `Task query: `
- [ ] `Couldn't open DB task: `
- [ ] `, WDB_TASK_NAME, `
- [ ] `err Couldn't open DB task`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid DB query syntax`

### wdb/parser_agent.rs `parse_syscheck`
- [ ] `, wdb.id, `
- [ ] `err Invalid FIM query syntax`
- [ ] `, wdb.id, `
- [ ] `err Cannot get fim scan info.`
- [ ] `, wdb.id, `
- [ ] `err Cannot update fim date field.`
- [ ] `, wdb.id, `
- [ ] `err Cannot clean fim database.`
- [ ] `, wdb.id, `
- [ ] `err Invalid Syscheck query syntax`
- [ ] `, wdb.id, `
- [ ] `err Cannot save fim control message`
- [ ] `, wdb.id, `
- [ ] `err Cannot save fim control message`
- [ ] `, wdb.id, `
- [ ] `err Cannot load Syscheck`
- [ ] `, wdb.id, `
- [ ] `err Cannot delete Syscheck`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `err Invalid Syscheck query syntax`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `err Invalid Syscheck query syntax`
- [ ] `, wdb.id, `
- [ ] `FIM query: `
- [ ] `err Invalid Syscheck query syntax`
- [ ] `, wdb.id, `
- [ ] `err Cannot save Syscheck`
- [ ] `, wdb.id, `
- [ ] `err Cannot save Syscheck`
- [ ] `, wdb.id, `
- [ ] `err Cannot perform range checksum`
- [ ] `ok no_data`
- [ ] `ok checksum_fail`
- [ ] `, wdb.id, `
- [ ] `err Cannot perform range checksum`
- [ ] `, wdb.id, `
- [ ] `DB query error near: `
- [ ] `err Invalid Syscheck query syntax`

### wdb/parser_agent.rs `parse_syscollector`
- [ ] `, wdb.id, `
- [ ] `err Invalid Syscollector query syntax`
- [ ] `, wdb.id, `
- [ ] `, query, `
- [ ] `, wdb.id, `
- [ ] `err Invalid Syscollector query syntax`
- [ ] `, wdb.id, `
- [ ] `err Cannot save Syscollector`
- [ ] `, wdb.id, `
- [ ] `err Cannot perform range checksum`
- [ ] `ok no_data`
- [ ] `ok checksum_fail`
- [ ] `, wdb.id, `
- [ ] `err Cannot perform range checksum`
- [ ] `, wdb.id, `
- [ ] `DB query error near: `
- [ ] `err Invalid Syscollector query syntax`

### wdb/parser_agent.rs `parse_sca`
- [ ] `err Invalid Security Configuration Assessment query syntax`
- [ ] `err Invalid configuration assessment query syntax`
- [ ] `Invalid Security Configuration Assessment query syntax.`
- [ ] `Security Configuration Assessment query: `
- [ ] `Invalid Security Configuration Assessment query syntax.`
- [ ] `Security Configuration Assessment query: `
- [ ] `Invalid configuration assessment query syntax.`
- [ ] `configuration assessment query: `
- [ ] `ok not found`
- [ ] `ok found `
- [ ] `Cannot query Security Configuration Assessment.`
- [ ] `err Cannot query Security Configuration Assessment`
- [ ] `Cannot update Security Configuration Assessment information.`
- [ ] `err Cannot update Security Configuration Assessment information.`
- [ ] `Cannot delete Security Configuration Assessment information.`
- [ ] `err Cannot delete Security Configuration Assessment information.`
- [ ] `Cannot delete Security Configuration Assessment checks.`
- [ ] `err Cannot delete Security Configuration Assessment checks.`
- [ ] `Cannot delete Security Configuration Assessment information.`
- [ ] `err Cannot delete Security Configuration Assessment check information.`
- [ ] `err Cannot query Security Configuration Assessment global`
- [ ] `err Cannot query Security Configuration Assessment scan`
- [ ] `err Cannot query Security Configuration Assessment scan`
- [ ] `err Cannot query policy scan`
- [ ] `err Cannot query policy scan`
- [ ] `Cannot save Security Configuration Assessment information.`
- [ ] `err Cannot save Security Configuration Assessment global information.`
- [ ] `Cannot save configuration assessment information.`
- [ ] `err Cannot save configuration assessment global information.`
- [ ] `Cannot save configuration assessment information.`
- [ ] `err Cannot save configuration assessment information.`
- [ ] `Cannot save configuration assessment information.`
- [ ] `err Cannot save configuration assessment information.`
- [ ] `Cannot save configuration assessment information.`
- [ ] `err Cannot save configuration assessment information.`
- [ ] `Invalid configuration assessment query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid Rootcheck query syntax`

### wdb/parser_agent.rs `parse_sca_insert`
- [ ] `err Invalid Security Configuration Assessment query syntax`
- [ ] `Invalid Security Configuration Assessment query syntax. JSON object not found or invalid`
- [ ] `Invalid Security Configuration Assessment query syntax. JSON object not found or invalid`
- [ ] `Malformed JSON: field 'id' must be a number`
- [ ] `Malformed JSON: field 'id' cannot be negative`
- [ ] `Malformed JSON: field 'policy_id' not found`
- [ ] `Malformed JSON: field 'policy_id' must be a string`
- [ ] `Malformed JSON: field 'check' not found`
- [ ] `Malformed JSON: field 'id' not found`
- [ ] `Malformed JSON: field 'id' must be a number`
- [ ] `Malformed JSON: field 'title' not found`
- [ ] `Malformed JSON: field 'title' must be a string`
- [ ] `Malformed JSON: field '`
- [ ] `' must be a string`
- [ ] `12 fields`
- [ ] `not applicable`
- [ ] `Cannot save Security Configuration Assessment information.`
- [ ] `err Cannot save Security Configuration Assessment information.`

### wdb/parser_agent.rs `bad_cmd`
- [ ] `DB query error near: `

### wdb/parser_agent.rs `parse_netinfo`
- [ ] `Invalid Network query syntax.`
- [ ] `Network query: `
- [ ] `err Invalid Network query syntax`
- [ ] `Cannot save Network information.`
- [ ] `err Cannot save Network information.`
- [ ] `Cannot delete old network information.`
- [ ] `err Cannot delete old network information.`
- [ ] `Invalid netinfo query syntax.`
- [ ] `err Invalid netinfo query syntax`

### wdb/parser_agent.rs `parse_netproto`
- [ ] `Invalid netproto query syntax.`
- [ ] `netproto query: `
- [ ] `err Invalid netproto query syntax`
- [ ] `Invalid Network query syntax.`
- [ ] `err Invalid Network query syntax`
- [ ] `Network query: `
- [ ] `Cannot save netproto information.`
- [ ] `err Cannot save netproto information.`

### wdb/parser_agent.rs `parse_netaddr`
- [ ] `Invalid netaddr query syntax.`
- [ ] `netaddr query: `
- [ ] `err Invalid netaddr query syntax`
- [ ] `Invalid Network query syntax.`
- [ ] `err Invalid Network query syntax`
- [ ] `Network query: `
- [ ] `Cannot save netaddr information.`
- [ ] `err Cannot save netaddr information.`

### wdb/parser_agent.rs `parse_osinfo`
- [ ] `err Missing osinfo action`
- [ ] `err Cannot get sys_osinfo database table information; SQL err: `
- [ ] `err Invalid osinfo action: `

### wdb/parser_agent.rs `parse_agents_set_sys_osinfo`
- [ ] `Invalid OS info query syntax.`
- [ ] `err Invalid OS info query syntax`
- [ ] `Invalid OS info query syntax.`
- [ ] `err Invalid OS info query syntax`
- [ ] `OS info query: `
- [ ] `15 fields`
- [ ] `Cannot save OS information.`
- [ ] `err Cannot save OS information.`

### wdb/parser_agent.rs `parse_hardware`
- [ ] `Invalid HW info query syntax.`
- [ ] `HW info query: `
- [ ] `err Invalid HW info query syntax`
- [ ] `wdb_parse_hardware(): Cannot save HW information.`
- [ ] `err Cannot save HW information.`

### wdb/parser_agent.rs `parse_ports`
- [ ] `Invalid Port query syntax.`
- [ ] `Port query: `
- [ ] `err Invalid Port query syntax`
- [ ] `Cannot save Port information.`
- [ ] `err Cannot save Port information.`
- [ ] `Cannot delete old Port information.`
- [ ] `err Cannot delete old Port information.`

### wdb/parser_agent.rs `inventory_get`
- [ ] `, p)) } else { out(msg!(`

### wdb/parser_agent.rs `parse_packages`
- [ ] `Invalid package info query syntax. Missing action`
- [ ] `DB query error. Missing action`
- [ ] `err Invalid package info query syntax. Missing action`
- [ ] `Invalid package info query syntax.`
- [ ] `Package info query: `
- [ ] `err Invalid package info query syntax`
- [ ] `16 fields`
- [ ] `Cannot save package information.`
- [ ] `err Cannot save package information.`
- [ ] `Cannot update scanned packages.`
- [ ] `Cannot delete old package information.`
- [ ] `err Cannot delete old package information.`
- [ ] `Invalid package info query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid package info query syntax`

### wdb/parser_agent.rs `parse_hotfixes`
- [ ] `Invalid hotfix info query syntax. Missing action`
- [ ] `DB query error. Missing action`
- [ ] `err Invalid hotfix info query syntax. Missing action`
- [ ] `Invalid hotfix info query syntax.`
- [ ] `Hotfix info query: `
- [ ] `err Invalid hotfix info query syntax`
- [ ] `Cannot save hotfix information.`
- [ ] `err Cannot save hotfix information.`
- [ ] `Cannot delete old hotfix information.`
- [ ] `err Cannot delete old hotfix information.`
- [ ] `Invalid hotfix info query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid hotfix info query syntax`

### wdb/parser_agent.rs `parse_processes`
- [ ] `Invalid Process query syntax.`
- [ ] `Process query: `
- [ ] `err Invalid Process query syntax`
- [ ] `9 fields`
- [ ] `Cannot save Process information.`
- [ ] `err Cannot save Process information.`
- [ ] `Cannot delete old Process information.`
- [ ] `err Cannot delete old Process information.`

### wdb/parser_agent.rs `parse_ciscat`
- [ ] `Invalid CISCAT query syntax.`
- [ ] `CISCAT query: `
- [ ] `err Invalid CISCAT query syntax`
- [ ] `Cannot save CISCAT information.`
- [ ] `err Cannot save CISCAT information.`

### wdb/parser_agent.rs `parse_rootcheck`
- [ ] `, id, `
- [ ] `err Invalid rootcheck query syntax`
- [ ] `err Error deleting rootcheck PM tuple`
- [ ] `, wdb.id, `
- [ ] `err Invalid rootcheck query syntax`
- [ ] `, wdb.id, `
- [ ] `err Error updating rootcheck PM tuple`
- [ ] `, wdb.id, `
- [ ] `err Error updating rootcheck PM tuple`

### wdb/parser_agent.rs `parse_dbsync`
- [ ] `DBSYNC query: `
- [ ] `err Invalid dbsync query syntax`

### wdb/parser_agent.rs `process_dbsync_data`
- [ ] `Invalid operation type: `
- [ ] `(5217): Could not parse syscollector delta information as JSON.`
- [ ] `JSON error near: `

### wdb/parser_agent.rs `fmt_f`
- [ ] `.into() } else { `
- [ ] `.into() } else { `
- [ ] `{v:.6}`

### wdb/parser_global.rs `global_sql_err`
- [ ] `Global DB Cannot execute SQL query; err database `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `err Cannot execute Global database query; `

### wdb/parser_global.rs `global_json`
- [ ] `Global DB JSON error near: `
- [ ] `err Invalid JSON syntax`

### wdb/parser_global.rs `parse_global_command`
- [ ] `Global DB Invalid DB query syntax for `
- [ ] `Global DB query error near: `
- [ ] `err Invalid DB query syntax`
- [ ] `Global DB Invalid DB query syntax.`
- [ ] `Global DB query error near: `
- [ ] `err Invalid DB query syntax`
- [ ] `Global DB Cannot execute SQL query; err database `
- [ ] `, WDB_GLOB_NAME, `
- [ ] `Global DB SQL query: `
- [ ] `err Cannot execute Global database query; `
- [ ] `Global DB`
- [ ] `Global DB`
- [ ] `Global DB`
- [ ] `Invalid DB query syntax.`
- [ ] `Global DB query error near: `
- [ ] `err Invalid DB query syntax`

### wdb/parser_global.rs `parse_global_insert_agent`
- [ ] `Global DB Invalid JSON syntax when inserting agent.`
- [ ] `Global DB Invalid JSON data when inserting agent. Not compliant with constraints defined in the database.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_update_agent_name`
- [ ] `Global DB Invalid JSON syntax when updating agent name.`
- [ ] `Global DB Invalid JSON data when updating agent name.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_update_agent_data`
- [ ] `Global DB Invalid JSON syntax when updating agent version.`
- [ ] `Global DB Invalid JSON data when updating agent version.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_get_agent_labels`
- [ ] `Error getting agent labels from global.db.`
- [ ] `err Error getting agent labels from global.db.`

### wdb/parser_global.rs `parse_global_set_agent_labels`
- [ ] `Invalid DB query syntax.`
- [ ] `DB query error near: `
- [ ] `err Invalid DB query syntax`

### wdb/parser_global.rs `parse_global_update_agent_keepalive`
- [ ] `Global DB Invalid JSON syntax when updating agent keepalive.`
- [ ] `Global DB Invalid JSON data when updating agent keepalive.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_update_connection_status`
- [ ] `Global DB Invalid JSON syntax when updating agent connection status.`
- [ ] `Global DB Invalid JSON data when updating agent connection status.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_update_status_code`
- [ ] `Global DB Invalid JSON syntax when updating agent status code.`
- [ ] `Global DB Invalid JSON data when updating agent status code.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_delete_agent`
- [ ] `{agent_id:03}`
- [ ] `Error deleting agent from agent table in global.db.`
- [ ] `err Error deleting agent from agent table in global.db.`

### wdb/parser_global.rs `parse_global_select_agent_name`
- [ ] `Error getting agent name from global.db.`
- [ ] `err Error getting agent name from global.db.`

### wdb/parser_global.rs `parse_global_select_agent_group`
- [ ] `Error getting agent group from global.db.`
- [ ] `err Error getting agent group from global.db.`

### wdb/parser_global.rs `parse_global_find_agent`
- [ ] `Global DB Invalid JSON syntax when finding agent id.`
- [ ] `Global DB Invalid JSON data when finding agent id.`
- [ ] `err Invalid JSON data`

### wdb/parser_global.rs `parse_global_find_group`
- [ ] `Error getting group id from global.db.`
- [ ] `err Error getting group id from global.db.`

### wdb/parser_global.rs `parse_global_insert_agent_group`
- [ ] `Error inserting group in global.db.`
- [ ] `err Error inserting group in global.db.`

### wdb/parser_global.rs `parse_global_select_group_belong`
- [ ] `Error getting agent groups information from global.db.`
- [ ] `err Error getting agent groups information from global.db.`

### wdb/parser_global.rs `parse_global_get_group_agents`
- [ ] `Invalid arguments, group name not found.`
- [ ] `err Invalid arguments, group name not found.`
- [ ] `Invalid arguments, 'last_id' not found.`
- [ ] `err Invalid arguments, 'last_id' not found.`
- [ ] `Invalid arguments, last agent id not found.`
- [ ] `err Invalid arguments, last agent id not found.`
- [ ] `Error getting group agents from global.db.`
- [ ] `err Error getting group agents from global.db.`

### wdb/parser_global.rs `parse_global_delete_group`
- [ ] `Error deleting group in global.db.`
- [ ] `err Error deleting group in global.db.`

### wdb/parser_global.rs `parse_global_select_groups`
- [ ] `Error getting groups from global.db.`
- [ ] `err Error getting groups from global.db.`

### wdb/parser_global.rs `parse_global_set_agent_groups`
- [ ] `Global DB Invalid JSON syntax when parsing set_agent_groups`
- [ ] `Global DB JSON error near: `
- [ ] `err Invalid JSON syntax`
- [ ] `Missing mandatory fields in set_agent_groups command.`
- [ ] `err Invalid JSON data, missing required fields`
- [ ] `Invalid mode '`
- [ ] `' in set_agent_groups command.`
- [ ] `err Invalid mode '`
- [ ] `' in set_agent_groups command`
- [ ] ` An error occurred during the set of the groups`

### wdb/parser_global.rs `parse_global_sync_agent_groups_get`
- [ ] `Global DB Invalid JSON syntax when parsing sync-agent-groups-get`
- [ ] `Global DB JSON error near: `
- [ ] `err Invalid JSON syntax`
- [ ] `Invalid alternative fields data in sync-agent-groups-get command.`
- [ ] `err Invalid JSON data, invalid alternative fields data`
- [ ] `err Invalid response from wdb_global_sync_agent_groups_get`
- [ ] `err Could not obtain a response from wdb_global_sync_agent_groups_get`

### wdb/parser_global.rs `parse_global_sync_agent_info_set`
- [ ] `Global DB Invalid JSON syntax updating unsynced agents.`
- [ ] `Global DB JSON error near: `
- [ ] `err Invalid JSON syntax`
- [ ] `Global DB Cannot execute SQL query; incorrect agent id in labels array.`
- [ ] `err Cannot update labels due to invalid id.`

### wdb/parser_global.rs `parse_get_groups_integrity`
- [ ] `Hash hex-digest does not have the expected length. Expected (`
- [ ] `) got (`
- [ ] `err Hash hex-digest does not have the expected length. Expected (`
- [ ] `) got (`
- [ ] `Error getting groups integrity information from global.db.`
- [ ] `err Error getting groups integrity information from global.db.`

### wdb/parser_global.rs `parse_global_recalculate_agent_group_hashes`
- [ ] `Error recalculating group hash of agents in global.db.`
- [ ] `err Error recalculating group hash of agents in global.db`

### wdb/parser_global.rs `parse_global_get_agent_info`
- [ ] `Error getting agent information from global.db.`
- [ ] `err Error getting agent information from global.db.`

### wdb/parser_global.rs `parse_global_get_agents_by_connection_status`
- [ ] `Invalid arguments 'last_id' not found.`
- [ ] `err Invalid arguments 'last_id' not found`
- [ ] `Invalid arguments 'connection_status' not found.`
- [ ] `err Invalid arguments 'connection_status' not found`
- [ ] `Invalid arguments 'limit' not found.`
- [ ] `err Invalid arguments 'limit' not found`
- [ ] `Error getting agents by connection status from global.db.`
- [ ] `err Error getting agents by connection status from global.db.`

### wdb/parser_global.rs `parse_global_get_all_agents`
- [ ] `Invalid arguments 'last_id' or 'context' not found.`
- [ ] `err Invalid arguments 'last_id' or 'context' not found`
- [ ] `err Error getting agents from global.db.`
- [ ] `Invalid arguments 'last_id' not found.`
- [ ] `err Invalid arguments 'last_id' not found`
- [ ] `Error getting agents from global.db.`
- [ ] `err Error getting agents from global.db.`

### wdb/parser_global.rs `parse_global_get_distinct_agent_groups`
- [ ] `Error getting agent groups from global.db.`
- [ ] `err Error getting agent groups from global.db.`

### wdb/parser_global.rs `parse_global_disconnect_agents`
- [ ] `Invalid arguments last id not found.`
- [ ] `err Invalid arguments last id not found`
- [ ] `Invalid arguments keepalive not found.`
- [ ] `err Invalid arguments keepalive not found`
- [ ] `Invalid arguments sync_status not found.`
- [ ] `err Invalid arguments sync_status not found`
- [ ] `Error getting agents to be disconnected from global.db.`
- [ ] `err Error getting agents to be disconnected from global.db.`

### wdb/parser_global.rs `parse_global_backup`
- [ ] `err Missing backup action`
- [ ] `Creating Global DB snapshot on demand failed: `
- [ ] `err Cannot execute backup get command, unable to open '`
- [ ] `' folder`
- [ ] `Invalid backup JSON syntax when restoring snapshot.`
- [ ] `JSON error near: `
- [ ] `err Invalid JSON syntax`
- [ ] `err Invalid backup action: `

### wdb/parser_global.rs `parse_task_command`
- [ ] `err Invalid command parameters`
- [ ] `Tasks DB Cannot execute SQL query; err database `
- [ ] `, WDB_TASK_NAME, `
- [ ] `Tasks DB SQL query: `
- [ ] `err Cannot execute Tasks database query; `
- [ ] `Invalid DB query syntax.`
- [ ] `Task DB query error near: `
- [ ] `err Invalid DB query syntax`

### wdb/parser_global.rs `parse_task_upgrade`
- [ ] `err Error insert task: 'parsing agent error'`
- [ ] `err Error insert task: 'parsing node error'`
- [ ] `err Error insert task: 'parsing module error'`

### wdb/parser_global.rs `parse_task_upgrade_get_status`
- [ ] `err Error get upgrade task status: 'parsing agent error'`
- [ ] `err Error get upgrade task status: 'parsing node error'`

### wdb/parser_global.rs `parse_task_upgrade_update_status`
- [ ] `err Error upgrade update status task: 'parsing agent error'`
- [ ] `err Error upgrade update status task: 'parsing node error'`
- [ ] `err Error upgrade update status task: 'parsing status error'`

### wdb/parser_global.rs `parse_task_upgrade_result`
- [ ] `err Error upgrade result task: 'parsing agent error'`

### wdb/parser_global.rs `parse_task_upgrade_cancel_tasks`
- [ ] `err Error upgrade cancel task: 'parsing node error'`

### wdb/parser_global.rs `parse_task_set_timeout`
- [ ] `err Error set timeout task: 'parsing now error'`
- [ ] `err Error set timeout task: 'parsing interval error'`

### wdb/parser_global.rs `parse_task_delete_old`
- [ ] `err Error delete old task: 'parsing timestamp error'`

### wdb/router.rs `router_initialize`
- [ ] `:router`

### wdb/sca.rs `pz`
- [ ] `(null)`

### wdb/sca.rs `sca_prep`
- [ ] `cannot begin transaction`

### wdb/sca.rs `sca_done`
- [ ] `SQLite: `

### wdb/sca.rs `sca_done_changes`
- [ ] `SQLite: `

### wdb/sca.rs `sca_unique`
- [ ] `SQLite: `
- [ ] `SQLite: `
- [ ] `SQLite: `

### wdb/sca.rs `sca_find`
- [ ] `cannot cache statement`
- [ ] `SQLite: `

### wdb/sca.rs `sca_save`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_policy_get_id`
- [ ] `cannot cache statement`
- [ ] `SQLite: `

### wdb/sca.rs `sca_policy_delete`
- [ ] `cannot cache statement`
- [ ] `SQLite: `

### wdb/sca.rs `sca_scan_info_delete`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_check_delete_distinct`
- [ ] `at wdb_sca_check_delete_distinct(): cannot cache statement`

### wdb/sca.rs `sca_check_delete`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_check_compliances_delete`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_check_rules_delete`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_scan_find`
- [ ] `cannot cache statement`
- [ ] `SQLite: `

### wdb/sca.rs `sca_single`
- [ ] `cannot cache statement`
- [ ] `SQLite: `

### wdb/sca.rs `sca_compliance_save`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_rules_save`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_policy_info_save`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_scan_info_save`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_scan_info_update`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_scan_info_update_start`
- [ ] `cannot cache statement`

### wdb/sca.rs `sca_checks_get_result`
- [ ] `cannot cache statement`
- [ ] `SQLite: `
- [ ] `not applicable`
- [ ] `{b:02x}`

### wdb/sca.rs `sca_update`
- [ ] `cannot cache statement`

### wdb/sk.rs `pz`
- [ ] `(null)`

### wdb/sk.rs `sk_build_sum`
- [ ] `!{}:{}`

### wdb/sk.rs `trunc16`
- [ ] `generic_read|`
- [ ] `generic_write|`
- [ ] `generic_execute|`
- [ ] `generic_all|`
- [ ] `delete|`
- [ ] `read_control|`
- [ ] `write_dac|`
- [ ] `write_owner|`
- [ ] `synchronize|`
- [ ] `read_data|`
- [ ] `write_data|`
- [ ] `append_data|`
- [ ] `read_ea|`
- [ ] `write_ea|`
- [ ] `execute|`
- [ ] `read_attributes|`
- [ ] `write_attributes|`

### wdb/sk.rs `decode_win_permissions`
- [ ] ` (allowed): `
- [ ] ` (denied): `

### wdb/state.rs `get_agent_time`
- [ ] `queries_breakdown.agent_breakdown.sql_time`
- [ ] `queries_breakdown.agent_breakdown.remove_time`
- [ ] `queries_breakdown.agent_breakdown.open_calls_time`
- [ ] `queries_breakdown.agent_breakdown.vacuum_time`
- [ ] `queries_breakdown.agent_breakdown.get_fragmentation_time`
- [ ] `queries_breakdown.agent_breakdown.sleep_time`
- [ ] `queries_breakdown.agent_breakdown.begin_time`
- [ ] `queries_breakdown.agent_breakdown.commit_time`
- [ ] `queries_breakdown.agent_breakdown.close_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.syscheck_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_file_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time`
- [ ] `queries_breakdown.agent_breakdown.rootcheck.rootcheck_time`
- [ ] `queries_breakdown.agent_breakdown.sca.sca_time`
- [ ] `queries_breakdown.agent_breakdown.ciscat.ciscat_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.process_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.package_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.port_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time`
- [ ] `queries_breakdown.agent_breakdown.sync.dbsync_time`

### wdb/state.rs `get_global_time`
- [ ] `queries_breakdown.global_breakdown.sql_time`
- [ ] `queries_breakdown.global_breakdown.backup_time`
- [ ] `queries_breakdown.global_breakdown.open_calls_time`
- [ ] `queries_breakdown.global_breakdown.vacuum_time`
- [ ] `queries_breakdown.global_breakdown.get_fragmentation_time`
- [ ] `queries_breakdown.global_breakdown.sleep_time`
- [ ] `queries_breakdown.global_breakdown.agent.insert_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_data_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_name_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_keepalive_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_connection_status_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_status_code_time`
- [ ] `queries_breakdown.global_breakdown.agent.reset_agents_connection_time`
- [ ] `queries_breakdown.global_breakdown.agent.delete_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_name_time`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_group_time`
- [ ] `queries_breakdown.global_breakdown.agent.find_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_agent_info_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_all_agents_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_distinct_groups_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time`
- [ ] `queries_breakdown.global_breakdown.agent.disconnect_agents_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_get_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_set_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time`
- [ ] `queries_breakdown.global_breakdown.agent.set_agent_groups_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_groups_integrity_time`
- [ ] `queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time`
- [ ] `queries_breakdown.global_breakdown.group.insert_agent_group_time`
- [ ] `queries_breakdown.global_breakdown.group.delete_group_time`
- [ ] `queries_breakdown.global_breakdown.group.select_groups_time`
- [ ] `queries_breakdown.global_breakdown.group.find_group_time`
- [ ] `queries_breakdown.global_breakdown.belongs.select_group_belong_time`
- [ ] `queries_breakdown.global_breakdown.belongs.get_group_agent_time`
- [ ] `queries_breakdown.global_breakdown.labels.get_labels_time`

### wdb/state.rs `get_task_time`
- [ ] `queries_breakdown.task_breakdown.sql_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_custom_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_get_status_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_update_status_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_result_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time`
- [ ] `queries_breakdown.task_breakdown.tasks.set_timeout_time`
- [ ] `queries_breakdown.task_breakdown.tasks.delete_old_time`

### wdb/state.rs `get_time_total`
- [ ] `queries_breakdown.wazuhdb_breakdown.remove_time`
- [ ] `queries_breakdown.mitre_breakdown.sql_time`

### wdb/state.rs `w_inc_provigildb_remove`
- [ ] `queries_breakdown.wazuhdb_breakdown.remove_queries`

### wdb/state.rs `w_inc_provigildb_remove_time`
- [ ] `queries_breakdown.wazuhdb_breakdown.remove_time`

### wdb/state.rs `w_inc_agent_open_time`
- [ ] `queries_breakdown.agent_breakdown.open_calls_time`

### wdb/state.rs `w_inc_agent_sql`
- [ ] `queries_breakdown.agent_breakdown.sql_queries`

### wdb/state.rs `w_inc_agent_sql_time`
- [ ] `queries_breakdown.agent_breakdown.sql_time`

### wdb/state.rs `w_inc_agent_remove`
- [ ] `queries_breakdown.agent_breakdown.remove_queries`

### wdb/state.rs `w_inc_agent_remove_time`
- [ ] `queries_breakdown.agent_breakdown.remove_time`

### wdb/state.rs `w_inc_agent_begin`
- [ ] `queries_breakdown.agent_breakdown.begin_queries`

### wdb/state.rs `w_inc_agent_begin_time`
- [ ] `queries_breakdown.agent_breakdown.begin_time`

### wdb/state.rs `w_inc_agent_commit`
- [ ] `queries_breakdown.agent_breakdown.commit_queries`

### wdb/state.rs `w_inc_agent_commit_time`
- [ ] `queries_breakdown.agent_breakdown.commit_time`

### wdb/state.rs `w_inc_agent_close`
- [ ] `queries_breakdown.agent_breakdown.close_queries`

### wdb/state.rs `w_inc_agent_close_time`
- [ ] `queries_breakdown.agent_breakdown.close_time`

### wdb/state.rs `w_inc_agent_vacuum`
- [ ] `queries_breakdown.agent_breakdown.vacuum_queries`

### wdb/state.rs `w_inc_agent_vacuum_time`
- [ ] `queries_breakdown.agent_breakdown.vacuum_time`

### wdb/state.rs `w_inc_agent_get_fragmentation`
- [ ] `queries_breakdown.agent_breakdown.get_fragmentation_queries`

### wdb/state.rs `w_inc_agent_get_fragmentation_time`
- [ ] `queries_breakdown.agent_breakdown.get_fragmentation_time`

### wdb/state.rs `w_inc_agent_rootcheck`
- [ ] `queries_breakdown.agent_breakdown.rootcheck.rootcheck_queries`

### wdb/state.rs `w_inc_agent_rootcheck_time`
- [ ] `queries_breakdown.agent_breakdown.rootcheck.rootcheck_time`

### wdb/state.rs `w_inc_agent_sca`
- [ ] `queries_breakdown.agent_breakdown.sca.sca_queries`

### wdb/state.rs `w_inc_agent_sca_time`
- [ ] `queries_breakdown.agent_breakdown.sca.sca_time`

### wdb/state.rs `w_inc_agent_ciscat`
- [ ] `queries_breakdown.agent_breakdown.ciscat.ciscat_queries`

### wdb/state.rs `w_inc_agent_ciscat_time`
- [ ] `queries_breakdown.agent_breakdown.ciscat.ciscat_time`

### wdb/state.rs `w_inc_agent_dbsync`
- [ ] `queries_breakdown.agent_breakdown.sync.dbsync_queries`

### wdb/state.rs `w_inc_agent_dbsync_time`
- [ ] `queries_breakdown.agent_breakdown.sync.dbsync_time`

### wdb/state.rs `w_inc_agent_syscheck`
- [ ] `queries_breakdown.agent_breakdown.syscheck.syscheck_queries`

### wdb/state.rs `w_inc_agent_syscheck_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.syscheck_time`

### wdb/state.rs `w_inc_agent_fim_file`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_file_queries`

### wdb/state.rs `w_inc_agent_fim_file_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_file_time`

### wdb/state.rs `w_inc_agent_fim_registry`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_queries`

### wdb/state.rs `w_inc_agent_fim_registry_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_time`

### wdb/state.rs `w_inc_agent_fim_registry_key`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_key_queries`

### wdb/state.rs `w_inc_agent_fim_registry_key_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time`

### wdb/state.rs `w_inc_agent_fim_registry_value`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_value_queries`

### wdb/state.rs `w_inc_agent_fim_registry_value_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time`

### wdb/state.rs `w_inc_agent_syscollector_processes`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries`

### wdb/state.rs `w_inc_agent_syscollector_packages`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries`

### wdb/state.rs `w_inc_agent_syscollector_hotfixes`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries`

### wdb/state.rs `w_inc_agent_syscollector_ports`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries`

### wdb/state.rs `w_inc_agent_syscollector_network_protocol`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries`

### wdb/state.rs `w_inc_agent_syscollector_network_address`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries`

### wdb/state.rs `w_inc_agent_syscollector_network_iface`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries`

### wdb/state.rs `w_inc_agent_syscollector_hwinfo`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries`

### wdb/state.rs `w_inc_agent_syscollector_osinfo`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries`

### wdb/state.rs `w_inc_agent_syscollector_users`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_users_queries`

### wdb/state.rs `w_inc_agent_syscollector_groups`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_groups_queries`

### wdb/state.rs `w_inc_agent_syscollector_browser_extensions`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_browser_extensions_queries`

### wdb/state.rs `w_inc_agent_syscollector_services`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_services_queries`

### wdb/state.rs `w_inc_agent_syscollector_times`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_groups_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_services_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_users_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_browser_extensions_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_process`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.process_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_process_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.process_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_packages`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.package_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_packages_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.package_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_hotfixes`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_hotfixes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_ports`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.port_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_ports_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.port_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_network_protocol`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_network_protocol_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_network_address`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_network_address_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_network_info`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_network_info_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_hardware`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_hardware_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_osinfo`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_queries`

### wdb/state.rs `w_inc_agent_syscollector_deprecated_osinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time`

### wdb/state.rs `w_inc_agent_sleep`
- [ ] `queries_breakdown.agent_breakdown.sleep_queries`

### wdb/state.rs `w_inc_agent_sleep_time`
- [ ] `queries_breakdown.agent_breakdown.sleep_time`

### wdb/state.rs `w_inc_global_open_time`
- [ ] `queries_breakdown.global_breakdown.open_calls_time`

### wdb/state.rs `w_inc_global_sql`
- [ ] `queries_breakdown.global_breakdown.sql_queries`

### wdb/state.rs `w_inc_global_sql_time`
- [ ] `queries_breakdown.global_breakdown.sql_time`

### wdb/state.rs `w_inc_global_backup`
- [ ] `queries_breakdown.global_breakdown.backup_queries`

### wdb/state.rs `w_inc_global_backup_time`
- [ ] `queries_breakdown.global_breakdown.backup_time`

### wdb/state.rs `w_inc_global_agent_insert_agent`
- [ ] `queries_breakdown.global_breakdown.agent.insert_agent_queries`

### wdb/state.rs `w_inc_global_agent_insert_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.insert_agent_time`

### wdb/state.rs `w_inc_global_agent_update_agent_data`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_data_queries`

### wdb/state.rs `w_inc_global_agent_update_agent_data_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_data_time`

### wdb/state.rs `w_inc_global_agent_update_agent_name`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_name_queries`

### wdb/state.rs `w_inc_global_agent_update_agent_name_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_name_time`

### wdb/state.rs `w_inc_global_agent_update_keepalive`
- [ ] `queries_breakdown.global_breakdown.agent.update_keepalive_queries`

### wdb/state.rs `w_inc_global_agent_update_keepalive_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_keepalive_time`

### wdb/state.rs `w_inc_global_agent_update_connection_status`
- [ ] `queries_breakdown.global_breakdown.agent.update_connection_status_queries`

### wdb/state.rs `w_inc_global_agent_update_connection_status_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_connection_status_time`

### wdb/state.rs `w_inc_global_agent_update_status_code`
- [ ] `queries_breakdown.global_breakdown.agent.update_status_code_queries`

### wdb/state.rs `w_inc_global_agent_update_status_code_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_status_code_time`

### wdb/state.rs `w_inc_global_agent_reset_agents_connection`
- [ ] `queries_breakdown.global_breakdown.agent.reset_agents_connection_queries`

### wdb/state.rs `w_inc_global_agent_reset_agents_connection_time`
- [ ] `queries_breakdown.global_breakdown.agent.reset_agents_connection_time`

### wdb/state.rs `w_inc_global_agent_delete_agent`
- [ ] `queries_breakdown.global_breakdown.agent.delete_agent_queries`

### wdb/state.rs `w_inc_global_agent_delete_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.delete_agent_time`

### wdb/state.rs `w_inc_global_agent_select_agent_name`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_name_queries`

### wdb/state.rs `w_inc_global_agent_select_agent_name_time`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_name_time`

### wdb/state.rs `w_inc_global_agent_select_agent_group`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_group_queries`

### wdb/state.rs `w_inc_global_agent_select_agent_group_time`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_group_time`

### wdb/state.rs `w_inc_global_agent_find_agent`
- [ ] `queries_breakdown.global_breakdown.agent.find_agent_queries`

### wdb/state.rs `w_inc_global_agent_find_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.find_agent_time`

### wdb/state.rs `w_inc_global_agent_get_agent_info`
- [ ] `queries_breakdown.global_breakdown.agent.get_agent_info_queries`

### wdb/state.rs `w_inc_global_agent_get_agent_info_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_agent_info_time`

### wdb/state.rs `w_inc_global_agent_get_all_agents`
- [ ] `queries_breakdown.global_breakdown.agent.get_all_agents_queries`

### wdb/state.rs `w_inc_global_agent_get_all_agents_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_all_agents_time`

### wdb/state.rs `w_inc_global_agent_get_distinct_groups`
- [ ] `queries_breakdown.global_breakdown.agent.get_distinct_groups_queries`

### wdb/state.rs `w_inc_global_agent_get_distinct_groups_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_distinct_groups_time`

### wdb/state.rs `w_inc_global_agent_get_agents_by_connection_status`
- [ ] `queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries`

### wdb/state.rs `w_inc_global_agent_get_agents_by_connection_status_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time`

### wdb/state.rs `w_inc_global_agent_disconnect_agents`
- [ ] `queries_breakdown.global_breakdown.agent.disconnect_agents_queries`

### wdb/state.rs `w_inc_global_agent_disconnect_agents_time`
- [ ] `queries_breakdown.global_breakdown.agent.disconnect_agents_time`

### wdb/state.rs `w_inc_global_agent_sync_agent_info_get`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries`

### wdb/state.rs `w_inc_global_agent_sync_agent_info_get_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_get_time`

### wdb/state.rs `w_inc_global_agent_sync_agent_info_set`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries`

### wdb/state.rs `w_inc_global_agent_sync_agent_info_set_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_set_time`

### wdb/state.rs `w_inc_global_agent_sync_agent_groups_get`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries`

### wdb/state.rs `w_inc_global_agent_sync_agent_groups_get_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time`

### wdb/state.rs `w_inc_global_agent_set_agent_groups`
- [ ] `queries_breakdown.global_breakdown.agent.set_agent_groups_queries`

### wdb/state.rs `w_inc_global_agent_set_agent_groups_time`
- [ ] `queries_breakdown.global_breakdown.agent.set_agent_groups_time`

### wdb/state.rs `w_inc_global_agent_get_groups_integrity`
- [ ] `queries_breakdown.global_breakdown.agent.get_groups_integrity_queries`

### wdb/state.rs `w_inc_global_agent_get_groups_integrity_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_groups_integrity_time`

### wdb/state.rs `w_inc_global_agent_recalculate_agent_group_hashes`
- [ ] `queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_queries`

### wdb/state.rs `w_inc_global_agent_recalculate_agent_group_hashes_time`
- [ ] `queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time`

### wdb/state.rs `w_inc_global_group_insert_agent_group`
- [ ] `queries_breakdown.global_breakdown.group.insert_agent_group_queries`

### wdb/state.rs `w_inc_global_group_insert_agent_group_time`
- [ ] `queries_breakdown.global_breakdown.group.insert_agent_group_time`

### wdb/state.rs `w_inc_global_group_delete_group`
- [ ] `queries_breakdown.global_breakdown.group.delete_group_queries`

### wdb/state.rs `w_inc_global_group_delete_group_time`
- [ ] `queries_breakdown.global_breakdown.group.delete_group_time`

### wdb/state.rs `w_inc_global_group_select_groups`
- [ ] `queries_breakdown.global_breakdown.group.select_groups_queries`

### wdb/state.rs `w_inc_global_group_select_groups_time`
- [ ] `queries_breakdown.global_breakdown.group.select_groups_time`

### wdb/state.rs `w_inc_global_group_find_group`
- [ ] `queries_breakdown.global_breakdown.group.find_group_queries`

### wdb/state.rs `w_inc_global_group_find_group_time`
- [ ] `queries_breakdown.global_breakdown.group.find_group_time`

### wdb/state.rs `w_inc_global_belongs_select_group_belong`
- [ ] `queries_breakdown.global_breakdown.belongs.select_group_belong_queries`

### wdb/state.rs `w_inc_global_belongs_select_group_belong_time`
- [ ] `queries_breakdown.global_breakdown.belongs.select_group_belong_time`

### wdb/state.rs `w_inc_global_belongs_get_group_agent`
- [ ] `queries_breakdown.global_breakdown.belongs.get_group_agent_queries`

### wdb/state.rs `w_inc_global_belongs_get_group_agent_time`
- [ ] `queries_breakdown.global_breakdown.belongs.get_group_agent_time`

### wdb/state.rs `w_inc_global_labels_get_labels`
- [ ] `queries_breakdown.global_breakdown.labels.get_labels_queries`

### wdb/state.rs `w_inc_global_labels_get_labels_time`
- [ ] `queries_breakdown.global_breakdown.labels.get_labels_time`

### wdb/state.rs `w_inc_global_vacuum`
- [ ] `queries_breakdown.global_breakdown.vacuum_queries`

### wdb/state.rs `w_inc_global_vacuum_time`
- [ ] `queries_breakdown.global_breakdown.vacuum_time`

### wdb/state.rs `w_inc_global_get_fragmentation`
- [ ] `queries_breakdown.global_breakdown.get_fragmentation_queries`

### wdb/state.rs `w_inc_global_get_fragmentation_time`
- [ ] `queries_breakdown.global_breakdown.get_fragmentation_time`

### wdb/state.rs `w_inc_global_sleep`
- [ ] `queries_breakdown.global_breakdown.sleep_queries`

### wdb/state.rs `w_inc_global_sleep_time`
- [ ] `queries_breakdown.global_breakdown.sleep_time`

### wdb/state.rs `w_inc_task_sql`
- [ ] `queries_breakdown.task_breakdown.sql_queries`

### wdb/state.rs `w_inc_task_sql_time`
- [ ] `queries_breakdown.task_breakdown.sql_time`

### wdb/state.rs `w_inc_task_set_timeout`
- [ ] `queries_breakdown.task_breakdown.tasks.set_timeout_queries`

### wdb/state.rs `w_inc_task_set_timeout_time`
- [ ] `queries_breakdown.task_breakdown.tasks.set_timeout_time`

### wdb/state.rs `w_inc_task_delete_old`
- [ ] `queries_breakdown.task_breakdown.tasks.delete_old_queries`

### wdb/state.rs `w_inc_task_delete_old_time`
- [ ] `queries_breakdown.task_breakdown.tasks.delete_old_time`

### wdb/state.rs `w_inc_task_upgrade`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_queries`

### wdb/state.rs `w_inc_task_upgrade_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_time`

### wdb/state.rs `w_inc_task_upgrade_custom`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_custom_queries`

### wdb/state.rs `w_inc_task_upgrade_custom_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_custom_time`

### wdb/state.rs `w_inc_task_upgrade_get_status`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_get_status_queries`

### wdb/state.rs `w_inc_task_upgrade_get_status_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_get_status_time`

### wdb/state.rs `w_inc_task_upgrade_update_status`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_update_status_queries`

### wdb/state.rs `w_inc_task_upgrade_update_status_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_update_status_time`

### wdb/state.rs `w_inc_task_upgrade_result`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_result_queries`

### wdb/state.rs `w_inc_task_upgrade_result_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_result_time`

### wdb/state.rs `w_inc_task_upgrade_cancel_tasks`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_queries`

### wdb/state.rs `w_inc_task_upgrade_cancel_tasks_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time`

### wdb/state.rs `w_inc_mitre_sql`
- [ ] `queries_breakdown.mitre_breakdown.sql_queries`

### wdb/state.rs `w_inc_mitre_sql_time`
- [ ] `queries_breakdown.mitre_breakdown.sql_time`

### wdb/state.rs `create_state_json`
- [ ] `, s.n(`
- [ ] `, s.n(`
- [ ] `, s.n(`
- [ ] `queries_breakdown.agent_breakdown.commit_queries`
- [ ] `queries_breakdown.agent_breakdown.remove_queries`
- [ ] `, s.n(`
- [ ] `queries_breakdown.agent_breakdown.vacuum_queries`
- [ ] `queries_breakdown.agent_breakdown.get_fragmentation_queries`
- [ ] `, s.n(`
- [ ] `queries_breakdown.agent_breakdown.ciscat.ciscat_queries`
- [ ] `queries_breakdown.agent_breakdown.rootcheck.rootcheck_queries`
- [ ] `, s.n(`
- [ ] `queries_breakdown.agent_breakdown.sync.dbsync_queries`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_file_queries`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_queries`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_key_queries`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_value_queries`
- [ ] `queries_breakdown.agent_breakdown.syscheck.syscheck_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_packages_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_ports_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_processes_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_users_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_groups_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_browser_extensions_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_services_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_queries`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.package_queries`
- [ ] `, s.n(`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.process_queries`
- [ ] `queries_breakdown.global_breakdown.backup_queries`
- [ ] `, s.n(`
- [ ] `queries_breakdown.global_breakdown.vacuum_queries`
- [ ] `queries_breakdown.global_breakdown.get_fragmentation_queries`
- [ ] `, s.n(`
- [ ] `queries_breakdown.global_breakdown.agent.delete_agent_queries`
- [ ] `queries_breakdown.global_breakdown.agent.disconnect_agents_queries`
- [ ] `queries_breakdown.global_breakdown.agent.find_agent_queries`
- [ ] `queries_breakdown.global_breakdown.agent.get_agent_info_queries`
- [ ] `queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_queries`
- [ ] `queries_breakdown.global_breakdown.agent.get_all_agents_queries`
- [ ] `queries_breakdown.global_breakdown.agent.get_distinct_groups_queries`
- [ ] `queries_breakdown.global_breakdown.agent.get_groups_integrity_queries`
- [ ] `queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_queries`
- [ ] `queries_breakdown.global_breakdown.agent.insert_agent_queries`
- [ ] `queries_breakdown.global_breakdown.agent.reset_agents_connection_queries`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_group_queries`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_name_queries`
- [ ] `queries_breakdown.global_breakdown.agent.set_agent_groups_queries`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_groups_get_queries`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_get_queries`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_set_queries`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_data_queries`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_name_queries`
- [ ] `queries_breakdown.global_breakdown.agent.update_connection_status_queries`
- [ ] `queries_breakdown.global_breakdown.agent.update_status_code_queries`
- [ ] `queries_breakdown.global_breakdown.agent.update_keepalive_queries`
- [ ] `queries_breakdown.global_breakdown.belongs.get_group_agent_queries`
- [ ] `queries_breakdown.global_breakdown.belongs.select_group_belong_queries`
- [ ] `queries_breakdown.global_breakdown.group.delete_group_queries`
- [ ] `queries_breakdown.global_breakdown.group.find_group_queries`
- [ ] `queries_breakdown.global_breakdown.group.insert_agent_group_queries`
- [ ] `queries_breakdown.global_breakdown.group.select_groups_queries`
- [ ] `queries_breakdown.global_breakdown.labels.get_labels_queries`
- [ ] `, s.n(`
- [ ] `, s.n(`
- [ ] `, s.n(`
- [ ] `, s.n(`
- [ ] `queries_breakdown.task_breakdown.tasks.delete_old_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.set_timeout_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_custom_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_get_status_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_result_queries`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_update_status_queries`
- [ ] `queries_breakdown.wazuhdb_breakdown.remove_queries`
- [ ] `, s.ms(`
- [ ] `, s.ms(`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.agent_breakdown.commit_time`
- [ ] `queries_breakdown.agent_breakdown.remove_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.agent_breakdown.vacuum_time`
- [ ] `queries_breakdown.agent_breakdown.get_fragmentation_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.agent_breakdown.ciscat.ciscat_time`
- [ ] `queries_breakdown.agent_breakdown.rootcheck.rootcheck_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.agent_breakdown.sync.dbsync_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_file_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_key_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.fim_registry_value_time`
- [ ] `queries_breakdown.agent_breakdown.syscheck.syscheck_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hotfixes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_hwinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_address_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_iface_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_network_protocol_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_osinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_packages_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_ports_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_processes_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_groups_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_users_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_browser_extensions_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.syscollector_services_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hardware_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.hotfix_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netaddr_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.netproto_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.osinfo_time`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.package_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.agent_breakdown.syscollector.deprecated.process_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.global_breakdown.backup_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.global_breakdown.vacuum_time`
- [ ] `queries_breakdown.global_breakdown.get_fragmentation_time`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.global_breakdown.agent.delete_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.disconnect_agents_time`
- [ ] `queries_breakdown.global_breakdown.agent.find_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_agent_info_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_agents_by_connection_status_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_all_agents_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_distinct_groups_time`
- [ ] `queries_breakdown.global_breakdown.agent.get_groups_integrity_time`
- [ ] `queries_breakdown.global_breakdown.agent.recalculate_agent_group_hashes_time`
- [ ] `queries_breakdown.global_breakdown.agent.insert_agent_time`
- [ ] `queries_breakdown.global_breakdown.agent.reset_agents_connection_time`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_group_time`
- [ ] `queries_breakdown.global_breakdown.agent.select_agent_name_time`
- [ ] `queries_breakdown.global_breakdown.agent.set_agent_groups_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_groups_get_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_get_time`
- [ ] `queries_breakdown.global_breakdown.agent.sync_agent_info_set_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_data_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_agent_name_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_connection_status_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_status_code_time`
- [ ] `queries_breakdown.global_breakdown.agent.update_keepalive_time`
- [ ] `queries_breakdown.global_breakdown.belongs.get_group_agent_time`
- [ ] `queries_breakdown.global_breakdown.belongs.select_group_belong_time`
- [ ] `queries_breakdown.global_breakdown.group.delete_group_time`
- [ ] `queries_breakdown.global_breakdown.group.find_group_time`
- [ ] `queries_breakdown.global_breakdown.group.insert_agent_group_time`
- [ ] `queries_breakdown.global_breakdown.group.select_groups_time`
- [ ] `queries_breakdown.global_breakdown.labels.get_labels_time`
- [ ] `, s.ms(`
- [ ] `, s.ms(`
- [ ] `, s.ms(`
- [ ] `queries_breakdown.task_breakdown.tasks.delete_old_time`
- [ ] `queries_breakdown.task_breakdown.tasks.set_timeout_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_cancel_tasks_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_custom_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_get_status_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_result_time`
- [ ] `queries_breakdown.task_breakdown.tasks.upgrade_update_status_time`
- [ ] `queries_breakdown.wazuhdb_breakdown.remove_time`
- [ ] `queries_breakdown.wazuhdb_breakdown.remove_time`

### wdb/stmts.rs `(top)`
- [ ] `SELECT changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE file = ?;`
- [ ] `SELECT 1 FROM fim_entry WHERE file = ?`
- [ ] `INSERT INTO fim_entry (file, type, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO fim_entry (file, type, date, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, attributes, symbolic_path, checksum, arch, value_name, value_type, full_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `UPDATE fim_entry SET date = strftime('%s', 'now'), changes = ?, size = ?, perm = ?, uid = ?, gid = ?, md5 = ?, sha1 = ?, uname = ?, gname = ?, mtime = ?, inode = ?, sha256 = ?, attributes = ?, symbolic_path = ? WHERE file = ?;`
- [ ] `DELETE FROM fim_entry WHERE full_path = ?;`
- [ ] `UPDATE fim_entry SET date = strftime('%s', 'now') WHERE file = ?;`
- [ ] `SELECT full_path, changes, size, perm, uid, gid, md5, sha1, uname, gname, mtime, inode, sha256, date, attributes, symbolic_path FROM fim_entry WHERE date < ?;`
- [ ] `SELECT file, attributes from fim_entry WHERE attributes IS NOT '0';`
- [ ] `UPDATE fim_entry SET attributes = ? WHERE file = ?;`
- [ ] `INSERT INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,  os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_osinfo (scan_id, scan_time, hostname, architecture, os_name, os_version, os_codename, os_major, os_minor,  os_patch, os_build, os_platform, sysname, release, version, os_release, os_display_version, checksum, reference) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `DELETE FROM sys_osinfo;`
- [ ] `SELECT * FROM sys_osinfo;`
- [ ] `INSERT INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_programs (scan_id, scan_time, format, name, priority, section, size, vendor, install_time, version, architecture, multiarch, source, description, location, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `DELETE FROM sys_programs WHERE scan_id != ?;`
- [ ] `UPDATE SYS_PROGRAMS SET CPE = ?, MSU_NAME = ? WHERE SCAN_ID = ? AND FORMAT IS ? AND NAME IS ? AND VENDOR IS ? AND VERSION IS ? AND ARCHITECTURE IS ?;`
- [ ] `SELECT CPE, MSU_NAME, FORMAT, NAME, VENDOR, VERSION, ARCHITECTURE FROM SYS_PROGRAMS WHERE SCAN_ID != ?;`
- [ ] `SELECT 1 FROM sys_programs WHERE item_id = ?;`
- [ ] `INSERT INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_hwinfo (scan_id, scan_time, board_serial, cpu_name, cpu_cores, cpu_mhz, ram_total, ram_free, ram_usage, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES (?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_hotfixes (scan_id, scan_time, hotfix, checksum) VALUES (?, ?, ?, ?);`
- [ ] `DELETE FROM sys_hwinfo;`
- [ ] `DELETE FROM sys_hotfixes WHERE scan_id != ?;`
- [ ] `INSERT INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `DELETE FROM sys_ports WHERE scan_id != ?;`
- [ ] `INSERT INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
- [ ] `INSERT OR REPLACE INTO sys_processes (scan_id, scan_time, pid, name, state, ppid, utime, stime, cmd, argvs, euser, ruser, suser, egroup, rgroup, sgroup, fgroup, priority, nice, size, vm_size, resident, share, start_time, pgrp, session, nlwp, tgid, tty, processor, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
- [ ] `DELETE FROM sys_processes WHERE scan_id != ?;`
- [ ] `INSERT INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_netiface (scan_id, scan_time, name, adapter, type, state, mtu, mac, tx_packets, rx_packets, tx_bytes, rx_bytes, tx_errors, rx_errors, tx_dropped, rx_dropped, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_netproto (scan_id, iface, type, gateway, dhcp, metric, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_netaddr (scan_id, iface, proto, address, netmask, broadcast, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `DELETE FROM sys_netiface WHERE scan_id != ?;`
- [ ] `DELETE FROM sys_netproto WHERE scan_id != ?;`
- [ ] `DELETE FROM sys_netaddr WHERE scan_id != ?;`
- [ ] `INSERT INTO sys_users (scan_id, scan_time, user_name, user_full_name, user_home, user_id, user_uid_signed, user_uuid, user_groups, user_group_id, user_group_id_signed, user_created, user_roles, user_shell, user_type, user_is_hidden, user_is_remote, user_last_login, user_auth_failed_count, user_auth_failed_timestamp, user_password_last_change, user_password_expiration_date, user_password_hash_algorithm, user_password_inactive_days, user_password_max_days_between_changes, user_password_min_days_between_changes, user_password_status, user_password_warning_days_before_expiration, process_pid, host_ip, login_status, login_type, login_tty, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_users (scan_id, scan_time, user_name, user_full_name, user_home, user_id, user_uid_signed, user_uuid, user_groups, user_group_id, user_group_id_signed, user_created, user_roles, user_shell, user_type, user_is_hidden, user_is_remote, user_last_login, user_auth_failed_count, user_auth_failed_timestamp, user_password_last_change, user_password_expiration_date, user_password_hash_algorithm, user_password_inactive_days, user_password_max_days_between_changes, user_password_min_days_between_changes, user_password_status, user_password_warning_days_before_expiration, process_pid, host_ip, login_status, login_type, login_tty, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT INTO sys_groups (scan_id, scan_time, group_id, group_name, group_description, group_id_signed, group_uuid, group_is_hidden, group_users, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_groups (scan_id, scan_time, group_id, group_name, group_description, group_id_signed, group_uuid, group_is_hidden, group_users, checksum) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT INTO sys_browser_extensions (scan_id, scan_time, browser_name, user_id, package_name, package_id, package_version, package_description, package_vendor, package_build_version, package_path, browser_profile_name, browser_profile_path, package_reference, package_permissions, package_type, package_enabled, package_visible, package_autoupdate, package_persistent, package_from_webstore, browser_profile_referenced, package_installed, file_hash_sha256, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_browser_extensions (scan_id, scan_time, browser_name, user_id, package_name, package_id, package_version, package_description, package_vendor, package_build_version, package_path, browser_profile_name, browser_profile_path, package_reference, package_permissions, package_type, package_enabled, package_visible, package_autoupdate, package_persistent, package_from_webstore, browser_profile_referenced, package_installed, file_hash_sha256, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT INTO sys_services (scan_id, scan_time, service_id, service_name, service_description, service_type, service_state, service_sub_state, service_enabled, service_start_type, service_restart, service_frequency, service_starts_on_mount, service_starts_on_path_modified, service_starts_on_not_empty_directory, service_inetd_compatibility, process_pid, process_executable, process_args, process_user_name, process_group_name, process_working_directory, process_root_directory, file_path, service_address, log_file_path, error_log_file_path, service_exit_code, service_win32_exit_code, service_following, service_object_path, service_target_ephemeral_id, service_target_type, service_target_address, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `INSERT OR REPLACE INTO sys_services (scan_id, scan_time, service_id, service_name, service_description, service_type, service_state, service_sub_state, service_enabled, service_start_type, service_restart, service_frequency, service_starts_on_mount, service_starts_on_path_modified, service_starts_on_not_empty_directory, service_inetd_compatibility, process_pid, process_executable, process_args, process_user_name, process_group_name, process_working_directory, process_root_directory, file_path, service_address, log_file_path, error_log_file_path, service_exit_code, service_win32_exit_code, service_following, service_object_path, service_target_ephemeral_id, service_target_type, service_target_address, checksum, item_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `DELETE FROM sys_services WHERE scan_id != ?;`
- [ ] `INSERT INTO ciscat_results (scan_id, scan_time, benchmark, profile, pass, fail, error, notchecked, unknown, score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);`
- [ ] `DELETE FROM ciscat_results WHERE scan_id != ?;`
- [ ] `UPDATE scan_info SET first_start = ?, start_scan = ? WHERE module = ?;`
- [ ] `UPDATE scan_info SET first_end = ?, end_scan = ? WHERE module = ?;`
- [ ] `UPDATE scan_info SET start_scan = ? WHERE module = ?;`
- [ ] `UPDATE scan_info SET end_scan = ? WHERE module = ?;`
- [ ] `UPDATE scan_info SET fim_first_check = ? WHERE module = ?;`
- [ ] `UPDATE scan_info SET fim_second_check = ? WHERE module = ?;`
- [ ] `UPDATE scan_info SET fim_third_check = ? WHERE module = ?;`
- [ ] `SELECT first_start FROM scan_info WHERE module = ?;`
- [ ] `SELECT first_end FROM scan_info WHERE module = ?;`
- [ ] `SELECT start_scan FROM scan_info WHERE module = ?;`
- [ ] `SELECT end_scan FROM scan_info WHERE module = ?;`
- [ ] `SELECT fim_first_check FROM scan_info WHERE module = ?;`
- [ ] `SELECT fim_second_check FROM scan_info WHERE module = ?;`
- [ ] `SELECT fim_third_check FROM scan_info WHERE module = ?;`
- [ ] `SELECT id,result FROM sca_check WHERE id = ?;`
- [ ] `UPDATE sca_check SET scan_id = ?, result = ?, reason = ? WHERE id = ?;`
- [ ] `INSERT INTO sca_check (id,scan_id,title,description,rationale,remediation,file,directory,process,registry,`references`,result,policy_id,command,reason,condition) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?);`
- [ ] `INSERT INTO sca_scan_info (start_scan,end_scan,id,policy_id,pass,fail,invalid,total_checks,score,hash) VALUES (?,?,?,?,?,?,?,?,?,?);`
- [ ] `UPDATE sca_scan_info SET start_scan = ?, end_scan = ?, id = ?, pass = ?, fail = ?, invalid = ?, total_checks = ?, score = ?, hash = ? WHERE policy_id = ?;`
- [ ] `INSERT INTO sca_check_compliance (id_check,`key`,`value`) VALUES(?,?,?);`
- [ ] `INSERT INTO sca_check_rules (id_check,`type`, rule) VALUES(?,?,?);`
- [ ] `SELECT policy_id,hash,id FROM sca_scan_info WHERE policy_id = ?;`
- [ ] `UPDATE sca_scan_info SET start_scan = ?, end_scan = ?, id = ?, pass = ?, fail = ?, invalid = ?, total_checks = ?, score = ?, hash = ? WHERE policy_id = ?;`
- [ ] `SELECT id FROM sca_policy WHERE id = ?;`
- [ ] `SELECT hash_file FROM sca_policy WHERE id = ?;`
- [ ] `INSERT INTO sca_policy (name,file,id,description,`references`,hash_file) VALUES(?,?,?,?,?,?);`
- [ ] `SELECT result FROM sca_check WHERE policy_id = ? ORDER BY id;`
- [ ] `SELECT id FROM sca_policy;`
- [ ] `DELETE FROM sca_policy WHERE id = ?;`
- [ ] `DELETE FROM sca_check WHERE policy_id = ?;`
- [ ] `DELETE FROM sca_scan_info WHERE policy_id = ?;`
- [ ] `DELETE FROM sca_check_compliance WHERE id_check NOT IN ( SELECT id FROM sca_check);`
- [ ] `DELETE FROM sca_check_rules WHERE id_check NOT IN ( SELECT id FROM sca_check);`
- [ ] `DELETE FROM sca_check WHERE scan_id != ? AND policy_id = ?;`
- [ ] `SELECT checksum FROM fim_entry ORDER BY file;`
- [ ] `SELECT checksum FROM fim_entry WHERE file BETWEEN ? and ? ORDER BY file;`
- [ ] `DELETE FROM fim_entry WHERE file < ? OR file > ? RETURNING file;`
- [ ] `DELETE FROM fim_entry WHERE file > ? AND file < ? RETURNING file;`
- [ ] `DELETE FROM fim_entry WHERE file = ? RETURNING file;`
- [ ] `DELETE FROM fim_entry;`
- [ ] `UPDATE sync_info SET last_attempt = ? WHERE component = ?;`
- [ ] `UPDATE sync_info SET last_attempt = ?, last_agent_checksum = ?, last_manager_checksum = ?, n_attempts = n_attempts + 1 WHERE component = ?;`
- [ ] `UPDATE sync_info SET last_attempt = ?, last_completion = ?, last_agent_checksum = ?, last_manager_checksum = ?, n_attempts = n_attempts + 1, n_completions = n_completions + 1 WHERE component = ?;`
- [ ] `UPDATE sync_info SET last_completion = ? WHERE component = ?;`
- [ ] `SELECT * FROM sync_info WHERE component = ?;`
- [ ] `SELECT checksum FROM fim_entry WHERE type='file' ORDER BY file;`
- [ ] `SELECT checksum FROM fim_entry WHERE type='file' AND file BETWEEN ? and ? ORDER BY file;`
- [ ] `DELETE FROM fim_entry WHERE type='file';`
- [ ] `DELETE FROM fim_entry WHERE type='file' AND (file < ? OR file > ?) RETURNING file;`
- [ ] `DELETE FROM fim_entry WHERE type='file' AND (file > ? AND file < ?) RETURNING file;`
- [ ] `DELETE FROM fim_entry WHERE type='file' AND file = ? RETURNING file;`
- [ ] `SELECT checksum FROM fim_entry WHERE (type='registry_key' OR type='registry_value') ORDER BY full_path`
- [ ] `SELECT checksum FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND full_path BETWEEN ? AND ? ORDER BY full_path`
- [ ] `DELETE FROM fim_entry WHERE type='registry_key' OR type='registry_value';`
- [ ] `DELETE FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND (full_path < ? OR full_path > ?) RETURNING full_path;`
- [ ] `DELETE FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND (full_path > ? AND full_path < ?) RETURNING full_path;`
- [ ] `SELECT checksum FROM fim_entry WHERE type='registry_key' ORDER BY full_path`
- [ ] `SELECT checksum FROM fim_entry WHERE type='registry_key' AND full_path BETWEEN ? AND ? ORDER BY full_path`
- [ ] `DELETE FROM fim_entry WHERE type='registry_key';`
- [ ] `DELETE FROM fim_entry WHERE type='registry_key' AND (full_path < ? OR full_path > ?) RETURNING full_path;`
- [ ] `DELETE FROM fim_entry WHERE type='registry_key' AND (full_path > ? AND full_path < ?) RETURNING full_path;`
- [ ] `SELECT checksum FROM fim_entry WHERE type='registry_value' ORDER BY full_path`
- [ ] `SELECT checksum FROM fim_entry WHERE type='registry_value' AND full_path BETWEEN ? AND ? ORDER BY full_path`
- [ ] `DELETE FROM fim_entry WHERE type='registry_value';`
- [ ] `DELETE FROM fim_entry WHERE type='registry_value' AND (full_path < ? OR full_path > ?) RETURNING full_path;`
- [ ] `DELETE FROM fim_entry WHERE type='registry_value' AND (full_path > ? AND full_path < ?) RETURNING full_path;`
- [ ] `DELETE FROM fim_entry WHERE (type='registry_key' OR type='registry_value') AND full_path = ? RETURNING full_path;`
- [ ] `INSERT INTO pm_event (date_first, date_last, log, pci_dss, cis) VALUES (?, ?, ?, ?, ?);`
- [ ] `UPDATE pm_event SET date_last = ? WHERE log = ?;`
- [ ] `DELETE FROM pm_event;`
- [ ] `INSERT INTO agent (id, name, ip, register_ip, internal_key, date_add, `group`) VALUES (?,?,?,?,?,?,?);`
- [ ] `UPDATE agent SET name = ? WHERE id = ?;`
- [ ] `UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ?, last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END), connection_status = ?, sync_status = ?, group_config_status = ? WHERE id = ?;`
- [ ] `UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ?, last_keepalive = (CASE WHEN id = 0 THEN 253402300799 ELSE STRFTIME('%s', 'NOW') END), ip = ?, connection_status = ?, sync_status = ?, group_config_status = ? WHERE id = ?;`
- [ ] `SELECT * FROM labels WHERE id = ?;`
- [ ] `DELETE FROM labels WHERE id = ?;`
- [ ] `INSERT INTO labels (id, key, value) VALUES (?,?,?);`
- [ ] `UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'), connection_status = ?, sync_status = ?, disconnection_time = 0, status_code = 0 WHERE id = ?;`
- [ ] `UPDATE agent SET connection_status = ?, sync_status = ?, disconnection_time = ?, status_code = ? WHERE id = ?;`
- [ ] `UPDATE agent SET status_code = ?, version = ?, sync_status = ? WHERE id = ?;`
- [ ] `DELETE FROM agent WHERE id = ?;`
- [ ] `SELECT name FROM agent WHERE id = ?;`
- [ ] `SELECT id FROM agent WHERE name = ? AND (register_ip = ? OR register_ip LIKE ? || '/_%');`
- [ ] `SELECT id FROM `group` WHERE name = ?;`
- [ ] `UPDATE agent SET group_hash = ? WHERE id = ?;`
- [ ] `INSERT INTO `group` (name) VALUES(?);`
- [ ] `SELECT name FROM belongs JOIN `group` ON id = id_group WHERE id_agent = ? order by priority;`
- [ ] `INSERT OR REPLACE INTO belongs (id_group, id_agent, priority) VALUES(?,?,?);`
- [ ] `DELETE FROM belongs WHERE id_agent = ?;`
- [ ] `DELETE FROM belongs WHERE id_group = ? and id_agent = ?;`
- [ ] `DELETE FROM `group` WHERE name = ?;`
- [ ] `SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?);`
- [ ] `SELECT id_agent FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ?) AND id_agent > ?;`
- [ ] `SELECT name FROM `group`;`
- [ ] `SELECT id, name, ip, os_name, os_version, os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, merged_sum, manager_host, node_name, last_keepalive, connection_status, disconnection_time, group_config_status, status_code FROM agent WHERE id > ? AND sync_status = 'syncreq' LIMIT 1;`
- [ ] `SELECT id, last_keepalive, connection_status, disconnection_time, status_code FROM agent WHERE id > ? AND sync_status = 'syncreq_status' LIMIT 1;`
- [ ] `SELECT id, last_keepalive FROM agent WHERE id > ? AND sync_status = 'syncreq_keepalive' LIMIT 1;`
- [ ] `SELECT sync_status FROM agent WHERE id = ?;`
- [ ] `UPDATE agent SET sync_status = ? WHERE id = ?;`
- [ ] `SELECT id, name FROM agent WHERE id > ? AND group_sync_status = 'syncreq' AND date_add < ? LIMIT 1;`
- [ ] `SELECT id, name FROM agent WHERE id > ? AND date_add < ? LIMIT 1;`
- [ ] `SELECT 1 FROM agent WHERE group_sync_status = 'syncreq';`
- [ ] `SELECT count(id_group) groups_number from belongs WHERE id_agent = ?;`
- [ ] `UPDATE agent SET group_sync_status = ? WHERE id = ?;`
- [ ] `SELECT MAX(priority) FROM belongs WHERE id_agent=?;`
- [ ] `SELECT `group` from agent where id = ?;`
- [ ] `UPDATE agent SET 'group' = ?, group_hash = ?, group_sync_status = ? WHERE id = ?;`
- [ ] `SELECT group_hash FROM agent WHERE id > 0 AND group_hash IS NOT NULL ORDER BY id;`
- [ ] `UPDATE agent SET 'group' = ?, group_hash = ? WHERE id = ?;`
- [ ] `UPDATE agent SET config_sum = :config_sum, ip = :ip, manager_host = :manager_host, merged_sum = :merged_sum, name = :name, node_name = :node_name, os_arch = :os_arch, os_build = :os_build, os_codename = :os_codename, os_major = :os_major, os_minor = :os_minor, os_name = :os_name, os_platform = :os_platform, os_uname = :os_uname, os_version = :os_version, version = :version, last_keepalive = :last_keepalive, connection_status = :connection_status, disconnection_time = :disconnection_time, group_config_status = :group_config_status, status_code= :status_code, sync_status = :sync_status WHERE id = :id;`
- [ ] `SELECT DISTINCT `group`, group_hash from agent WHERE id > 0 AND group_hash > ? ORDER BY group_hash;`
- [ ] `SELECT id FROM agent WHERE id > ?;`
- [ ] `SELECT id, `group` FROM agent WHERE id > ?;`
- [ ] `SELECT id,version,name,ip FROM agent;`
- [ ] `SELECT id FROM agent WHERE id > ? AND connection_status = ?;`
- [ ] `SELECT id FROM agent WHERE id > ? AND connection_status = ? AND node_name = ? ORDER BY id LIMIT ?;`
- [ ] `SELECT * FROM agent WHERE id = ?;`
- [ ] `SELECT id FROM agent WHERE id > ? AND (connection_status = 'active' OR connection_status = 'pending') AND last_keepalive < ?;`
- [ ] `UPDATE agent SET connection_status = 'disconnected', status_code = ?, sync_status = ?, disconnection_time = STRFTIME('%s', 'NOW') where connection_status != 'disconnected' AND connection_status != 'never_connected' AND id != 0;`
- [ ] `SELECT EXISTS(SELECT 1 FROM agent WHERE id=?);`
- [ ] `INSERT INTO TASKS VALUES(NULL,?,?,?,?,?,?,?,?);`
- [ ] `SELECT *, MAX(CREATE_TIME) FROM TASKS WHERE AGENT_ID = ?;`
- [ ] `SELECT *, MAX(CREATE_TIME) FROM TASKS WHERE AGENT_ID = ? AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');`
- [ ] `UPDATE TASKS SET STATUS = ?, LAST_UPDATE_TIME = ?, ERROR_MESSAGE = ? WHERE TASK_ID = ?;`
- [ ] `SELECT * FROM TASKS WHERE STATUS = ?;`
- [ ] `DELETE FROM TASKS WHERE CREATE_TIME <= ?;`
- [ ] `DELETE FROM TASKS WHERE TASK_ID = ?;`
- [ ] `UPDATE TASKS SET STATUS = 'Cancelled', LAST_UPDATE_TIME = ? WHERE NODE = ? AND STATUS = 'Pending' AND (COMMAND = 'upgrade' OR COMMAND = 'upgrade_custom');`
- [ ] `PRAGMA journal_mode=WAL;`
- [ ] `PRAGMA foreign_keys=ON;`
- [ ] `PRAGMA synchronous=1;`
- [ ] `SELECT checksum FROM sys_processes WHERE checksum != 'legacy' AND checksum != '' ORDER BY pid;`
- [ ] `SELECT checksum FROM sys_processes WHERE pid BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY pid;`
- [ ] `DELETE FROM sys_processes WHERE pid < ? OR pid > ? OR checksum = 'legacy' OR checksum = '' RETURNING pid;`
- [ ] `DELETE FROM sys_processes WHERE pid > ? AND pid < ? RETURNING pid;`
- [ ] `DELETE FROM sys_processes;`
- [ ] `DELETE FROM sys_processes WHERE pid = ? RETURNING pid;`
- [ ] `SELECT checksum FROM sys_programs WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_programs WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_programs WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING name, version, architecture, format, location, item_id;`
- [ ] `DELETE FROM sys_programs WHERE item_id > ? AND item_id < ? RETURNING name, version, architecture, format, location, item_id;`
- [ ] `DELETE FROM sys_programs;`
- [ ] `DELETE FROM sys_programs WHERE item_id = ? RETURNING name, version, architecture, format, location, item_id;`
- [ ] `SELECT checksum FROM sys_hotfixes WHERE checksum != 'legacy' AND checksum != '' ORDER BY hotfix;`
- [ ] `SELECT checksum FROM sys_hotfixes WHERE hotfix BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY hotfix;`
- [ ] `DELETE FROM sys_hotfixes WHERE hotfix < ? OR hotfix > ? OR checksum = 'legacy' OR checksum = '' RETURNING hotfix;`
- [ ] `DELETE FROM sys_hotfixes WHERE hotfix > ? AND hotfix < ? RETURNING hotfix;`
- [ ] `DELETE FROM sys_hotfixes;`
- [ ] `DELETE FROM sys_hotfixes WHERE hotfix = ? RETURNING hotfix;`
- [ ] `SELECT checksum FROM sys_ports WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_ports WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_ports WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING protocol, local_ip, local_port, inode, item_id;`
- [ ] `DELETE FROM sys_ports WHERE item_id > ? AND item_id < ? RETURNING protocol, local_ip, local_port, inode, item_id;`
- [ ] `DELETE FROM sys_ports WHERE item_id = ? RETURNING protocol, local_ip, local_port, inode, item_id;`
- [ ] `DELETE FROM sys_ports;`
- [ ] `SELECT checksum FROM sys_netproto WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_netproto WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_netproto WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING item_id;`
- [ ] `DELETE FROM sys_netproto WHERE item_id > ? AND item_id < ? RETURNING item_id;`
- [ ] `DELETE FROM sys_netproto WHERE item_id = ? RETURNING item_id;`
- [ ] `DELETE FROM sys_netproto;`
- [ ] `SELECT checksum FROM sys_netaddr WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_netaddr WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_netaddr WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING item_id;`
- [ ] `DELETE FROM sys_netaddr WHERE item_id > ? AND item_id < ? RETURNING item_id;`
- [ ] `DELETE FROM sys_netaddr WHERE item_id = ? RETURNING item_id;`
- [ ] `DELETE FROM sys_netaddr;`
- [ ] `SELECT checksum FROM sys_netiface WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_netiface WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_netiface WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING item_id;`
- [ ] `DELETE FROM sys_netiface WHERE item_id > ? AND item_id < ? RETURNING item_id;`
- [ ] `DELETE FROM sys_netiface WHERE item_id = ? RETURNING item_id;`
- [ ] `DELETE FROM sys_netiface;`
- [ ] `SELECT checksum FROM sys_hwinfo WHERE checksum != 'legacy' AND checksum != '' ORDER BY board_serial;`
- [ ] `SELECT checksum FROM sys_hwinfo WHERE board_serial BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY board_serial;`
- [ ] `DELETE FROM sys_hwinfo WHERE board_serial < ? OR board_serial > ? OR checksum = 'legacy' OR checksum = '' RETURNING board_serial;`
- [ ] `DELETE FROM sys_hwinfo WHERE board_serial > ? AND board_serial < ? RETURNING board_serial;`
- [ ] `DELETE FROM sys_hwinfo WHERE board_serial = ? RETURNING board_serial;`
- [ ] `DELETE FROM sys_hwinfo;`
- [ ] `SELECT checksum FROM sys_osinfo WHERE checksum != 'legacy' AND checksum != '' ORDER BY os_name;`
- [ ] `SELECT checksum FROM sys_osinfo WHERE os_name BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY os_name;`
- [ ] `DELETE FROM sys_osinfo WHERE os_name < ? OR os_name > ? OR checksum = 'legacy' OR checksum = '' RETURNING os_name;`
- [ ] `DELETE FROM sys_osinfo WHERE os_name > ? AND os_name < ? RETURNING os_name;`
- [ ] `DELETE FROM sys_osinfo WHERE os_name = ? RETURNING os_name;`
- [ ] `DELETE FROM sys_osinfo;`
- [ ] `SELECT checksum FROM sys_users WHERE checksum != 'legacy' AND checksum != '' ORDER BY user_name;`
- [ ] `SELECT checksum FROM sys_users WHERE user_name BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY user_name;`
- [ ] `DELETE FROM sys_users WHERE user_name < ? OR user_name > ? OR checksum = 'legacy' OR checksum = '' RETURNING user_name;`
- [ ] `DELETE FROM sys_users WHERE user_name > ? AND user_name < ? RETURNING user_name;`
- [ ] `DELETE FROM sys_users WHERE user_name = ? RETURNING user_name;`
- [ ] `DELETE FROM sys_users;`
- [ ] `SELECT checksum FROM sys_groups WHERE checksum != 'legacy' AND checksum != '' ORDER BY group_name;`
- [ ] `SELECT checksum FROM sys_groups WHERE group_name BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY group_name;`
- [ ] `DELETE FROM sys_groups WHERE group_name < ? OR group_name > ? OR checksum = 'legacy' OR checksum = '' RETURNING group_name;`
- [ ] `DELETE FROM sys_groups WHERE group_name > ? AND group_name < ? RETURNING group_name;`
- [ ] `DELETE FROM sys_groups WHERE group_name = ? RETURNING group_name;`
- [ ] `DELETE FROM sys_groups;`
- [ ] `SELECT checksum FROM sys_browser_extensions WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_browser_extensions WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_browser_extensions WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING item_id;`
- [ ] `DELETE FROM sys_browser_extensions WHERE item_id > ? AND item_id < ? RETURNING item_id;`
- [ ] `DELETE FROM sys_browser_extensions WHERE item_id = ? RETURNING item_id;`
- [ ] `DELETE FROM sys_browser_extensions;`
- [ ] `SELECT checksum FROM sys_services WHERE checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `SELECT checksum FROM sys_services WHERE item_id BETWEEN ? and ? AND checksum != 'legacy' AND checksum != '' ORDER BY item_id;`
- [ ] `DELETE FROM sys_services WHERE item_id < ? OR item_id > ? OR checksum = 'legacy' OR checksum = '' RETURNING item_id;`
- [ ] `DELETE FROM sys_services WHERE item_id > ? AND item_id < ? RETURNING item_id;`
- [ ] `DELETE FROM sys_services WHERE item_id = ? RETURNING item_id;`
- [ ] `DELETE FROM sys_services;`
- [ ] `SELECT HOTFIX FROM SYS_HOTFIXES;`
- [ ] `SELECT DISTINCT NAME, VERSION, ARCHITECTURE, VENDOR, FORMAT, SOURCE, CPE, MSU_NAME, ITEM_ID, DESCRIPTION, LOCATION, SIZE, INSTALL_TIME FROM SYS_PROGRAMS;`

### wdb/syscollector.rs `begin_or`
- [ ] `, func, `

### wdb/syscollector.rs `cache_or`
- [ ] `, func, `

### wdb/syscollector.rs `step_unique`
- [ ] `SQLite: `
- [ ] `SQLite: `
- [ ] `SQLite: `

### wdb/syscollector.rs `step_done`
- [ ] `SQLite: `

### wdb/syscollector.rs `netproto_insert`
- [ ] ` } else { b`

### wdb/syscollector.rs `netaddr_insert`
- [ ] ` } else { b`

### wdb/syscollector.rs `scan_delete`
- [ ] `Deleting old information from '`
- [ ] `' table: `

### wdb/syscollector.rs `osinfo_save`
- [ ] `at wdb_osinfo_save(): cannot cache statement (`
- [ ] `Deleting old information from 'sys_osinfo' table: `

### wdb/syscollector.rs `package_update`
- [ ] `at wdb_package_update(): cannot begin transaction`
- [ ] `at wdb_package_update(): cannot cache get statement`
- [ ] `at wdb_package_update(): cannot cache update statement`
- [ ] `Unable to update the 'sys_programs' table: `
- [ ] `Unable to update the 'sys_programs' table: `

### wdb/syscollector.rs `hardware_save`
- [ ] `Deleting old information from 'sys_hwinfo' table: `

### wdb/syscollector.rs `syscollector_save2`
- [ ] `at wdb_syscollector_save2(): no payload`
- [ ] `at wdb_syscollector_save2(): no attributes`
- [ ] `user_password_warning_days_before_expiration`
- [ ] `at wdb_syscollector_save2(): Invalid component.`

### wdb/tables.rs `(top)`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `), target_name: `
- [ ] `, default_value: Default::Text(`
- [ ] `, default_value: Default::Text(`
- [ ] `user_password_warning_days_before_expiration`
- [ ] `, value: `
- [ ] `, value: `

### wdb/task.rs `(top)`
- [ ] `In progress`

### wdb/task.rs `sql_error`
- [ ] `(5211): SQL error: '`

### wdb/task.rs `task_prep`
- [ ] `(5212): Cannot begin transaction.`
- [ ] `(5213): Cannot cache statement.`

### wdb/task.rs `task_cache`
- [ ] `(5213): Cannot cache statement.`

### wdb/task.rs `wdbcom_dispatch`
- [ ] `Invalid JSON input`
- [ ] `Empty command`
- [ ] `Unrecognized command`
- [ ] `Empty parameters`
- [ ] `Empty section`
- [ ] `Unrecognized or not configured section`

### wdb/threads.rs `run_backup`
- [ ] `Database backup thread started.`
- [ ] `Creating Global DB snapshot by interval failed: `

### wdb/threads.rs `run_up`
- [ ] `Opening directory: '`
- [ ] `{db_folder}/{name}`

### wdb/upgrade.rs `decode_win_attributes`
- [ ] `ARCHIVE, `
- [ ] `COMPRESSED, `
- [ ] `DEVICE, `
- [ ] `DIRECTORY, `
- [ ] `ENCRYPTED, `
- [ ] `HIDDEN, `
- [ ] `INTEGRITY_STREAM, `
- [ ] `NORMAL, `
- [ ] `NOT_CONTENT_INDEXED, `
- [ ] `NO_SCRUB_DATA, `
- [ ] `OFFLINE, `
- [ ] `READONLY, `
- [ ] `RECALL_ON_DATA_ACCESS, `
- [ ] `RECALL_ON_OPEN, `
- [ ] `REPARSE_POINT, `
- [ ] `SPARSE_FILE, `
- [ ] `SYSTEM, `
- [ ] `TEMPORARY, `
- [ ] `VIRTUAL, `

### wdb/upgrade.rs `upgrade`
- [ ] `, wdb.id, `
- [ ] `Updating database '`
- [ ] `' to version `

### wdb/upgrade.rs `upgrade_global`
- [ ] `, wdb.id, `
- [ ] `Creating pre-upgrade Global DB snapshot failed: `
- [ ] `, wdb.id, `
- [ ] `Creating pre-upgrade Global DB snapshot failed: `
- [ ] `Updating database '`
- [ ] `' to version `
- [ ] `Failed to update global.db to version `
- [ ] `. The global.db was restored to the original state.`
- [ ] `Failed to update global.db to version `

### wdb/upgrade.rs `backup`
- [ ] `{WDB2_DIR}/{sagent_id}.db`
- [ ] `Creating DB backup and create clear DB for agent: '`
- [ ] `Couldn't create SQLite database for agent '`
- [ ] `out of memory`
- [ ] `Can't open SQLite backup database '`
- [ ] `Couldn't create SQLite database backup for agent '`

### wdb/upgrade.rs `recreate_global`
- [ ] `{WDB2_DIR}/{WDB_GLOB_NAME}.db`
- [ ] `Couldn't create SQLite database '`
- [ ] `out of memory`
- [ ] `Can't open SQLite backup database '`

### wdb/upgrade.rs `create_backup`
- [ ] `{WDB2_DIR}/{agent_id}.db`
- [ ] `Couldn't open source '`
- [ ] `{WDB2_DIR}/{agent_id}.db-oldv{version}-{}`
- [ ] `Couldn't open dest '`

### wdb/upgrade.rs `adjust_v4`
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, wdb.id, `
- [ ] `, attrs, `
- [ ] `, wdb.id, `

### wdb/upgrade.rs `is_older_than_v310`
- [ ] `SELECT COUNT(*) FROM agent WHERE id=0 AND last_keepalive=253402300799;`
- [ ] `, wdb.id, `
