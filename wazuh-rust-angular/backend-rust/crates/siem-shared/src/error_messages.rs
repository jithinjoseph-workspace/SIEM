//! Wazuh Canonical Error, Warning and Information Messages (src/error_messages)
//!
//! Provides the centralized error definitions and codes matching:
//! - `error_messages.h` (codes 1101 - 9000)
//! - `warning_messages.h`
//! - `information_messages.h`
//! - `debug_messages.h`

/// System and Process Errors (1101 - 1144)
pub mod system {
    pub const FORK_ERROR: &str = "(1101): Could not fork due to [(%d)-(%s)].";
    pub const MEM_ERROR: &str = "(1102): Could not acquire memory due to [(%d)-(%s)].";
    pub const FOPEN_ERROR: &str = "(1103): Could not open file '%s' due to [(%d)-(%s)].";
    pub const SIZE_ERROR: &str = "(1104): Maximum string size reached for: %s.";
    pub const NULL_ERROR: &str = "(1105): Attempted to use null string.";
    pub const FORMAT_ERROR: &str = "(1106): String not correctly formatted.";
    pub const MKDIR_ERROR: &str = "(1107): Could not create directory '%s' due to [(%d)-(%s)].";
    pub const HOME_ERROR: &str = "(1108): Unable to find Wazuh install directory. Export it to WAZUH_HOME environment variable.";
    pub const THREAD_ERROR: &str = "(1109): Unable to create new pthread.";
    pub const FWRITE_ERROR: &str = "(1110): Could not write file '%s' due to [(%d)-(%s)].";
    pub const WAITPID_ERROR: &str = "(1111): Error during waitpid()-call due to [(%d)-(%s)].";
    pub const SETSID_ERROR: &str = "(1112): Error during setsid()-call due to [(%d)-(%s)].";
    pub const MUTEX_ERROR: &str = "(1113): Unable to set pthread mutex.";
    pub const SELECT_ERROR: &str = "(1114): Error during select()-call due to [(%d)-(%s)].";
    pub const FREAD_ERROR: &str = "(1115): Could not read from file '%s' due to [(%d)-(%s)].";
    pub const FSEEK_ERROR: &str = "(1116): Could not set position in file '%s' due to [(%d)-(%s)].";
    pub const FILE_ERROR: &str = "(1117): Error handling file '%s'.";
    pub const FSTAT_ERROR: &str = "(1118): Could not retrieve information of file '%s' due to [(%d)-(%s)].";
    pub const FGETS_ERROR: &str = "(1119): Invalid line on file '%s': %s.";
    pub const GLOB_ERROR: &str = "(1121): Glob error. Invalid pattern: '%s'.";
    pub const GLOB_NFOUND: &str = "(1122): No file found by pattern: '%s'.";
    pub const UNLINK_ERROR: &str = "(1123): Unable to delete file: '%s' due to [(%d)-(%s)].";
    pub const RENAME_ERROR: &str = "(1124): Could not rename file '%s' to '%s' due to [(%d)-(%s)].";
    pub const OPEN_ERROR: &str = "(1126): Unable to open file '%s' due to [(%d)-(%s)].";
    pub const CHMOD_ERROR: &str = "(1127): Could not chmod object '%s' due to [(%d)-(%s)].";
    pub const MKSTEMP_ERROR: &str = "(1128): Could not create temporary file '%s' due to [(%d)-(%s)].";
    pub const DELETE_ERROR: &str = "(1129): Could not unlink file '%s' due to [(%d)-(%s)].";
    pub const SETGID_ERROR: &str = "(1130): Unable to switch to group '%s' due to [(%d)-(%s)].";
    pub const SETUID_ERROR: &str = "(1131): Unable to switch to user '%s' due to [(%d)-(%s)].";
    pub const CHROOT_ERROR: &str = "(1132): Unable to chroot to directory '%s' due to [(%d)-(%s)].";
    pub const CHDIR_ERROR: &str = "(1133): Unable to chdir to directory '%s' due to [(%d)-(%s)].";
    pub const LINK_ERROR: &str = "(1134): Unable to link from '%s' to '%s' due to [(%d)-(%s)].";
    pub const CHOWN_ERROR: &str = "(1135): Could not chown object '%s' due to [(%d)-(%s)].";
    pub const EPOLL_ERROR: &str = "(1136): Could not handle epoll descriptor.";
    pub const LOST_ERROR: &str = "(1137): Lost connection with manager. Setting lock.";
    pub const FTELL_ERROR: &str = "(1139): Could not get position from file '%s' due to [(%d)-(%s)].";
    pub const FCLOSE_ERROR: &str = "(1140): Could not close file '%s' due to [(%d)-(%s)].";
}

/// Common Configuration & Network Errors (1201 - 1250)
pub mod common {
    pub const CONN_ERROR: &str = "(1201): No remote connection configured.";
    pub const CONFIG_ERROR: &str = "(1202): Configuration error at '%s'.";
    pub const USER_ERROR: &str = "(1203): Invalid user '%s' or group '%s' given: %s (%d)";
    pub const CONNTYPE_ERROR: &str = "(1204): Invalid connection type: '%s'.";
    pub const PORT_ERROR: &str = "(1205): Invalid port number: '%d'.";
    pub const BIND_ERROR: &str = "(1206): Unable to Bind port '%d' due to [(%d)-(%s)]";
    pub const RCONFIG_ERROR: &str = "(1207): %s remote configuration in '%s' is corrupted.";
    pub const ENROLL_CONN_ERROR: &str = "(1208): Unable to connect to enrollment service at '[%s]:%d'";
    pub const ENROLL_CONNECTED: &str = "(1209): Connected to enrollment service at '[%s]:%d'";
    pub const QUEUE_ERROR: &str = "(1210): Queue '%s' not accessible: '%s'";
    pub const QUEUE_FATAL: &str = "(1211): Unable to access queue: '%s'. Giving up.";
    pub const PID_ERROR: &str = "(1212): Unable to create PID file.";
    pub const DENYIP_WARN: &str = "(1213): Message from '%s' not allowed. Cannot find the ID of the agent.";
    pub const MSG_ERROR: &str = "(1214): Problem receiving message from '%s'.";
    pub const CLIENT_ERROR: &str = "(1215): No client configured. Exiting.";
    pub const CONNS_ERROR: &str = "(1216): Unable to connect to '[%s]:%d/%s': '%s'.";
    pub const SEC_ERROR: &str = "(1217): Error creating encrypted message.";
    pub const SEND_ERROR: &str = "(1218): Unable to send message to '%s': %s";
    pub const RULESLOAD_ERROR: &str = "(1219): Unable to access the rules directory.";
    pub const RULES_ERROR: &str = "(1220): Error loading the rules: '%s'.";
    pub const LISTS_ERROR: &str = "(1221): Error loading the list: '%s'.";
    pub const IMSG_ERROR: &str = "(1222): Invalid msg: %s";
    pub const QUEUE_SEND: &str = "(1224): Error sending message to queue.";
    pub const SIGNAL_RECV: &str = "(1225): SIGNAL [(%d)-(%s)] Received. Exit Cleaning...";
    pub const XML_ERROR: &str = "(1226): Error reading XML file '%s': %s (line %d).";
    pub const XML_ERROR_VAR: &str = "(1227): Error applying XML variables '%s': %s.";
    pub const XML_NO_ELEM: &str = "(1228): Element '%s' without any option.";
    pub const XML_INVALID: &str = "(1229): Invalid element '%s' on the '%s' config.";
    pub const XML_INVELEM: &str = "(1230): Invalid element in the configuration: '%s'.";
    pub const XML_ELEMNULL: &str = "(1231): Invalid NULL element in the configuration.";
    pub const XML_READ_ERROR: &str = "(1232): Error reading XML. Unknown cause.";
    pub const XML_INVATTR: &str = "(1233): Invalid attribute '%s' in the configuration: '%s'.";
    pub const XML_VALUENULL: &str = "(1234): Invalid NULL content for element: %s.";
    pub const XML_VALUEERR: &str = "(1235): Invalid value for element '%s': %s.";
    pub const XML_MAXREACHED: &str = "(1236): Maximum number of elements reached for: %s.";
    pub const INVALID_IP: &str = "(1237): Invalid ip address: '%s'.";
    pub const INVALID_ELEMENT: &str = "(1238): Invalid value for element '%s': %s";
    pub const NO_CONFIG: &str = "(1239): Configuration file not found: '%s'.";
    pub const INVALID_TIME: &str = "(1240): Invalid time format: '%s'.";
    pub const INVALID_DAY: &str = "(1241): Invalid day format: '%s'.";
    pub const ACCEPT_ERROR: &str = "(1242): Couldn't accept TCP connections: %s (%d)";
    pub const RECV_ERROR: &str = "(1243): Couldn't receive message from peer: %s (%d)";
    pub const DUP_SECURE: &str = "(1244): Can't add more than one secure connection.";
    pub const SEND_DISCON: &str = "(1245): Sending message to disconnected agent '%s'.";
    pub const SHARED_ERROR: &str = "(1246): Unable to send file '%s' to agent ID '%s'.";
    pub const TCP_NOT_SUPPORT: &str = "(1247): TCP not supported for this operating system.";
    pub const TCP_EPIPE: &str = "(1248): Unable to send message. Connection has been closed by remote server.";
    pub const CONN_REF: &str = "(1249): Unable to send message. Connection with remote server refused.";
    pub const ACCESS_ERROR: &str = "(1250): Error trying to execute \"%s\": %s (%d).";
}

/// Active Response Errors (1280 - 1350)
pub mod execd {
    pub const AR_CMD_MISS: &str = "(1280): Missing command options. You must specify a 'name' and 'executable'.";
    pub const AR_MISS: &str = "(1281): Missing options in the active response configuration.";
    pub const ARQ_ERROR: &str = "(1301): Unable to connect to active response queue.";
    pub const AR_INV_LOC: &str = "(1302): Invalid active response location: '%s'.";
    pub const AR_INV_CMD: &str = "(1303): Invalid command '%s' in the active response.";
    pub const AR_DEF_AGENT: &str = "(1304): No agent defined for response.";
    pub const AR_NO_TIMEOUT: &str = "(1305): Timeout not allowed for command: '%s'.";
    pub const EXECD_INV_MSG: &str = "(1310): Invalid active response (execd) message '%s'.";
    pub const EXEC_INV_NAME: &str = "(1311): Invalid command name '%s' provided.";
    pub const EXEC_CMDERROR: &str = "(1312): Error executing '%s': %s";
    pub const EXEC_INV_CONF: &str = "(1313): Invalid active response config: '%s'.";
    pub const EXEC_SHUTDOWN: &str = "(1314): Shutdown received. Deleting responses.";
    pub const EXEC_INV_JSON: &str = "(1315): Invalid JSON message: '%s'";
    pub const EXEC_INV_CMD: &str = "(1316): Invalid AR command: '%s'";
    pub const EXEC_CMD_FAIL: &str = "(1317): Could not launch command %s (%d)";
    pub const EXEC_BAD_NAME: &str = "(1318): Command name truncated %s";
    pub const AR_NOAGENT_ERROR: &str = "(1320): Agent '%s' not found.";
    pub const EXEC_QUEUE_CONNECTION_ERROR: &str = "(1321): Error communicating with queue '%s'.";
    pub const EXEC_QUEUE_BUSY: &str = "(1322): Socket busy.";
    pub const EXEC_DISABLED: &str = "(1350): Active response disabled.";
}

/// Authentication and Crypto Errors (1401 - 1410)
pub mod auth {
    pub const INVALID_KEY: &str = "(1401): Error reading authentication key: '%s'.";
    pub const NO_AUTHFILE: &str = "(1402): Authentication key file '%s' not found.";
    pub const ENCFORMAT_ERROR: &str = "(1403): Incorrectly formatted message from agent '%s' (host '%s').";
    pub const ENCKEY_ERROR: &str = "(1404): Authentication error. Wrong key or corrupt payload. Message received from agent '%s' at '%s'.";
    pub const ENCSIZE_ERROR: &str = "(1405): Message size not valid: '%64s'.";
    pub const ENCSUM_ERROR: &str = "(1406): Checksum mismatch. Message received from agent '%s' at '%s'.";
    pub const ENCTIME_ERROR: &str = "(1407): Duplicated counter for '%s'.";
    pub const ENC_IP_ERROR: &str = "(1408): Invalid ID %s for the source ip: '%s' (name '%s').";
    pub const ENCFILE_CHANGED: &str = "(1409): Authentication file changed. Updating.";
    pub const ENC_READ: &str = "(1410): Reading authentication keys file.";
}

/// Database & WDB Errors (5201 - 5217)
pub mod database {
    pub const DBINIT_ERROR: &str = "(5201): Error initializing database handler.";
    pub const DBCONN_ERROR: &str = "(5202): Error connecting to database '%s'(%s): ERROR: %s.";
    pub const DBQUERY_ERROR: &str = "(5203): Error executing query '%s'. Error: '%s'.";
    pub const DB_GENERROR: &str = "(5204): Database error. Unable to run query.";
    pub const DB_MISS_CONFIG: &str = "(5205): Missing database configuration. It requires host, user, pass and database.";
    pub const DB_CONFIGERR: &str = "(5206): Database configuration error.";
    pub const DB_COMPILED: &str = "(5207): Wazuh not compiled with support for '%s'.";
    pub const DB_MAINERROR: &str = "(5208): Multiple database errors. Exiting.";
    pub const DB_CLOSING: &str = "(5209): Closing connection to database.";
    pub const DB_ATTEMPT: &str = "(5210): Attempting to reconnect to database.";
    pub const DB_SQL_ERROR: &str = "(5211): SQL error: '%s'";
    pub const DB_TRANSACTION_ERROR: &str = "(5212): Cannot begin transaction.";
    pub const DB_CACHE_ERROR: &str = "(5213): Cannot cache statement.";
    pub const DB_CACHE_NULL_STMT: &str = "(5214): Null statement on internal cache.";
    pub const DB_AGENT_SQL_ERROR: &str = "(5215): DB(%s) SQL Error: '%s'.";
    pub const DB_INVALID_DELTA_MSG: &str = "(5216): DB(%s) Could not bind delta field '%s' from '%s' scan.";
    pub const DB_DELTA_PARSING_ERR: &str = "(5217): Could not parse syscollector delta information as JSON.";
}

/// Logcollector Messages & Errors (1600 - 1611, 1901 - 1976)
pub mod logcollector {
    pub const SYSTEM_ERROR: &str = "(1600): Internal error. Exiting..";
    pub const MISS_LOG_FORMAT: &str = "(1901): Missing 'log_format' element.";
    pub const MISS_FILE: &str = "(1902): Missing 'location' element.";
    pub const INV_EVTLOG: &str = "(1903): Invalid event log: '%s'.";
    pub const LOGC_FILE_ERROR: &str = "(1904): File not available, ignoring it: '%s'.";
    pub const NO_FILE: &str = "(1905): No file configured to monitor.";
    pub const PARSE_ERROR: &str = "(1906): Error parsing file: '%s'.";
    pub const NSTD_EVTLOG: &str = "(1907): Non-standard event log set: '%s'.";
    pub const READING_FILE: &str = "(1950): Analyzing file: '%s'.";
    pub const READING_EVTLOG: &str = "(1951): Analyzing event log: '%s'.";
    pub const VAR_LOG_MON: &str = "(1952): Monitoring variable log file: '%s'.";
    pub const INV_MULTILOG: &str = "(1953): Invalid DJB multilog file: '%s'.";
    pub const MISS_SOCK_NAME: &str = "(1954): Missing field 'name' for socket.";
    pub const MISS_SOCK_LOC: &str = "(1955): Missing field 'location' for socket.";
    pub const NEW_GLOB_FILE: &str = "(1957): New file that matches the '%s' pattern: '%s'.";
    pub const DUP_FILE: &str = "(1958): Log file '%s' is duplicated.";
    pub const FORGET_FILE: &str = "(1959): File '%s' no longer exists.";
    pub const FILE_LIMIT: &str = "(1960): File limit has been reached (%d).";
    pub const CURRENT_FILES: &str = "(1961): Files being monitored: %i/%i.";
    pub const OPEN_ATTEMPT: &str = "(1962): Unable to open file '%s'. Remaining attempts: %d";
    pub const OPEN_UNABLE: &str = "(1963): Unable to open file '%s'.";
    pub const NON_TEXT_FILE: &str = "(1964): File '%s' is not ASCII or UTF-8 encoded.";
    pub const EXCLUDE_FILE: &str = "(1965): File excluded: '%s'.";
    pub const DUP_FILE_INODE: &str = "(1966): Inode for file '%s' already found. Skipping it.";
    pub const LOCALFILE_REGEX: &str = "(1967): Syntax error on multiline_regex: '%s'";
    pub const MISS_MULT_REGEX: &str = "(1968): Missing 'multiline_regex' element.";
    pub const FAIL_SHA1_GEN: &str = "(1969): Failure to generate the SHA1 hash from file '%s'";
}

/// Informational Messages
pub mod info {
    pub const STARTUP_MSG: &str = "Started (pid: %d).";
    pub const PRIVSEP_MSG: &str = "Chrooted to directory: %s, using user: %s";
    pub const MSG_SOCKET_SIZE: &str = "(unix_domain) Maximum send buffer set to: '%d'.";
    pub const NO_SYSLOG: &str = "(1501): IP or network must be present in syslog access list (allowed-ips). Syslog server disabled.";
    pub const CONN_TO: &str = "Connected to '%s' (%s queue)";
    pub const MAIL_DIS: &str = "E-Mail notification disabled. Clean Exit.";
    pub const WAZUH_HOMEDIR: &str = "Wazuh home directory: %s";
}
