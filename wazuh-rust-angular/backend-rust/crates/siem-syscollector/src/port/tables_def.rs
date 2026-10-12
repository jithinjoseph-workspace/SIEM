//! `syscollectorTablesDef.hpp`: the dbsync tables, the rsync configurations
//! and the item id fields (generated from the header, byte for byte).


pub const OS_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_osinfo (
    hostname TEXT,
    architecture TEXT,
    os_name TEXT,
    os_version TEXT,
    os_codename TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_patch TEXT,
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    os_display_version TEXT,
    checksum TEXT,
    PRIMARY KEY (os_name)) WITHOUT ROWID;"#;

pub const OS_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_osinfo",
        "component":"syscollector_osinfo",
        "index":"os_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE os_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const OS_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_osinfo",
        "first_query":
            {
                "column_list":["os_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"os_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["os_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"os_name ASC",
                "count_opt":1
            },
        "component":"syscollector_osinfo",
        "index":"os_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["os_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        }"#;

pub const HW_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_hwinfo (
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_mhz DOUBLE,
    ram_total INTEGER,
    ram_free INTEGER,
    ram_usage INTEGER,
    checksum TEXT,
    PRIMARY KEY (board_serial)) WITHOUT ROWID;"#;

pub const HW_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hwinfo",
        "component":"syscollector_hwinfo",
        "index":"board_serial",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE board_serial ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const HW_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_hwinfo",
        "first_query":
            {
                "column_list":["board_serial"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"board_serial DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["board_serial"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"board_serial ASC",
                "count_opt":1
            },
        "component":"syscollector_hwinfo",
        "index":"board_serial",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["board_serial, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        }"#;

pub const HOTFIXES_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_hotfixes(
    hotfix TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix)) WITHOUT ROWID;"#;

pub const HOTFIXES_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hotfixes",
        "component":"syscollector_hotfixes",
        "index":"hotfix",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE hotfix ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const HOTFIXES_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_hotfixes",
        "first_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix ASC",
                "count_opt":1
            },
        "component":"syscollector_hotfixes",
        "index":"hotfix",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["hotfix, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        }"#;

pub const PACKAGES_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_packages(
    name TEXT,
    version TEXT,
    vendor TEXT,
    install_time TEXT,
    location TEXT,
    architecture TEXT,
    groups TEXT,
    description TEXT,
    size BIGINT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    format TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (name,version,architecture,format,location)) WITHOUT ROWID;"#;
pub const PACKAGES_ITEM_ID_FIELDS: &[&str] = &["name", "version", "architecture", "format", "location"];

pub const PACKAGES_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_packages",
        "component":"syscollector_packages",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const PACKAGES_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_packages",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_packages",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        }"#;

pub const PROCESSES_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_processes",
        "first_query":
            {
                "column_list":["pid"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"pid DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["pid"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"pid ASC",
                "count_opt":1
            },
        "component":"syscollector_processes",
        "index":"pid",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["pid, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const PROCESSES_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_processes",
        "component":"syscollector_processes",
        "index":"pid",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE pid ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const PROCESSES_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_processes (
    pid TEXT,
    name TEXT,
    state TEXT,
    ppid BIGINT,
    utime BIGINT,
    stime BIGINT,
    cmd TEXT,
    argvs TEXT,
    euser TEXT,
    ruser TEXT,
    suser TEXT,
    egroup TEXT,
    rgroup TEXT,
    sgroup TEXT,
    fgroup TEXT,
    priority BIGINT,
    nice BIGINT,
    size BIGINT,
    vm_size BIGINT,
    resident BIGINT,
    share BIGINT,
    start_time BIGINT,
    pgrp BIGINT,
    session BIGINT,
    nlwp BIGINT,
    tgid BIGINT,
    tty BIGINT,
    processor BIGINT,
    checksum TEXT,
    PRIMARY KEY (pid)) WITHOUT ROWID;"#;

pub const PORTS_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_ports",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_ports",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const PORTS_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_ports",
        "component":"syscollector_ports",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const PORTS_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_ports (
       protocol TEXT,
       local_ip TEXT,
       local_port BIGINT,
       remote_ip TEXT,
       remote_port BIGINT,
       tx_queue BIGINT,
       rx_queue BIGINT,
       inode BIGINT,
       state TEXT,
       pid BIGINT,
       process TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (inode, protocol, local_ip, local_port)) WITHOUT ROWID;"#;
pub const PORTS_ITEM_ID_FIELDS: &[&str] = &["inode", "protocol", "local_ip", "local_port"];

pub const NETIFACE_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_network_iface",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_iface",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const NETIFACE_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_iface",
        "component":"syscollector_network_iface",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const NETIFACE_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_network_iface (
       name TEXT,
       adapter TEXT,
       type TEXT,
       state TEXT,
       mtu INTEGER,
       mac TEXT,
       tx_packets INTEGER,
       rx_packets INTEGER,
       tx_bytes INTEGER,
       rx_bytes INTEGER,
       tx_errors INTEGER,
       rx_errors INTEGER,
       tx_dropped INTEGER,
       rx_dropped INTEGER,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (name,adapter,type)) WITHOUT ROWID;"#;
pub const NETIFACE_ITEM_ID_FIELDS: &[&str] = &["name", "adapter", "type"];

pub const NETPROTO_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_network_protocol",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_protocol",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const NETPROTO_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_protocol",
        "component":"syscollector_network_protocol",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const NETPROTO_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_network_protocol (
       iface TEXT,
       type TEXT,
       gateway TEXT,
       dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
       metric TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,type)) WITHOUT ROWID;"#;
pub const NETPROTO_ITEM_ID_FIELDS: &[&str] = &["iface", "type"];

pub const NETADDRESS_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_network_address",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_address",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const NETADDRESS_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_address",
        "component":"syscollector_network_address",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const NETADDR_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_network_address (
       iface TEXT,
       proto INTEGER,
       address TEXT,
       netmask TEXT,
       broadcast TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,proto,address)) WITHOUT ROWID;"#;
pub const NETADDRESS_ITEM_ID_FIELDS: &[&str] = &["iface", "proto", "address"];

pub const USERS_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_users",
        "first_query":
            {
                "column_list":["user_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"user_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["user_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"user_name ASC",
                "count_opt":1
            },
        "component":"syscollector_users",
        "index":"user_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "column_list":["user_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const USERS_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_users",
        "component":"syscollector_users",
        "index":"user_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE user_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const USERS_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_users (
        user_name TEXT,
        user_full_name TEXT,
        user_home TEXT,
        user_id BIGINT,
        user_uid_signed BIGINT,
        user_uuid TEXT,
        user_groups TEXT,
        user_group_id BIGINT,
        user_group_id_signed BIGINT,
        user_created DOUBLE,
        user_roles TEXT,
        user_shell TEXT,
        user_type TEXT,
        user_is_hidden INTEGER,
        user_is_remote INTEGER,
        user_last_login BIGINT,
        user_auth_failed_count BIGINT,
        user_auth_failed_timestamp DOUBLE,
        user_password_last_change DOUBLE,
        user_password_expiration_date INTEGER,
        user_password_hash_algorithm TEXT,
        user_password_inactive_days INTEGER,
        user_password_max_days_between_changes INTEGER,
        user_password_min_days_between_changes INTEGER,
        user_password_status TEXT,
        user_password_warning_days_before_expiration INTEGER,
        process_pid BIGINT,
        host_ip TEXT,
        login_status INTEGER,
        login_tty TEXT,
        login_type TEXT,
        checksum TEXT,
        PRIMARY KEY (user_name)) WITHOUT ROWID;"#;
pub const USERS_ITEM_ID_FIELDS: &[&str] = &["user_name"];

pub const GROUPS_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_groups",
        "first_query":
            {
                "column_list":["group_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"group_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["group_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"group_name ASC",
                "count_opt":1
            },
        "component":"syscollector_groups",
        "index":"group_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "column_list":["group_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        }"#;

pub const GROUPS_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_groups",
        "component":"syscollector_groups",
        "index":"group_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE group_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const GROUPS_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_groups (
    group_id BIGINT,
    group_name TEXT,
    group_description TEXT,
    group_id_signed BIGINT,
    group_uuid TEXT,
    group_is_hidden INTEGER,
    group_users TEXT,
    checksum TEXT,
    PRIMARY KEY (group_name)) WITHOUT ROWID;"#;

pub const SERVICES_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_services",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_services",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        }"#;

pub const SERVICES_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_services",
        "component":"syscollector_services",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const SERVICES_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_services (
        service_id TEXT,
        service_name TEXT,
        service_description TEXT,
        service_type TEXT,
        service_state TEXT,
        service_sub_state TEXT,
        service_enabled TEXT,
        service_start_type TEXT,
		service_restart TEXT,
		service_frequency BIGINT,
		service_starts_on_mount INTEGER,
		service_starts_on_path_modified TEXT,
		service_starts_on_not_empty_directory TEXT,
		service_inetd_compatibility INTEGER,
        process_pid BIGINT,
        process_executable TEXT,
        process_args TEXT,
		process_user_name TEXT,
		process_group_name TEXT,
		process_working_dir TEXT,
		process_root_dir TEXT,
        file_path TEXT,
        service_address TEXT,
        log_file_path TEXT,
        error_log_file_path TEXT,
        service_exit_code INTEGER,
        service_win32_exit_code INTEGER,
        service_following TEXT,
        service_object_path TEXT,
        service_target_ephemeral_id BIGINT,
        service_target_type TEXT,
        service_target_address TEXT,
        checksum TEXT,
        item_id TEXT,
        PRIMARY KEY (service_id, file_path)) WITHOUT ROWID;"#;
pub const SERVICES_ITEM_ID_FIELDS: &[&str] = &["service_id", "file_path"];


pub const BROWSER_EXTENSIONS_START_CONFIG_STATEMENT: &str = r#"{"table":"dbsync_browser_extensions",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_browser_extensions",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        }"#;

pub const BROWSER_EXTENSIONS_SYNC_CONFIG_STATEMENT: &str = r#"
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_browser_extensions",
        "component":"syscollector_browser_extensions",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    "#;

pub const BROWSER_EXTENSIONS_SQL_STATEMENT: &str = r#"CREATE TABLE dbsync_browser_extensions (
        browser_name TEXT,
        user_id TEXT,
        package_name TEXT,
        package_id TEXT,
        package_version TEXT,
        package_description TEXT,
        package_vendor TEXT,
        package_build_version TEXT,
        package_path TEXT,
        browser_profile_name TEXT,
        browser_profile_path TEXT,
        package_reference TEXT,
        package_permissions TEXT,
        package_type TEXT,
        package_enabled INTEGER,
        package_visible INTEGER,
        package_autoupdate INTEGER,
        package_persistent INTEGER,
        package_from_webstore INTEGER,
        browser_profile_referenced INTEGER,
        package_installed TEXT,
        file_hash_sha256 TEXT,
        checksum TEXT,
        item_id TEXT,
        PRIMARY KEY (browser_name,user_id,browser_profile_path,package_name,package_version)) WITHOUT ROWID;"#;
pub const BROWSER_EXTENSIONS_ITEM_ID_FIELDS: &[&str] = &["browser_name", "user_id", "browser_profile_path", "package_name", "package_version"];


pub const NET_IFACE_TABLE: &str = "dbsync_network_iface";
pub const NET_PROTOCOL_TABLE: &str = "dbsync_network_protocol";
pub const NET_ADDRESS_TABLE: &str = "dbsync_network_address";
pub const PACKAGES_TABLE: &str = "dbsync_packages";
pub const HOTFIXES_TABLE: &str = "dbsync_hotfixes";
pub const PORTS_TABLE: &str = "dbsync_ports";
pub const PROCESSES_TABLE: &str = "dbsync_processes";
pub const OS_TABLE: &str = "dbsync_osinfo";
pub const HW_TABLE: &str = "dbsync_hwinfo";
pub const USERS_TABLE: &str = "dbsync_users";
pub const GROUPS_TABLE: &str = "dbsync_groups";
pub const SERVICES_TABLE: &str = "dbsync_services";
pub const BROWSER_EXTENSIONS_TABLE: &str = "dbsync_browser_extensions";
