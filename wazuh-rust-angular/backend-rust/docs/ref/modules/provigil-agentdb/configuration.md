# provigil-agentdb Configuration

Configuration is read from `etc/ossec.conf` or command-line parameters.

## Configuration Options

```xml
<ossec_config>
  <database>
    <!-- Database root path -->
    <path>queue/db</path>
    <!-- Maximum open database connections in connection cache -->
    <max-open-dbs>512</max-open-dbs>
    <!-- Backup and maintenance schedule -->
    <backup-interval>24h</backup-interval>
    <vacuum-interval>7d</vacuum-interval>
    <!-- Synchronous SQLite write mode (NORMAL or FULL) -->
    <sync-mode>NORMAL</sync-mode>
  </database>
</ossec_config>
```

## Options Reference

| Parameter | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `database.path` | string | `queue/db` | Directory where SQLite `.db` files are created and maintained. |
| `database.max-open-dbs` | integer | `512` | Maximum agent database file descriptors cached open simultaneously. |
| `database.backup-interval`| duration | `24h` | Period between automatic global and agent database backups. |
| `database.sync-mode` | enum | `NORMAL` | SQLite pragma synchronous mode (`OFF`, `NORMAL`, `FULL`). |
