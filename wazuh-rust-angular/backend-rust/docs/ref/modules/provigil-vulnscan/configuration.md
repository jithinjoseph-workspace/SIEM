# provigil-vulnscan Configuration

Configuration directives are defined within `etc/ossec.conf` under the `<vulnerability-detection>` block.

## Configuration Schema

```xml
<ossec_config>
  <vulnerability-detection>
    <enabled>yes</enabled>
    <!-- Update interval for vulnerability feeds -->
    <feed-update-interval>1h</feed-update-interval>
    <!-- Local CTI storage path -->
    <database-path>queue/vulnerabilities/cve.db</database-path>
    <!-- Automatic scan triggers -->
    <scan-on-inventory-change>yes</scan-on-inventory-change>
    <full-scan-interval>24h</full-scan-interval>
    <!-- CISA KEV priority boost -->
    <cisa-kev-boost>yes</cisa-kev-boost>
    <!-- Minimum CVSS score threshold for generating high-priority alerts -->
    <min-cvss-alert>7.0</min-cvss-alert>
  </vulnerability-detection>
</ossec_config>
```

## Parameter Details

| Directive | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | boolean | `yes` | Enables the manager vulnerability detection engine. |
| `feed-update-interval` | duration | `1h` | Interval between checking for updated CTI CVE definitions. |
| `scan-on-inventory-change` | boolean | `yes` | Scans an agent immediately after package additions or updates are reported. |
| `full-scan-interval` | duration | `24h` | Full baseline rescan period for all registered agents. |
| `cisa-kev-boost` | boolean | `yes` | Automatically elevates severity when a CVE appears in CISA Known Exploited Vulnerabilities. |
