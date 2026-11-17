# provigil-analysisd Configuration

The daemon loads configuration directives from `etc/ossec.conf` under the `<analysis>`, `<global>`, and `<ruleset>` tags, or receives runtime options from command-line arguments.

## Key Configuration Directives

```xml
<ossec_config>
  <global>
    <!-- Enable or disable JSON alert output -->
    <jsonout_output>yes</jsonout_output>
    <!-- Enable or disable standard alerts.log -->
    <alerts_log>yes</alerts_log>
    <!-- Log all incoming events into archives -->
    <logall>no</logall>
    <logall_json>yes</logall_json>
    <!-- Output file rotation settings -->
    <rotate_interval>1d</rotate_interval>
    <max_output_size>500M</max_output_size>
  </global>

  <ruleset>
    <!-- Decoder paths -->
    <decoder_dir>ruleset/decoders</decoder_dir>
    <!-- Rule paths and lists -->
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/blacklist</list>
  </ruleset>

  <logtest>
    <!-- Interactive logtest service -->
    <enabled>yes</enabled>
    <threads>4</threads>
    <max_sessions>64</max_sessions>
    <session_timeout>600</session_timeout>
  </logtest>

  <!-- External Syslog Forwarding -->
  <socket>
    <name>external-siem</name>
    <location>/var/run/syslog.sock</location>
    <mode>udp</mode>
  </socket>
</ossec_config>
```

## Command-Line Arguments

- `-f`: Run in foreground (default when supervised by `siem-api`).
- `-d`: Increase debug level (can be passed multiple times for verbose tracing).
- `-t`: Test configuration and syntax validation, then exit.
- `-c <path>`: Specify alternate configuration file (default: `etc/ossec.conf`).
- `-V`: Print daemon version and build metadata.
