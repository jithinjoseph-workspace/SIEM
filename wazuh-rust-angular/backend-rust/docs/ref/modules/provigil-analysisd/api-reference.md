# provigil-analysisd API & Socket Reference

`provigil-analysisd` exposes multiple Unix domain sockets for event ingestion, interactive log testing, and management control.

## Sockets

### 1. Ingestion Socket (`queue/sockets/queue`)
- **Protocol**: Unix Datagram or Stream with framing.
- **Message Format**: 
  - `[byte 0: Queue Kind Character]` followed by message payload:
    - `:` (`Event`): General agent syslog/event.
    - `d` (`Syscheck`): File Integrity Monitoring diff/checksum event.
    - `r` (`Rootcheck`): Rootkit detection and policy check event.
    - `s` (`SCA`): Security Configuration Assessment event.
    - `c` (`Syscollector`): System inventory hardware/package delta event.
    - `w` (`Winevt`): Windows Event Channel native log event.
    - `u` (`Upgrade`): Agent upgrade progress event.

### 2. Logtest Socket (`queue/sockets/logtest`)
- **Protocol**: Length-prefixed JSON framing.
- **Request Format**:
  ```json
  {
    "event": "Nov 16 12:00:00 host sshd[1234]: Failed password for invalid user admin from 192.168.1.100 port 22 ssh2",
    "token": "optional-session-token"
  }
  ```
- **Response Format**:
  ```json
  {
    "error": 0,
    "message": "ok",
    "data": {
      "timestamp": "2026-11-16T12:00:00Z",
      "predecoder": { "program_name": "sshd", "timestamp": "Nov 16 12:00:00" },
      "decoder": { "name": "sshd" },
      "rule": { "id": "5716", "level": 5, "description": "SSHD authentication failed." }
    }
  }
  ```

### 3. Analysis Control Socket (`queue/sockets/analysis`)
Used by `siem-api` to query live queue statistics, reload rulesets at runtime, or retrieve component health status.
- Commands:
  - `get-stats`: Returns live EPS (events per second), dropped counters, and queue saturation.
  - `reload`: Atomically reloads decoders, CDB lists, and rules without dropping in-flight connections.
