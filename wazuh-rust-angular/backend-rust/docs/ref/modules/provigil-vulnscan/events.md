# provigil-vulnscan Event & Alert Schema

Detected vulnerabilities are formatted into structured JSON documents and emitted into the alert stream for ClickHouse ingestion (`siem_vulnerabilities` and `siem_alerts`).

## Vulnerability Detection Event Format

```json
{
  "timestamp": "2026-11-16T12:00:00Z",
  "agent": {
    "id": "042",
    "name": "WIN-SRV-PROD-01",
    "ip": "10.0.1.50"
  },
  "vulnerability": {
    "cve": "CVE-2024-21413",
    "title": "Microsoft Outlook Remote Code Execution Vulnerability",
    "severity": "Critical",
    "cvss": {
      "cvss3_score": 9.8,
      "cvss3_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    },
    "cisa_kev": true,
    "package": {
      "name": "Microsoft Office 365 Apps",
      "version": "16.0.17126.20132",
      "architecture": "x64",
      "format": "win"
    },
    "remediation": {
      "fixed_version": "16.0.17231.20182",
      "reference_url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21413"
    },
    "status": "Active"
  }
}
```

## Resolution Event Format

When a software update fixes an existing vulnerability, a resolution event is generated:

```json
{
  "timestamp": "2026-11-16T12:30:00Z",
  "agent": { "id": "042" },
  "vulnerability": {
    "cve": "CVE-2024-21413",
    "package": { "name": "Microsoft Office 365 Apps" },
    "status": "Resolved",
    "resolved_at": "2026-11-16T12:30:00Z"
  }
}
```
