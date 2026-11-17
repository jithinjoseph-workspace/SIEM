# provigil-vulnscan

## Overview

`provigil-vulnscan` is the specialized manager-side vulnerability detection engine for ProVigil. It inspects endpoint software inventories (installed packages, operating system versions, and installed hotfixes/KBs) and correlates them with comprehensive Cyber Threat Intelligence (CTI) feeds in standard CVE v5 JSON formats.

Unlike endpoint-resident scanners that impact user workstation performance, `provigil-vulnscan` runs centrally on the ProVigil Manager. It scans directly against the agent inventories stored in `provigil-agentdb`. This architecture enables **offline scanning**: workstations that are disconnected, in sleep mode, or offline are still continuously evaluated against freshly published zero-day CVE advisories using their last-reported inventory.

## Key Features

- **Continuous Vulnerability Assessment**: Evaluates CVE impact across Windows, Linux, and macOS package formats.
- **Offline Agent Scanning**: Instantly detects newly disclosed vulnerabilities on offline agents without requiring endpoint compute or active connectivity.
- **CTI Multi-Source Feed Ingestion**: Ingests, normalizes, and indexes NVD, CISA KEV (Known Exploited Vulnerabilities), vendor advisories (RedHat, Debian, Ubuntu, Microsoft MSRC), and OSV feeds.
- **CPE Matching & Version Normalization**: Advanced semantic versioning parser supporting RPM, DEB, SemVer, and Windows build numbers.
- **Exploit & Severity Enrichment**: Flags vulnerabilities present in CISA KEV or associated with public exploit code with prioritized alert severities.
