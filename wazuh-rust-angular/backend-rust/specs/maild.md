# Maild: Mail Delivery & Alert Batching

## Purpose
Delivery of security alerts, batching/digesting, hourly rate limiting, and alert data extraction.

## Features Required

### 1. Alert Data Extraction (`AlertData`)
- Extracts structured security fields from standard SIEM JSON alerts without depending on external crates:
  - `rule`: numeric rule ID
  - `level`: numeric severity level
  - `alertid`: alert event identifier
  - `date`: human-readable local timestamp
  - `location`: reporting agent or manager location
  - `comment`: rule description
  - `group`: rule categorization groups
  - `srcip`, `srcport`, `dstip`, `dstport`: network metadata
  - `user`: subject username
  - `filename`: FIM / Syscheck file path
  - `log`: full event log lines

### 2. Rate Limiting & Digest Grouping
- **Hourly Rate Limiting**:
  - `max_per_hour` (default 12, max 9999).
  - Resets every hour.
  - Warns in server logs when rate limit is exceeded:
    `"Maximum number of e-mails per hour reached (max: {}). Ignoring notifications until next hour."`
- **Delay & Batching**:
  - When grouping is enabled, holds alerts within `next_timeout` (2s) or `default_timeout` (18s) to batch related alerts into a single digest email.
  - Immediate send for alerts marked `do_not_delay` or `do_not_group`.

