# Risk Fabric

Risk Fabric gives every alert a business risk score (1–100). The score uses four things:

- which business process the computer belongs to;
- how privileged the user is;
- which time windows are in effect;
- the alert's level and ATT&CK tactic.

Console page: `/analyst/risk-fabric`. API: `/api/v1/risk-fabric/*`.
Code: `crates/siem-risk-fabric/src/engine.rs` and `crates/siem-risk-fabric/src/api.rs`; in siem-api, `crates/siem-api/src/main.rs` and `crates/siem-api/src/engine_docs.rs`.

## Decisions

### Each tenant has its own settings

The business processes and time windows describe one customer's computers and calendar. So each tenant keeps its own copy, stored in ClickHouse table `siem_engine_docs` under id `risk_fabric:<tenant>`.

A tenant that has never changed its settings uses the shared settings (id `risk_fabric`). These are the settings stored before this change, or the defaults. Its first change creates its own copy.

The reason: until this change there was one set of settings for all tenants. One tenant's edit changed every other tenant's scores, and nobody could tell which tenant had changed what.

Each alert is scored with its own tenant's settings: the tenant recorded on the alert, otherwise its agent's tenant.

### Only admins change the settings

Only a platform admin or a tenant admin can add, change or delete a process or a window. Anyone else gets HTTP 403.

Everyone can still read the settings and run the what-if evaluation (`POST /evaluate`), because that changes nothing. The console hides the editing buttons from other users.

### Input checks (HTTP 400 with the reason)

The server refuses:

- a process without a name or id;
- weights outside 0.1–5;
- a pattern that is empty or longer than 128 characters;
- a process with no asset or group pattern, because it would match no computer;
- a window multiplier outside 0.1–3;
- an unknown window type;
- a date range without readable start and end dates (`YYYY-MM-DD`), or with the end before the start.

An empty pattern matches nothing. Before this change it matched every alert.

### Time windows

Windows use the server's local time, because office hours and month-end are local.

- **Office hours:** Monday–Friday 08:00–18:00. An off-hours window (its id or name says off-hours, night or unattended) is in effect outside those hours; any other office-hours window is in effect during them.
- **Month-end financial close:** in effect from the 27th to the 1st only. Before this change it applied ×1.15 on every other day.
- **Other recurring windows**, such as maintenance: in effect while an admin has them switched on.
- **Date range:** in effect from the start date to the end date. A range whose dates can't be read is never in effect. Before this change it was always in effect.

The summary's count of active windows counts the windows **in effect now**, not every window that is switched on.

### New-process form

The form starts empty, with example patterns shown only as placeholders. Before this change it came pre-filled with sample patterns, so saving it unchanged created a nameless process that matched payment-like names and a test network range.
