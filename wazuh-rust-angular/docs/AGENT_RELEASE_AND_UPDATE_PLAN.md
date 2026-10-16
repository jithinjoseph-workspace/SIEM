# Agent releases and fleet updates (planned)

Status: **planned, not started.** The upgrade engine it builds on is done (see
"Already in place"). This document records the agreed design so it can be
built later.

## Goal

Releasing a new agent version is the **platform owner's** job (super admin).
Each organisation (tenant) only decides **when** its own agents take a
published release. A tenant admin sees "new version available" and updates
all of their agents with one button, or lets them update automatically.

## Roles

| Role | Can do |
|---|---|
| **Super admin** (platform owner) | Build, sign and publish agent releases (Windows, Linux); write release notes; mark a release *required* (security); withdraw a bad release; see agent versions across all tenants |
| **Tenant admin** (organisation admin) | See "new version available" for their agents; update all or selected agents; turn auto-update on/off with a maintenance window; follow progress and retry failures. **Cannot** upload or pick their own packages |
| **Analyst** | See each agent's version and update status only |

## How it works

1. The super admin publishes release `vX.Y.Z`. The platform signs the packages
   with the **platform signing key** and stores them in one central **release
   repository**.
2. Every tenant's manager points its `<agent-upgrade><wpk_repository>` at that
   repository. The repository uses Wazuh's layout, which the ported upgrade
   module already reads: `<os path>/versions` (lines of `<version> <sha1>`)
   next to the `.wpk` files.
3. A tenant admin clicks **Update all**: siem-api sends one `upgrade` request
   with the tenant's outdated agents to modulesd (`queue/tasks/upgrade`). The
   manager upgrades a few agents at a time (`max_threads`).
4. Each agent checks the package signature against the platform certificate,
   installs, restarts and reports the result. The tenant sees it per agent.

## Already in place (2026-10-15)

- Manager upgrade engine (`siem-modulesd`: agent_upgrade, task_manager,
  download). Validation, repository lookup, WPK download and SHA1 check,
  chunked transfer, task states. Identical to Wazuh 4.14.7 in a side-by-side
  test against the C code.
- Agent side (`siem-winagent/src/upgrade.rs`): receive, WPK signature check
  (CA store), unpack, run the installer, report the result. Identical to the C
  agent.
- API: `POST /api/v1/agents/:id/upgrade`, `GET /api/v1/agents/:id/upgrade`.
- UI: per-agent **Upgrade** tab (agent details), tenant admins only.

## To build

### 1. Release builder and signer (hardest part)
- Build step that turns the Rust agent builds into a WPK:
  - merged file (`!<size> <name>` entries) with the new binaries and the
    installer script;
  - gzip;
  - `WPK256\0` + signer certificate (PEM) + `\0` + RSA-SHA256 signature +
    content (the format the agent's `w_wpk_unsign` port reads).
- Windows `upgrade.bat`: stop the `WazuhSvc` service, replace the files (keep
  `ossec.conf`, `client.keys`, queues), start the service, write
  `upgrade\upgrade_result` (`0` ok, `1` missing dependency, `2` failed). The
  agent reports that file to the manager after it restarts.
- Linux `upgrade.sh`: same idea for the ported Linux agent.
- Test a real install end to end (needs an admin / root machine).

### 2. Platform signing
- Platform signing CA. The private key is kept offline or in a secret store,
  and only the super admin's publishing flow can use it.
- Its public certificate (`wpk_root.pem`) is installed with every agent, and
  the agents' `<agent-upgrade><ca_verification><ca_store>` points to it.
  Today agents only trust Wazuh's official certificate, so our own packages
  would be refused.

### 3. Release registry (super admin)
- Table of releases: version, OS packages + sha1, notes, status (draft /
  published / withdrawn), *required* flag, publish date.
- Super-admin page: upload or build, publish, withdraw, notes.
- Fleet view: agent count per version, per tenant.
- Publishing writes the repository layout (`versions` files + `.wpk`).

### 4. Tenant update features
- Agents page banner: "Agent vX.Y.Z available — N of M agents outdated", with
  the release notes.
- **Update all** / **Update selected** (one upgrade request, many agents).
- Auto-update toggle per tenant with a maintenance window (e.g. 01:00–05:00);
  a scheduler starts the upgrades in that window.
- Progress view per agent (In queue / Updating / Updated / Error + reason),
  **Retry failed**.

### 5. Permission changes
- Remove **Custom WPK** (`file_path`) from tenant admins; super admin only.
- Tenant admins can only upgrade to a **published** release (no free version
  or repository fields).
- Analysts: read-only version and status.

## Open decisions

1. **Auto-update:** offer auto-update with a maintenance window, or only the
   *Update all* button?
2. **Required releases:** may the super admin force a *required* (security)
   release on all tenants, or does each tenant always decide?

## Known limits

- The Linux deploy script still installs the old `siem-agent-linux`. Linux
  agents can use releases only after the switch to the ported Wazuh Linux
  agent (`siem-agentd`).
- On Windows, a non-elevated agent cannot unpack the package (the temp files
  only allow Administrators/SYSTEM, as in Wazuh). Installed agents run as
  SYSTEM, so this only affects test setups.
