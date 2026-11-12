# Predictive Security Posture (per tenant)

Status: plan (2026-11-11). Owner asked for a real, data-driven version: a posture score for
yesterday, today and a forecast for tomorrow, with history, honest confidence and the reasons.

## 1. What the customer sees

- **Three cards**: Yesterday (actual, and what we had forecast for it), Today (live, updated
  hourly), Tomorrow (forecast with a confidence range, e.g. 62–72).
- **Score**: 0–100, **100 = strongest posture**. Bands: 80+ Good, 60–79 Fair, 40–59 At Risk,
  below 40 Critical.
- **Why**: the top drivers in plain words with links, e.g. "−8: 12 critical alerts on
  win-node-e296 (rule 92213, Mimikatz)", "−5: 3 known-exploited CVEs unpatched on 2 hosts",
  "+4: SCA pass rate up from 27 % to 33 %".
- **Trend chart**: actual score per day, the forecast that was made for each day, and the band.
- **Forecast accuracy**: average error of past forecasts ("forecasts were within ±4 on 9 of the
  last 10 days"); shown so the number is trusted, not just pretty.
- **Weakest hosts**: the same score per agent, lowest first.
- **Reports**: one per day (score, drivers, forecast, AI summary), kept as history; "Create case"
  from a report.

## 2. Inputs (all already stored in the tenant's ClickHouse database)

| Component (weight) | Source | Measure |
|---|---|---|
| Threat activity (30 %) | `siem_alerts` | severity-weighted alerts of the last 24 h per active agent, against the tenant's own baseline (same weekday, previous days); critical (level 12+) counts most; one noisy rule on one host is capped so it cannot dominate |
| Vulnerability exposure (25 %) | `siem_vulnerability_state` + threat intel (CISA KEV) | open CVEs weighted by CVSS; known-exploited (KEV) weighted highest; age of the oldest critical |
| Configuration hardening (20 %) | `siem_sca_checks` | SCA pass rate across agents, weighted by check severity |
| Attack progression (15 %) | `siem_intent_dossiers`, `siem_threat_predictions` | highest intent probability and kill-chain progress; predicted next stages |
| Coverage and hygiene (10 %) | agent registry, `siem_tamper`, `soar_cases` | share of agents active, tamper lock, outdated agent versions, open critical cases older than 24 h |

Weights are a setting per tenant; the defaults above.

## 3. Data quality (what makes it real)

- **Only real agents**: deleted agents and load-test agents (registry rows marked deleted,
  `lt-*` names) are excluded; alerts from removed agents do not count.
- **Gaps**: days with no data (manager off) are marked "no data", never scored as perfect;
  the forecast skips them instead of reading them as zero.
- **Spikes**: robust statistics (median and median absolute deviation, values beyond 5 MAD
  capped) so a load test or a single flood day does not distort the baseline.
- **Minimum history**: under 3 days the forecast is shown as "learning" with a wide band;
  day-of-week seasonality is used only after 14 days.
- **Per-tenant isolation**: every query is on the tenant's own database.

## 4. Forecast for tomorrow

- Forecast **each component**, then combine with the weights:
  - Threat activity: exponential smoothing with trend (Holt) on the daily severity-weighted
    alert rate; Holt-Winters with weekly season after 14 days; plus the threat predictions'
    next-stage probability as an expected increase.
  - Vulnerabilities: today's open set, plus the recent daily rate of new CVEs, minus the recent
    patch rate.
  - SCA and hygiene: carry today's value (they change only when configuration changes).
  - Attack progression: intent velocity (accelerating / steady) moves it up or down.
- **Confidence range**: from backtesting, i.e. the spread of past forecast errors (forecast made
  each day for the next, compared with what happened). Wider when history is short.
- **Accuracy record**: every forecast is stored and compared with the actual next day;
  the page shows the average error.

## 5. Schedule and storage

- Every hour: compute Today (live) per tenant.
- After midnight (tenant's time zone): finalize yesterday's score, compute tomorrow's forecast,
  write the daily report.
- ClickHouse, tenant database: `siem_posture_daily` (day, score, components, drivers, forecast for
  the next day, range, model, data quality notes) and `siem_posture_hourly` (today's live points,
  kept 7 days). No files.
- AI summary per report through the platform AI providers, only when the tenant has AI on;
  otherwise a written summary from the drivers. Within the existing AI budget settings.

## 6. API and page

- `GET /api/v1/posture` (the three cards), `GET /api/v1/posture/history?days=30`,
  `GET /api/v1/posture/report/:day`, `GET /api/v1/posture/agents` (weakest hosts),
  `POST /api/v1/posture/run` (tenant admin: recompute now).
- Page `/analyst/posture`: our own design (cards with weather-style icons, trend chart with the
  band, drivers, weakest hosts, reports, Create case). Permission: the existing SIEM analyst
  permissions.

## 7. Tests and proof

- Unit tests: each component's score from fixed data; robust statistics on spike and gap data;
  the forecast on synthetic series with a known trend and weekly season.
- Backtest on the tenant's real history; report the error in the run log.
- API tests; a smoke-test check that the page's API answers and today's score is present.
- Live check on the running system: today's score and its drivers match what the alerts,
  vulnerabilities and SCA pages show.

## 8. Order of work

1. Scores and data quality (components, real-agent filter, robust baseline) + tests.
2. Daily and hourly storage + scheduler.
3. Forecast + backtest + accuracy record + tests.
4. API.
5. Page.
6. AI summary + Create case + per-agent view.
7. Live check, smoke test, documentation.
