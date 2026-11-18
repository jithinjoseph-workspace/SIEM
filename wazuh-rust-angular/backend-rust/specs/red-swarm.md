# Red Swarm & Purple Team

Console: Analyst → Red Swarm & Purple Team. API: `/api/v1/redswarm/*` (status, catalog, campaigns,
run-once, history, gaps, heatmap, kill-switch).

## What it does

Red Swarm checks, all the time, whether ProVigil catches known attacks on the computers it watches.
A round takes one attack from the catalog and one computer of that attack's system (Windows or
Linux), and sends the attack's events to the analysis engine **as that computer's own**, through
the same queue, format and rules as its real events. Nothing runs on the computer.

The round is **Defended** when an alert of its own events carries one of the attack's ATT&CK ids,
a **Soft gap** when only a generic alert fired, a **Hard gap** when nothing fired. A gap gets a
drafted rule that waits for an analyst's approval (Apply / Reject / Roll back); an applied rule is
loaded by the analysis engine.

## Design decisions

| Decision | Reason |
|---|---|
| Rounds go through the real analysis engine, not a separate built-in engine | A Defended result must mean the rules that check the PCs' real events catch the attack. |
| Samples are in the agents' exact formats: a Windows agent's event payload (`{"Message":..,"Event":"<Event>"}`), a Linux agent's log line | The engine decodes them as it decodes real events; a description of an event proves nothing. |
| Each round's events carry the location `redswarm/<round id>/<technique>`; only rounds this server started (15 minutes) count | The verdict reads only the round's own alerts (a real attack at the same time is not the round's detection), and an agent cannot hide its own events by naming them so. |
| A round's alerts are shown live and to the verifier only: never stored, scored, grouped into cases, mailed or answered with an active response; its events are not archived as the computer's | A simulation must not change anything about the real computer. |
| Live modes (running attack commands on computers) stay off | There is no safe channel to run attack commands on endpoints. |
| The built-in campaign runs every 15 minutes (was every minute) | 15 attacks: the whole catalog about every 4 hours, without filling the live feed. |
| The verifier waits up to 10 seconds and keeps looking until Defended | The engine's alerts come back through the alert stream; a generic alert can come before the precise one. |

## Catalog (siem-redswarm `catalog.rs`)

Windows: password guessing (4625), Security log cleared (1102), new local account (4720), member
added to Administrators (4732), new service (7045), encoded PowerShell (Sysmon 1), LSASS memory
read (Sysmon 10), Run key (Sysmon 13).

Linux: SSH password guessing, sudo to root, new account, account added to the sudo group, root's
crontab changed, unsigned kernel module, network card in sniffing mode.

`siem-api/src/redswarm_engine.rs` has a test that runs every sample through the real analysis
engine with the shipped ruleset and fails when an attack is not caught with its expected ATT&CK id.
