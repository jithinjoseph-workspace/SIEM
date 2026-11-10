# provigil-agent: labels, event buffer limits, several managers

Written 2026-11-03 from a study of how the old agent does these. Describes what the new code
must do. Contains no code. Written from this description only; no old agent code is opened.

## 1. Labels

- Config (`provigil-agent.json`): `labels`: list of `{ "key": <text>, "value": <text>, "hidden": <bool, default false> }` (serde default: none).
- Every keepalive body carries `"labels": [ {key, value, hidden}, ... ]` plus `"agent_ip"`: the
  IPv4 address the agent uses to reach the manager (the local address of a connection to the
  manager; `null` when unknown). Keepalive bodies keep their existing fields.
- The manager stores them (the agent does nothing else with them).

## 2. Event buffer limits

Config (`provigil-agent.json`), object `buffer` (serde default):
`{ "disabled": false, "queue_size": 5000, "events_per_second": 500 }` (`queue_size` 1–100000,
`events_per_second` 1–1000; values outside are clamped with a warning).

- The buffer holds at most `queue_size` events. When it is full, a new event is dropped (counted;
  the count is logged once a minute while it keeps happening).
- Sending is paced: at most `events_per_second` events per second leave the agent (batches are
  sized and spaced so the average stays under the limit).
- `disabled: true`: no pacing and no `queue_size` limit (the existing in-memory limit stays as a
  safety net).
- States, checked whenever an event is added and whenever events are sent:
  - usage reaches 90 % → warning log `Agent buffer at 90 %.` and one event
    `wazuh: Agent buffer: '90%'.`
  - full → warning `Agent buffer is full: Events may be lost.` and event `wazuh: Agent buffer: 'full'.`
  - still full 15 seconds after it became full → warning
    `Agent buffer is flooded: Producing too many events.` and event `wazuh: Agent buffer: 'flooded'.`
  - after any of those, usage back at or under 70 % → info
    `Agent buffer is under 70 %. Working properly again.` and event `wazuh: Agent buffer: 'normal'.`
  Each state event is sent once per transition, never repeated while the state lasts. The event
  texts are exact (the manager's rules match them).
- A state event is a log event: `{"event_type":"logfile","timestamp":..,"agent":{..},"location":"wazuh-agent","message":<text>}`.
  It is put in front of the queue and is not counted against `queue_size` (it must get out even
  when the buffer is full).

## 3. Several managers (failover)

Config: `manager_urls`: list (serde default: empty). The effective list is `manager_urls` when
not empty, else `[manager_url]`. Also `max_retries` (default 5) and `retry_interval_secs`
(default 10).

- The agent works with one manager at a time (the first at start).
- A request to the manager (keepalive, event batch, YARA rules, result report) that fails to
  connect or gets a server error (5xx) counts as a failure; a success resets the count.
- After `max_retries` consecutive failures, wait `retry_interval_secs`, then switch to the next
  manager in the list: info log `Trying next manager in the line: '<url>'.`; after the last one,
  start again at the first with warning `Unable to connect to any manager.`
- Enrollment (when there is no identity yet) tries each manager in the list in turn.
- Requests in flight keep their manager; the switch applies to the next request. Events that
  failed stay in the buffer and go to the new manager.
- Log the manager in use at start and at every switch.

## Tests

- Labels serialised in the keepalive body, hidden flag kept; `agent_ip` present.
- Buffer: queue_size limit drops new events and counts them; state events for 90 %, full,
  flooded (with a short tolerance in the test), normal, each once per transition, exact texts,
  placed in front; pacing (100 events at 50 eps take about 2 s).
- Failover: with three fake URLs, five failures switch to the second, a success resets the count,
  after the third it wraps to the first with the warning.

Then `cargo test -p provigil-agent`, clippy clean on the files changed (`--no-deps`), build.
