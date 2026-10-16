# Manager load test: simulated Windows agents (2026-10-16)

**Short answer:** one manager holds **10,000 connected agents** without trouble.
But today it processes only about **2,000 Windows events per second in total**, and
above that it **loses events**. 10,000 real Windows agents average roughly
0.5–5 events/s each (5,000–50,000 EPS), so before a cloud rollout at that size the
event pipeline must get faster (see "What to fix", item 1).

## How it was tested

- `backend-rust/tools/loadgen` (new) simulates Windows agents with the port's own
  `siem-crypto`. Each fake agent:
  - connects to remoted on TCP 1514 with AES encryption and sender counters, like a real agent;
  - sends the startup handshake and a keepalive every 10 s;
  - sends Application event-log events in the agent's real format (`{"Message","Event": XML}` on queue `f`).
- 1 in 20 events is an error event, which raises alert 60602 (level 9). The rest are
  informational events that create no alert, as on a real host.
- Agents were enrolled through the real API (`POST /api/v1/agents/enroll`) in a separate
  `loadtest` tenant (database `ndr_loadtest`), then deleted afterwards.
- Everything ran on this one dev PC (Windows 11, manager daemons + ClickHouse in Docker +
  the load tool). A cloud server will be faster; what matters here is *which* part breaks first.
- `monitor.ps1` sampled every 10 s: CPU and memory per process, remoted/analysisd state
  files (queues, dropped events), and ClickHouse row counts.

## Results

| Agents | Events/s sent | Delivered to ClickHouse | Result |
|---|---|---|---|
| 100 | 100 | 100% | OK |
| 1,000 | 1,000 | 100% | OK. remoted ~20% of one core, analysisd ~40%, nothing dropped |
| 5,000 | 5,000 | ~35% | **Overloaded.** remoted's queue (131,072) filled after ~60 s; 59% of events discarded |
| 10,000 | 1,000 (+1,000 keepalives/s) | ~45% | All 10,000 TCP connections fine; remoted's queue filled after ~150 s |
| 4,000 | 2,000 | 99% | OK, with `analysisd.label_cache_maxage=60` (see item 2) |
| 10,000 | 2,000 | ~35% | Overloaded even with the 60 s label cache |

Other numbers:
- **Enrollment:** about 43 agents/s at the start, 30/s at 10,000 agents (p50 latency
  375 → 565 ms). Each enrollment rewrites the whole `client.keys` file.
- **Memory:** siem-api stayed at 350–700 MB (the in-memory windows are capped at
  50,000 alerts and 50,000 events). remoted grew to ~190 MB with 10,000 connections.

## Bugs found and fixed during the test

1. **Two agents enrolling at the same moment got the same agent id** (6 of 100 in the
   first test). The second key replaced the first, so one machine would silently stop
   reporting (for example during a GPO rollout).
   - Fix: `next_free_agent_id` reserves the id with one atomic `fetch_add`
     (`crates/siem-api/src/main.rs`).
   - Checked: 10,000 concurrent enrollments, 10,000 unique ids.
2. **After analysisd restarted, all agent events were lost (Windows manager build)**
   until remoted was also restarted.
   - Cause: on Windows the "Unix socket" is a loopback UDP port. analysisd took a new
     random port on restart, and siem-api's supervisor deleted the port file. A UDP
     send to a closed port does not fail, so remoted kept "delivering" into nothing.
   - Fix: the receiver re-binds its previous port (`crates/siem-ipc/src/local.rs`,
     with a test). The supervisor keeps the port file and waits for it to be rewritten
     (`crates/siem-api/src/wazuh_manager.rs`).
   - Checked: port kept across restarts; events flow right after an analysisd restart.
   - Linux is not affected (real Unix sockets).

## Why it slows down (bottlenecks, most important first)

1. **analysisd runs on one thread.** The port does input, decoding, rule matching and
   output on a single thread (`siem-analysisd/src/daemon.rs`, main loop). C Wazuh runs
   these as thread pools (`event_threads`, `winevt_threads`, `rule_matching_threads`,
   one per CPU by default).
   - Measured: fed directly with Windows events, analysisd tops out at **~2,100 events/s**
     with that thread at 92% of a core (about 450 µs per Windows event). Other cores stay idle.
2. **Blocking wazuh-db lookups on that thread.** For each event analysisd looks up the
   agent's labels. The cache keeps them `analysisd.label_cache_maxage` seconds (default 10).
   With thousands of agents most lookups miss, and each miss is a synchronous wazuh-db
   query (~0.5 ms) on the only thread. Throughput then stays near 2,000/s **while all CPUs are mostly idle**.
   - Measured: raising the setting to 60 (its maximum) took 4,000 agents × 0.5 EPS from
     "queue full, events discarded" to 99% delivered.
3. **remoted with 10,000 agents.** Even with the 60 s cache, 10,000 agents at only
   2,000 EPS filled remoted's queue while remoted and analysisd used little CPU. Some
   per-message wait remains (keepalive handling or per-agent lookups). This needs a profiler run.
4. **Windows overload is silent.** When analysisd falls behind on the Windows build,
   datagrams overflow the UDP buffer and no counter shows it ("dropped 0"). Linux
   blocks the sender instead, and remoted counts the discards.

## What to fix (recommended order)

1. **Run analysisd's stages on several threads, as C does** (decoders, winevt decoder,
   rule matching, output writers). This is the main capacity limit. Expected gain: roughly
   one core's worth (~2,000 Windows EPS on this PC) per extra core.
2. **Stop blocking on wazuh-db per event:** make the label lookup non-blocking or
   preload the labels, and set `analysisd.label_cache_maxage=60` in the shipped
   `local_internal_options.conf` meanwhile. This is a one-line config win.
3. **Profile remoted with 10,000 agents** (control-message path, per-agent lookups) and fix what shows up.
4. **Re-run this test on Linux** (the cloud OS), also against the C Wazuh 4.14.7 manager
   as a baseline, to get production numbers per vCPU.
5. Enrollment: avoid rewriting all of `client.keys` per enrollment (append, or batch the
   writes). It is 30/s at 10,000 agents, fine for now.

## Cloud sizing until then

With today's code, plan on **one manager per ~1,500–2,000 EPS**. That is about
1,000–2,000 Windows agents at typical rates. siem-api, ClickHouse and wazuh-db were never the
limit in these tests (ClickHouse stayed under ~1 core and 2.2 GB).

## How to rerun

```
cd backend-rust/tools/loadgen
cargo build --release
# tenant DB once: CREATE DATABASE ndr_loadtest + CREATE TABLE ndr_loadtest.<t> AS ndr.<t> (TENANT_TABLES)
node enroll.cjs 1000 keys.txt            # enrolls lt-00000.. in tenant "loadtest" (append more with: node enroll.cjs N keys.txt 16 <start>)
powershell -File monitor.ps1 -out mon.csv -secs 200    # in a second terminal
target/release/loadgen keys.txt 127.0.0.1:1514 1000 1 30 180 ../../data/manager/etc/shared/default/merged.mg
python show.py mon.csv
node blast_analysisd.cjs <agent id> <name> 2000,4000 20   # analysisd alone, bypassing remoted
node enroll.cjs delete                   # removes all loadtest agents
```
loadgen arguments: keys file, manager address, agents, events/s per agent, ramp seconds, duration seconds, merged.mg path.
