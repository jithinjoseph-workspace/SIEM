# Manager scaling plan (for later)

Status 2026-10-16: **not started; not needed yet.** After the speed fix one manager on a
desktop PC takes 5,000 agents at 5,000 events/s and 10,000 connected agents with no event
lost (see `LOAD_TEST_RESULTS.md`). This page records the three ways to grow beyond that,
in the order they should be done.

| When | What | Effort | Gain |
|---|---|---|---|
| One manager gets close to ~5,000 events/s | 1. Multi-threaded analysisd | ~1 day | ~1.5–2x per manager |
| More tenants than one manager can hold | 2. Several managers, tenants assigned to them | ~1–2 weeks | Practically unlimited (add managers) |
| One tenant alone is bigger than one manager | 3. Port the Wazuh cluster (master + workers) | ~4–6 weeks | One tenant spread over many managers |

How to tell which is needed: watch per manager the remoted state file (`queue_size`,
`discarded_count`) and the analysisd state file (`events_dropped`, queue usage) and the
CPU of `wazuh-analysisd`. Rising queues or a busy analysisd core = time for step 1;
then step 2.

---

## 1. Multi-threaded analysisd

Today analysisd (`crates/siem-analysisd`) does decoding, rule matching and output on one
thread. C Wazuh uses thread pools (`analysisd.event_threads`, `winevt_threads`,
`rule_matching_threads`, ... ; 0 = one per CPU).

**Design (keeps output byte-identical to C):** process each batch of queued messages in two stages.
- **Stage A, parallel:** `clean_msg` + decoding of each message on N threads (generic
  decoders and the eventchannel decoder; other internal decoders stay serial). Each thread
  owns a copy of the decoder set (`Decoders` is `Clone`) and its own `decoder_match` buffer;
  `g_rules_hash` is shared read-only. Decoding is ~45% of the cost of a Windows event.
- **Stage B, one thread, original order:** state counters, rule matching (stateful:
  frequency/timeframe, `if_matched_sid`, firedtimes, ignore), accumulator, alerts, archives,
  active responses — exactly as today.

**Details that must be carried from stage A to stage B:**
1. Plugin decoders change `decoders.infos[ev.decoder].type_` while decoding (sonicwall,
   ossec-alert; the value depends only on the event). Record it per event in stage A and set
   it on the main decoder set in stage B before rule matching (the category check reads it).
2. The eventchannel decoder's `first_time` counter decides WARNING (first) vs DEBUG2 (later)
   for "Could not read XML string". Capture the message in stage A, decide the level in stage B.
3. Log messages from decoding are captured per event and replayed in order in stage B.
4. `reload_ruleset` replaces the engine: refresh the per-thread decoder copies (generation counter).
5. Small batches (the oracle feeds one message at a time) can use the parallel path through a
   test switch so the C comparison covers it.

**Not included:** parallel rule matching (C does it with locks; much harder to keep identical).

**Verification:** all existing C oracles with the parallel path forced on (ruleset 1,770 cases,
logtest, analysisd daemon 13 outputs), plus a 50,000-event run single- vs multi-threaded with a
pinned clock giving byte-identical alerts/archives. Then the load test (`tools/loadgen`).
Benchmark/profiler: `cargo run --release -p siem-analysisd --example bench_events`.

Optional extra found while profiling: `decode_event` clones the decoder node lists
(`decs.pn` / `decs.nopn`) for every event; borrowing them instead is a cheap single-thread win.

---

## 2. Several managers, tenants assigned to them (recommended way to scale out)

Tenants never share agents, so managers do not need to synchronize with each other. Each
manager is a full stack (remoted, analysisd, wazuh-db, modulesd); ClickHouse, Valkey, the
API and the UI stay shared.

**Scope:**
| Part | Work |
|---|---|
| Manager registry | Table of managers in ClickHouse: id, public address (agents), internal address (API), capacity, state |
| Tenant → manager | Assigned when the tenant is created (least loaded); super admin can move a tenant (agents re-enroll or get the new address through a pushed config) |
| Deploy wizard / enrollment | Install command and `ossec.conf` use the tenant's manager address; enrollment goes to that manager |
| siem-api | Today it starts and reads one local manager (`wazuh_manager.rs`). Split into: a small manager-side service per manager (tails alerts/archives into ClickHouse, applies keys/groups, runs agent actions) and the central API that routes per tenant |
| Agent actions, upgrades, groups, agent.conf | Routed to the tenant's manager |
| Super-admin UI | Managers page: list, load (agents, EPS, queues), add/drain a manager |
| Deployment | One container/VM per manager (Docker image), health checks, log/metric collection |

**Effort:** ~1–2 weeks. **Limit:** one tenant must fit on one manager.

---

## 3. Port the Wazuh cluster (master + workers)

Only if a single tenant outgrows one manager.

Wazuh 4.14.7 cluster = `wazuh-clusterd` (Python, `framework/wazuh/core/cluster/`, ~7,600 lines:
`master.py`, `worker.py`, `server.py`, `client.py`, `local_server.py`, `dapi/`, `cluster.json`).

**Scope:**
| Part | Work |
|---|---|
| Node roles and transport | Master/worker TCP connections, handshake, keep-alives, the cluster key (port of `server.py`/`client.py`/`common.py`) |
| Integrity sync master → workers | `client.keys`, `etc/shared/` groups and `agent.conf`, rules/decoders/lists (`cluster.json` file list) |
| Agent info sync workers → master | Agent status, groups, inventory (wazuh-db `sync-agent-info`, `sync-agent-groups`) |
| Group assignment | remoted already asks the cluster (`ClusterClient::assign_group`, stub `NoCluster` today) |
| Distributed API (`dapi`) | Requests forwarded to the node that holds the agent |
| Load balancer | Agents connect through it to any worker; reconnect on worker loss |
| Testing | Against a real Wazuh 4.14.7 cluster (oracle) + failover tests |

**Effort:** ~4–6 weeks. Already present: config reader `siem-config/src/cluster.rs`,
remoted cluster hooks, wazuh-db sync commands (ported in `siem-wdb`).
**Limit:** master sync load and storage eventually; Wazuh documents clusters with tens of
thousands of agents.
