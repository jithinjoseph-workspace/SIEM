# ProVigil cluster: one control plane, N workers

Status: design (2026-11-09). Builds on `provigil-gateway.md` (phases 1-2 done).

## 1. Goal

Grow past one machine without a rewrite: add a worker, the fleet spreads; lose a worker, its
agents move on their own and nothing is lost; lose the console, agents keep sending.

Targets: 10,000 agents on one worker, 100,000 on 10 workers; a worker failure costs no events
and agents are back within 60 s; config changes reach every worker within 30 s.

## 2. Today (one machine)

```
agents -> provigil-gateway -> provigil-analysisd (engine) -> stream -> siem-api -> ClickHouse
                    \-> provigil-db (agent state, SQLite on this machine)   provigil-modulesd (scanner)
```

Already cluster-ready: gateways share agents (keys, registry, command queue, protocol marks in
ClickHouse); agents keep a list of managers and fail over; a server whose copy of an agent's SCA
or inventory does not match the agent's fingerprint asks the agent for one full send, so agent
state can be rebuilt from the agent at any time.

Single points today: one engine, one provigil-db, one siem-api, one ClickHouse.

## 3. Roles

**Control plane ("master")**: siem-api (console, API, Sigma, intent, risk, SOAR), auth-service,
the shared config store, ClickHouse, Valkey. Owns tenants, users, rules, policies, groups,
enrollment, the worker registry and agent placement. Runs no per-event work.

**Worker** (one package, many copies): provigil-gateway + provigil-analysisd + provigil-db +
provigil-modulesd. Owns a shard of agents: accepts their connections, decodes and matches their
events, keeps their state, scans their vulnerabilities, writes alerts and events straight to
ClickHouse. Workers are interchangeable: any worker's state can be rebuilt (section 6).

**Shared storage**: ClickHouse (events, alerts, registry, keys, commands, config versions),
Valkey (live fan-out of alerts to siem-api, leader locks).

```
                 load balancer (TCP 8089/8443, health checks)
                  /                 |                  \
          worker A              worker B            worker C        <- gateway+engine+db+scanner
             \                     |                   /
              ClickHouse (replicated)   Valkey   <-  control plane: siem-api x2, auth
```

## 4. Placement: which worker serves an agent

- Each agent has a home worker and a backup, chosen at enrollment by the control plane from the
  worker registry (least loaded among healthy workers, spread across racks/zones when known).
  Stored in the agent registry row (`home_worker`, `backup_worker`).
- The enrollment answer and every keepalive answer carry the agent's manager list: home first,
  backup second, the load balancer last. The agent already fails over along such a list.
- Any gateway still accepts any agent (keys are shared): an agent that reaches the wrong worker
  is served and told its home in the keepalive answer, so placement repairs itself.
- Adding a worker: new enrollments prefer it; a rebalance moves agents in batches by changing
  `home_worker` (the agent reconnects within one keepalive). Removing (drain): its agents get
  their backup as home, then it stops.

Why not hashing alone: explicit placement lets an operator drain, pin a tenant to its own
workers (data residency, large customers) and rebalance without moving everyone.

## 5. Event path per worker

- Gateway -> engine on the same worker (as today, local queue, backpressure 429/503).
- Engine -> worker's stream forwarder -> ClickHouse directly (batched, write-ahead spool on
  disk, acknowledged; today this hop goes through siem-api). Nothing waits on the control plane.
- Alerts also go to a Valkey stream that siem-api reads for live work (Sigma correlation,
  intent, risk, websocket). If siem-api is down, alerts are still stored; siem-api catches up
  from its last stream position.
- Correlation: rules that count or link events of one agent stay correct, because one agent's
  events always meet in one engine. Rules that link several agents (same source IP on many
  hosts) run centrally in siem-api over the alert stream, as Sigma and intent already do.

## 6. Agent state and worker failure

- provigil-db stays local to the worker (fast, no network per row). It is a cache of what the
  agent sent, not the only copy:
  - SCA results and inventory: on a new worker the fingerprints do not match, the worker asks
    the agent for a full send, the state refills (paths `sca_full`, `inventory_full`).
  - FIM baseline: the agent holds it; the worker asks for the state on first contact.
  - SCA copy, vulnerabilities, alerts, events: already in ClickHouse.
- So a dead worker loses nothing: its agents fail over to their backup, which refills their
  state from the agents, spread over the full-send splay.
- Commands: in ClickHouse; any worker hands them out once (`agent_command_queue`).

## 7. Configuration sync

- Rules, decoders, lists, SCA policies, agent group configuration, Sigma rules, YARA rules:
  stored in ClickHouse as versioned bundles (one version number per kind and tenant).
- Each worker polls the versions every 10 s, downloads what changed, checks the bundle hash,
  applies it (engine reload, gateway group-config cache) and reports the applied version in the
  worker registry. The console shows per worker: applied version, last sync, errors.
- A bad bundle (engine fails to load it) is rejected by the worker, which keeps the last good
  one and reports the error; it is never half applied.

## 8. Worker registry and health

- Table `cluster_workers`: id, address, zone, version, started, last heartbeat (every 5 s),
  capacity (configured), load (agents, events/s, engine queue %, inventory backlog), applied
  config versions, state (`active`, `draining`, `down`).
- A worker with no heartbeat for 20 s is `down`: placement skips it; its agents are already
  failing over on their own (they do not wait for the control plane).
- Load balancer health check: the gateway's `/health` (ready only when engine, provigil-db and
  ClickHouse answer).

## 9. Control plane availability

- Two or more siem-api behind the console's load balancer. In-memory state is a cache of
  ClickHouse/Valkey; jobs that must run once (agent monitor, retention, threat-intel refresh,
  scheduled reports, placement) take a Valkey lock with a lease and renew it; the other copy
  takes over when the lease ends.
- ClickHouse: 3 nodes with replication and ClickHouse Keeper; tables move to replicated engines.
- Valkey: primary + replica with automatic failover (or Sentinel).
- With the control plane fully down, workers keep accepting and storing events; only the
  console, enrollment and central correlation pause.

## 10. Security

- Cluster CA: each worker gets a certificate at join (a one-time join token from the console);
  worker <-> control plane and worker <-> ClickHouse/Valkey use mutual TLS.
- Per-worker ClickHouse user with only the rights it needs (insert events/alerts, read config).
- Agent CA unchanged: all workers present certificates from the install-wide agent CA, so an
  agent trusts any worker.

## 11. Operations

- Add worker: install package, join token, it registers, placement starts using it.
- Rolling upgrade: drain one worker, upgrade, back to active, next. Agents never all move at once.
- Console "Cluster" page: workers, load, health, config versions, drain/activate, rebalance.

## 12. Phases (each: spec detail -> build -> tests -> live test)

1. **C1 Worker package and registry**: stream forwarder writes straight to ClickHouse; Valkey
   alert stream to siem-api; `cluster_workers` heartbeats; console Cluster page (read only).
2. **C2 Placement and failover**: home/backup at enrollment, manager list in answers, self-repair
   on wrong worker, refill on a new worker; test: kill a worker under load, 0 lost.
3. **C3 Config sync**: versioned bundles, poll/apply/report, bad-bundle rejection.
4. **C4 Control plane HA**: two siem-api with leases; replicated ClickHouse; Valkey failover.
5. **C5 Operations**: drain, rebalance, rolling upgrade, join tokens, mTLS.
6. **C6 Scale proof**: 3 workers on separate machines, 10,000 agents at real event rates, then
   30,000; worker kill, siem-api kill, ClickHouse node kill.

## 13. Open questions for the owner

- Pilot size: does the pilot need more than one worker? (One worker on a dedicated server is
  expected to carry about 10,000 agents at 1-2 events/s each.)
- Tenant pinning: should a tenant be able to require its own workers?
- Cloud or on-premises first (decides the load balancer: cloud LB, HAProxy, or DNS).
