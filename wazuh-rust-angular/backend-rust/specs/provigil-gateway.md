# provigil-gateway: the agent front door

Status: description for a clean-room rewrite (2026-11-05). No code is to be copied from
`siem-remoted` or translated from it. This file says **what** the old agent gateway did, what
siem-api's agent front door does today, and what the new gateway must do. The developer who
writes `provigil-gateway` reads this file, `provigil-proto`, `provigil-agent/src/transport.rs`
and the siem-api files named in part 2, and never opens `siem-remoted` or `old-code/`.

Sources read for this description (file names only, so it can be checked later):

- old gateway: `siem-remoted` `lib.rs`, `main.rs`, `server.rs`, `manager.rs`, `keystore.rs`
  (which re-exports `siem-crypto` `keystore.rs`), `forwarders.rs`, `mq.rs`, `router.rs`,
  `state.rs`, `agent_info.rs`, `request.rs`, `shared_download.rs`, `syslog.rs`, `wdb.rs`,
  `config.rs`; `siem-config` `remote.rs`; `docs/LOAD_TEST_RESULTS.md` (16 Oct).
- today's front door: siem-api `agent_grpc.rs`, `main.rs` (`ingest`, `ingest_unless`,
  `ingest_batch`, `agent_keepalive`, `agent_response_result`, `enroll_agent`,
  `resolve_agent_tenant`, `agent_bearer_ok`, `agent_key_ok`, `agent_yara_rules`, the live,
  upgrade, command and download handlers, the listener start), `tenancy.rs`
  (`refuse_plain_agents`, `is_agent_route`, `AgentKeys`), `http_agent_state.rs`,
  `provigil_manager.rs` (`send_agent_events`, the analysis-engine lag loop, `send_ar_queue`,
  `queue_http_command`, `push_http_command`, `take_http_commands`, `live_query`,
  `on_command_result`, `queue_http_upgrade`, the key service, the console actions),
  `agent_config.rs`, `persist.rs` (`save_commands`), `agent_keys_store.rs`, `db.rs`
  (agent rows, registry, tenant keys), `vulnerability.rs` (`request_rescan`),
  `syslog_tenancy.rs`; `provigil-proto` `lib.rs`; `provigil-agent` `transport.rs`, `edr.rs`,
  `upgrade.rs`, `lib.rs`; `provigil-loadtest` `main.rs`; `specs/AGENT-REVIEW-FIXES.md`
  parts F, G-b, H, I, M, N, O, P.

Names: "the engine" is the analysis engine (`siem-analysisd`); "provigil-db" is the manager's
agent database daemon (per-agent SQLite plus global.db); "the old gateway" is `siem-remoted`.

---

## 1. The old gateway's job, feature by feature (what, not how)

Each item has an id (R1...) used again in the table of part 4.

### 1.1 Connections and limits

- **R1 Listeners.** Reads one or more connection blocks from the manager configuration. A
  "secure" block listens for agents on a port (default 1514) over TCP, UDP or both, optionally
  on one local address and over IPv6. A "syslog" block listens for remote syslog (default 514).
  (`lib.rs` start, `siem-config` `remote.rs`)
- **R2 Fatal start errors.** No connection configured, a queue size below 1, or a port that
  cannot be bound stops the daemon with a critical message. A queue size above 262,144 only
  warns ("may run out of memory"). (`config.rs`, `main.rs`)
- **R3 TCP accept loop.** Each accepted connection gets no-delay, a connection number, a
  reader and a writer task; the open-session counter goes up and down with it. Accept errors
  are logged and accepting continues. (`server.rs`)
- **R4 Framed messages with a size limit.** A TCP stream carries length-prefixed messages; a
  message above the maximum message size (64 KiB) closes the connection with a warning.
  (`server.rs`)
- **R5 UDP.** Datagrams up to the maximum size are queued like TCP messages; replies go back
  to the sender's address. (`server.rs`)
- **R6 Bounded receive queue.** Every received message goes into one bounded queue (default
  131,072). When it is full the message is discarded, counted ("discarded"), and a single
  warning says the queue is full and events may be lost (once, not per message). (`server.rs`)
- **R7 Worker pool.** 1 to 16 workers take messages from the queue. Message-counter
  verification and more than one worker are refused together at start, because order cannot
  be guaranteed. (`server.rs`, `config.rs`)
- **R8 Per-connection send buffer.** Replies to one agent go through a per-connection buffer
  with a byte limit (64 KiB to 1 MiB). When full, the sender waits once (1-60 s, configurable)
  and then drops the packet, counted as "send discarded" for that agent, with a warning. A
  failed write closes the connection. (`server.rs`)
- **R9 Socket close bookkeeping.** On close it remembers the global message number at that
  moment (messages from that socket still in the queue are then ignored and counted as
  "dequeued after close"), removes the socket from the key table and lowers the session count.
  (`server.rs`)
- **R10 Tuning options with ranges.** About 30 internal options, each with a minimum and
  maximum: receive and send chunk, buffer relax, send buffer size, send retry wait, receive
  timeout, TCP keepalive idle/interval/count, worker pool, merge shared, pass empty key file,
  control queue size, key update interval, router forwarding off, state interval, open-file
  limit, sender pool, request pool, request and response timeouts, retransmission timeout
  (seconds and milliseconds), maximum attempts, guess agent group, shared reload interval,
  disk storage, message-id verification, receive counter flush, debug level. Several are
  read and reported but never used (TCP keepalive trio, receive timeout, open-file limit,
  send chunk, buffer relax, average printout). (`config.rs`)
- **R11 Command line.** Version, help, debug level (repeatable), test configuration and exit,
  foreground, configuration file, home directory, and "do not build merged files".
  Configuration warnings are printed at start. (`main.rs`)

### 1.2 Agent authentication and key reload

- **R12 Key source.** Agent keys come from the key file, or, when siem-api passes its key
  service address and token, from siem-api over loopback (30 tries, one per second, at start).
  siem-api keeps the keys encrypted in ClickHouse. (`siem-crypto` `keystore.rs`,
  `provigil_manager.rs` key service, `agent_keys_store.rs`)
- **R13 No keys.** An empty key set stops the daemon unless "pass empty key file" is set.
  (`siem-crypto` `keystore.rs`)
- **R14 Who is speaking.** A message names its agent by id (then the source address must be
  inside the network the key allows) or is matched by the exact source address of a key.
  (`server.rs`, `keystore.rs`)
- **R15 Unknown sender.** An unknown id or address is refused: warning, connection closed,
  "unknown" counter, and a key request (by id or by address) is queued for the enrollment
  daemon. (`server.rs`)
- **R16 Ping.** An unauthenticated ping gets a pong over the same transport, counted.
  (`server.rs`)
- **R17 Connection overtake.** One key, one live connection. A message on a new connection
  for a key that already has one is refused ("key already in use") unless the old connection
  was idle longer than the overtake time (default 60 s); then the old one is closed after the
  new message is handled. (`server.rs`)
- **R18 Empty message.** Refused, connection closed, counted unknown. (`server.rs`)
- **R19 Decryption and replay protection.** Each message is decrypted with the agent's key and
  its counters checked. Wrong key (also queues a key request), corrupt message and duplicated
  counter are each logged with their own message; the connection is closed and the message
  counted unknown. A decrypted payload above the maximum size is refused the same way.
  (`server.rs`)
- **R20 Receive counters on disk.** Each agent's last counters are written to files, flushed
  every N messages. (`lib.rs`, `server.rs`)
- **R21 Last-received time.** Every good message sets the agent's last-received time. It
  decides whether the agent counts as connected (within the disconnection time, default
  10-15 min): replies, requests and active responses to an agent not heard from within that
  time are refused ("sending to disconnected agent"). (`server.rs`, `forwarders.rs`)
- **R22 Key reload.** Every key-update interval it checks whether the key source changed (file
  stamp, or the key service's version). On a change it reloads, keeps each agent's network
  state (last received, connection, address) when its id and allowed address did not change,
  restarts the counters, and counts the reload. (`forwarders.rs`, `keystore.rs`)
- **R23 Key request link.** Connects to the enrollment daemon's request socket (4 tries a
  second apart, then every 300 s), keeps the request that failed to send and sends it again
  after reconnecting; marks the feature unavailable while down. (`forwarders.rs`)
- **R24 Sender counter.** The global sender counter is kept in a file that stays open and is
  rewritten in place on every sent message (the 16 Oct fix, see 1.8). (`lib.rs`, `server.rs`)

### 1.3 Per-agent state and keepalive tracking

- **R25 Session bookkeeping.** A control message records the agent's transport, address and
  current connection (and links the connection to the key) unless it is older than the last
  close of that connection; a shutdown is always taken. (`server.rs`)
- **R26 Startup.** The startup message carries the agent version. It is remembered. An agent
  newer than the manager is refused unless "allow higher versions" is on (default off): it gets
  an error answer and its row gets status code "invalid version" plus the version. A startup
  with no readable version gets "could not retrieve version" and its status code. A good
  startup sets the row to "pending" and marks the next keepalive as the first after start.
  (`manager.rs`, `config.rs`, `wdb.rs`)
- **R27 Shutdown.** Forgets the version, sends an "agent stopped" event (agent name and
  address) to the engine, sets the row to "disconnected" with the reason "shutdown received".
  No acknowledgement. (`manager.rs`)
- **R28 Keepalive cleaning.** Invalid UTF-8 replaced, the random tail after the last line
  removed; a keepalive without a line break is refused with a warning. (`manager.rs`)
- **R29 Acknowledgement.** Every startup and keepalive is acknowledged to the agent, counted.
  (`manager.rs`)
- **R30 Control queue.** Keepalives wait in a queue keyed by agent: a newer one replaces the
  waiting one (counted inserted / replaced / processed). When full, the keepalive is not
  queued (no counter, no log). One worker writes them to provigil-db. (`manager.rs`)
- **R31 Keepalive contents.** Parsed into: OS name, version, major, minor, build, codename,
  platform, architecture, the raw OS string (Windows and Unix forms, several distributions),
  agent version, configuration checksum, shared-bundle checksum, labels (plain, hidden, and
  the agent's own address label). (`agent_info.rs`)
- **R32 Labels added by the manager.** The manager's host name, the node name and the agent
  version are added to the stored labels (the agent's address label too, when sent). The
  engine puts labels on the agent's alerts. (`manager.rs`)
- **R33 Unchanged keepalive.** While a bundle push is pending and the keepalive did not
  change, only "last keepalive / active" is written. (`manager.rs`)
- **R34 Group lookup and assignment.** The agent's group comes from provigil-db; when it has
  none, from the bundle checksum it reports: optionally guessed by matching a known group's
  checksum, else "default", stored only if empty. A cluster worker asks the master instead.
  (`manager.rs`, `wdb.rs`)
- **R35 Group configuration status.** "synced" when the agent's bundle checksum equals the
  group's, else "not synced" and a bundle push is queued (once while one is pending).
  (`manager.rs`)
- **R36 Agent row write.** Each processed keepalive writes the agent's row (OS fields,
  version, checksums, labels, manager host, node, connection "active", sync status, group
  status). Sync status depends on master/worker role and on first-after-start or a changed
  bundle. (`manager.rs`, `agent_info.rs`, `wdb.rs`)
- **R37 Reset at start.** At start every agent's connection status is reset, so agents show
  disconnected until they speak again (warning when that fails). (`lib.rs`, `wdb.rs`)
- **R38 Per-agent statistics pruning.** Every state interval the per-agent counters are cut
  down to the agents active on this node. (`forwarders.rs`, `state.rs`)

### 1.4 Message routing to the engine queues

- **R39 Event hand-off.** A non-control message goes to the engine's input with a source
  label made of agent id, name and address (cut to 255 bytes), on the "secure message" queue;
  counted per agent. (`server.rs`, `mq.rs`)
- **R40 Engine link.** The link to the engine reconnects forever (once a second), logs the
  loss and the reconnection, and sends the message again once after reconnecting. A message
  that is not in queue form is logged as "not correctly formatted" and dropped. (`mq.rs`)
- **R41 Inventory forwarding.** Unless switched off, inventory deltas and inventory sync
  messages are also forwarded to the inventory and vulnerability providers with the agent's
  id, name, address (the source address when the key says "any") and version. File-integrity
  messages are never forwarded. Messages too large are skipped. (`router.rs`, `server.rs`)
- **R42 Remote syslog.** Only from allowed addresses (deny list first, an allow list is
  required, without it the syslog block is ignored with a notice). UDP: trailing NUL and line
  break removed, priority header removed. TCP: one task per client, split on line breaks,
  bounded buffer, priority header removed. Lines go to the engine's syslog queue with the
  source address. (`syslog.rs`)

### 1.5 Request/response to agents

- **R43 Local request socket.** A local socket accepts JSON commands:
  statistics (global), per-agent statistics (a list of fewer than 150 ids, or "all" paged from
  a last id, 150 per page, "more to come" signalled), configuration (sections remote, internal,
  global), and "assign group" (agent and checksum). Errors have numbered meanings: invalid
  JSON, empty command, unknown command, empty parameters, empty section, unknown section,
  invalid agents parameter, database error, empty last id, too many agents, invalid agent or
  checksum. (`request.rs`, `state.rs`, `config.rs`)
- **R44 Request relay.** Any other text on the socket is "agent id + payload": sent to the
  agent with a random request number. Limits: a request pool (waiting at most the request
  timeout for a place, else "internal error"); duplicated number refused; over UDP the request
  is resent up to the maximum attempts until acknowledged; then it waits for the answer up to
  the response timeout. Errors returned to the caller: cannot send, maximum attempts exceeded,
  response timeout, internal error. Over UDP the final answer is acknowledged to the agent.
  (`request.rs`)
- **R45 Answer routing.** An agent's answer is matched to its waiting request by number; an
  unknown number is logged as a possible duplicate. (`request.rs`)

### 1.6 Shared and configuration file distribution

- **R46 Group bundles.** At start and every shared-reload interval it scans the group folders:
  per file modification times; one bundle per group made of a group header, the active-response
  definitions and every file except hidden ones and earlier bundles; binary files are refused
  ("invalid shared file", remembered until modified, then re-checked); paths over 200
  characters skipped (warned once); the bundle's checksum; written only when it changed (atomic
  replace when "disk storage" is on). (`manager.rs`)
- **R47 Multi-group bundles.** Agents in several groups get a combined bundle, named by a
  short hash of the group list, rebuilt when a member group changes or the bundle was edited
  from outside (warning), removed when no agent uses it; unknown folders cleaned at start.
  (`manager.rs`)
- **R48 No bundles on a worker.** A cluster worker or the "no merged" flag stops bundle
  creation. (`config.rs`)
- **R49 Remote group files.** A YAML file can list, per group, file URLs and a poll interval
  (default 1800 s): the files (or a whole bundle, checked before use, deleted when corrupt) are
  downloaded on that schedule; the YAML is reloaded when it changes; missing group folders are
  created. (`shared_download.rs`)
- **R50 Bundle push.** A sender pool sends a bundle to agents whose checksum differs: a header
  with checksum and name, the content in small pieces, a close marker; over UDP it pauses a
  second every 30 pieces; each piece counted; failures warned. (`manager.rs`)

### 1.7 Active-response delivery, counters and state

- **R51 Active responses from the engine.** Reads the engine's active-response queue. Each
  request says: all agents, the agent of the event, or one named agent, and whether the
  payload is a response command or a raw control message. "All agents" means every agent heard
  from within the disconnection time. Too-long messages are cut. Invalid requests are logged.
  Each delivery counted per agent. (`forwarders.rs`)
- **R52 Configuration-assessment dumps.** Reads the engine's assessment-request queue and sends
  each "dump this policy" request to the named agent, counted. (`forwarders.rs`)
- **R53 Sending.** Every reply is encrypted for the agent and sent over its current
  transport; "agent not found" and "disconnected agent" refuse it. (`server.rs`)
- **R54 Counters.** Global: uptime, open TCP sessions, bytes received and sent, key reloads,
  messages received (events, control with keepalive / startup / shutdown / request breakdown,
  ping, unknown, dequeued after close, discarded), messages sent (acknowledgements, shared
  bundle pieces, active responses, assessment requests, requests, discarded), receive-queue
  size and usage, control-queue usage and inserted / replaced / processed. Per agent: uptime,
  events, control messages with the same breakdown, and the same sent breakdown. (`state.rs`)
- **R55 State file.** Every state interval (0 disables it) the counters are written to a state
  file (temporary file then rename) with an "updated every ..." line. (`forwarders.rs`,
  `state.rs`)
- **R56 Clock.** A once-a-second cached clock is used on the hot path. (`forwarders.rs`)

### 1.8 The 16 Oct scaling fixes and why (`docs/LOAD_TEST_RESULTS.md`)

Before: 5,000 agents at 1 EPS lost 59 %; 10,000 agents at 0.5 EPS lost 77 %. After: 5,000
agents at 5,000 EPS and 10,000 agents at about 4,000 EPS (plus 1,000 keepalives/s), every sent
event reached ClickHouse, 0 discarded, 0 dropped. The 10,000-agent run was limited by the load
generator on the same PC, not the manager.

- **F1 (the gateway's own fix).** The sender counter file was opened, written and closed for
  every sent message (every keepalive acknowledgement) while holding locks the workers share:
  about 4 ms per keepalive on Windows, so workers queued and the receive queue overflowed.
  Fixed by keeping the file open and rewriting in place: keepalive handling went from ~4.3 ms
  to microseconds. **Lesson for the new gateway: no disk write and no shared lock per message
  on the keepalive or event path.** (R24, rule G-R1 in part 3)
- **F2 (engine).** The engine waited on provigil-db for agent labels whenever its cache entry
  was older than 10 s, i.e. on almost every event with thousands of agents. Now a stale entry
  is served while a background task refreshes it.
- **F3 (engine).** Hot spots in XML parsing and rule matching removed (Windows events
  9,974 → 22,428/s on one core).
- **F4 (engine).** The "2,100 events/s ceiling" was a backlog from the previous run.
- **F5 (enrollment, siem-api).** Two simultaneous enrollments could get the same id; fixed by
  reserving ids with one atomic step (10,000 concurrent enrollments, 10,000 unique ids).
- **F6 (engine restart on Windows).** After an engine restart all events were lost until the
  gateway restarted too: on Windows the engine's local socket is a loopback UDP port, the engine
  took a new port and a UDP send to a closed port does not fail. Fixed: the engine re-binds its
  previous port and the supervisor keeps the port file.
- **Known limits then:** the engine on one thread; on Windows an overloaded engine loses
  datagrams silently (UDP buffer, "dropped 0"); enrollment rewrote the whole key set per
  enrollment (about 30/s at 10,000 agents).

### 1.9 Overload and engine restart

- **Overload:** receive queue full → messages discarded and counted, one warning (R6); send
  buffer full → one wait, then dropped and counted (R8); control queue full → keepalive not
  processed, nothing counted (R30); engine slow → the engine link blocks the workers, the
  receive queue fills, then R6. Nothing is pushed back to the agent: the agent is not told to
  slow down, the message is simply gone. On Windows an overloaded engine also loses datagrams
  with no counter at all (1.8).
- **Engine restart:** the link reconnects every second and sends the current message once
  more; messages that were in the engine's socket buffer are lost; on Windows, before F6,
  everything was lost until the gateway restarted.

---

## 2. What siem-api's agent front door does today (the list the gateway keeps exactly)

Each item has an id (S1...) used again in part 4. Unless a reason in part 4 says otherwise,
the gateway behaves exactly as described here, including status codes and answer shapes,
because `provigil-agent` `transport.rs` depends on them.

### 2.1 Listeners and TLS (`agent_grpc.rs`, `main.rs`, `tenancy.rs`)

- **S1 gRPC listener**, TLS only, port `SIEM_GRPC_PORT` (default 8089), service
  `provigil.agent.v1.AgentService` with calls Enroll, Keepalive, Events, Result, Config, Yara,
  Upgrade (server stream). `SIEM_GRPC_TLS_CERT` / `SIEM_GRPC_TLS_KEY` replace the certificate.
  Messages up to 16 MiB in both directions. HTTP/2 keepalive ping 60 s, TCP keepalive 60 s,
  at most 8 concurrent calls per connection, 14 s per call (under the agent's 15 s).
- **S2 HTTPS listener**, port `SIEM_TLS_PORT` (default 8443), serving siem-api's whole router
  (agent routes and console routes) over TLS, ALPN h2 and http/1.1, TLS handshake limited to
  10 s (warning on failure or timeout), accept errors logged with a 100 ms pause.
- **S3 Long accept queue** on both agent listeners (65,535; on Windows the "as asked" hint, since
  the default is cut to 200), address reuse on Unix. Tested with a 3,000-connection burst.
- **S4 Plain port 8088 refuses agents**: the agent routes (ingest in its three spellings,
  command ack, enroll, agent state, command fetch by query or path, keepalive, response result,
  YARA rules, group config but not the console's live config) answer **426** with "Agents
  connect over TLS: use the HTTPS or gRPC address of /api/server-info" when the socket peer is
  not loopback, unless `SIEM_AGENT_PLAIN=1`. Loopback stays allowed (tests, load tool, dev
  proxy). The peer is the socket's, not a header.
- **S5 Install-wide CA** in `data/tls/`, made at first start; its key file readable only by
  the service account and Administrators (Windows ACL) or mode 600 (Unix); a key that exists
  but cannot be read is an error, never replaced by a new CA. Not the syslog CA (that needs
  ClickHouse and the secret; agents must connect without them).
- **S6 Server certificate** issued from that CA at every start for: `SIEM_LAN_IP`,
  `MANAGER_IP`, `SITE_DOMAIN` (comma lists), the host name, every local IPv4 address,
  `localhost`, `127.0.0.1` (sorted, no repeats). The key stays in memory. No certificate →
  the agent listeners stay down (never plain). Renewed only at start (a known shortcut).
- **S7 `/api/server-info`** (public): LAN address, console port and URL, `https_url`,
  `grpc_url` (grpcs), `ca_pem`, `agent_files` (published file → SHA-256, re-hashed only when the
  file time changes), `agent_version` (the published agent's version). Never the private key.

### 2.2 Authentication and tenant rules (`main.rs`, `tenancy.rs`, `agent_grpc.rs`)

- **S8 Agent key.** The agent sends its own key as `Authorization: Bearer` and, on gRPC and on
  the per-agent HTTPS paths, its id (`x-agent-id` or the path). Compared in constant time
  against the keystore. Every call except Enroll requires it (gRPC answers UNAUTHENTICATED).
- **S9 Legacy key header.** The Linux prototype agent sends `X-Agent-Key` instead; accepted
  wherever the bearer is.
- **S10 Tenant key.** `X-Tenant-Key` maps to a tenant (constant-time search). An unknown tenant
  key → 401; an inactive tenant → 403; an agent bound to one tenant presenting another tenant's
  key → 409. Without a tenant key the agent keeps its tenant (new ones go to `default`). A tenant
  id sent by the agent in the body is never trusted.
- **S11 Removed and deactivated agents.** Removed → 404, deactivated → 410, on every agent call.
  The agent enrolls again after 3 refusals in a row of 401/404/410 (`transport.rs`).
- **S12 Unenrolled agent ids.** An agent id with no key is accepted with no key check and is
  bound on first sight to the tenant of the tenant key (or `default`); a registry row is
  written and the id counter raised so the id is never issued again.
- **S13 Status mapping (gRPC).** 400 → INVALID_ARGUMENT, 401 → UNAUTHENTICATED, 403 and 410 →
  PERMISSION_DENIED, 404 → NOT_FOUND, 409 → ALREADY_EXISTS, 429 → RESOURCE_EXHAUSTED, others →
  INTERNAL. The agent maps them back (UNAVAILABLE / UNKNOWN / CANCELLED = network down;
  DEADLINE_EXCEEDED = 408; FAILED_PRECONDITION = 412).

### 2.3 Enrollment (`main.rs` `enroll_agent`, `agent_grpc.rs`)

- **S14 Enroll** on gRPC and on `POST /api/v1/agents/enroll` (HTTPS): tenant from the tenant
  key, else the signed-in console user's tenant, else `default`. Name rules: 2-128 characters of
  letters, digits, dot, underscore, hyphen (400). A removed name in that tenant is refused (403)
  unless `force`. Groups must exist (manager group names carry the tenant; unknown → 400).
  The same name in the same tenant gets the same id and a new key ("re-enrolled"); a new agent
  gets the next id from one atomic counter (ids never reused). The registry row is written to
  ClickHouse **before** the key is returned. The keystore changes, the key version goes up
  (the key service and the ClickHouse copy follow), the agent row is registered in provigil-db,
  the per-agent caches of `http_agent_state.rs` are forgotten. An enrollment cut short (call
  time limit, client gone) is rolled back completely (key, registry marked removed, provigil-db
  purged). Answer: agent id, name, address, raw key, tenant id, groups, re-enrolled flag.

### 2.4 Keepalive (`main.rs` `agent_keepalive`, `http_agent_state.rs`, `provigil_manager.rs`)

- **S15** Tenant checks (S10, S11).
- **S16** siem-api's in-memory agent entry set active / created (name from the enrollment), and
  the ClickHouse `siem_agents` row written at most every 60 s per agent or at once on a change
  of status, name, address or version, never awaited (`db.rs` `save_agent_row`).
- **S17** Queued commands handed out: the legacy list (persisted in ClickHouse with a
  "delivered" mark when taken, `persist.rs`) and, for agents proving their key with the bearer,
  the ProVigil list (`take_http_commands`, in memory). Each command is handed out once.
- **S18** The agent is marked "talks the ProVigil protocol" (in memory). Console actions use
  that mark to queue commands for it instead of sending them to the old gateway.
- **S19** The reported version (letters, digits, `.`, `-`, `_`, at most 32 characters) is kept
  for the next provigil-db flush.
- **S20** `group_config_version` compared with the current version of the agent's group
  configuration → `group_config_status` "synced" / "not synced" in provigil-db, written only
  when it changed.
- **S21** `fim_state_wanted` → if the agent holds or gets one of its tenant's 20 baseline slots,
  the answer carries a `fim_state_allowed` command. A slot is freed by the agent's last baseline
  batch or after 10 minutes.
- **S22** Labels (`labels: [{key, value, hidden}]`, keys without line breaks or colons) and
  `agent_ip` (a valid address) stored in provigil-db as the engine expects them; rewritten only
  when they changed (fingerprint per agent); the agent row's address updated.
- **S23** provigil-db writes run in the background: the commands taken reach the agent even
  when provigil-db is slow or down.
- **S24** A flusher every 10 s writes "last keepalive, active, no disconnection, status code 0"
  for every agent heard from, 1,000 ids per statement; node, address and version only for
  agents whose version changed (kept to retry when a statement fails); every ~hour all are
  rewritten (a restored provigil-db gets its fields back).
- **S25** HTTPS answer: status, agent id, commands; errors: status error with a message.

### 2.5 Events (`main.rs` `ingest*`, `http_agent_state.rs`, `provigil_manager.rs`)

- **S26 Batch ids.** A batch carries `batch_id`; the last 64 ids per agent are kept; a repeat is
  answered OK and not processed. An id is forgotten again when its batch was not taken (refused,
  or cut short by the time limit) so a later try is processed.
- **S27 Backpressure.** While the engine is "behind" (S36) the batch is answered **429** before
  its id counts as seen; the agent keeps it and sends it later.
- **S28 Body forms and limit.** A list, an object with `events`, or one event; up to 16 MiB on
  HTTPS (`AGENT_BODY_LIMIT`; other agent routes keep the 2 MiB default); an agent id missing
  from the body falls back to "001".
- **S29 Baseline first.** `fim_state` events go first, straight into provigil-db's file table
  (no engine, no alert), on their own provigil-db connection; not stored → **503** for the batch
  (nothing of it taken yet); the batch flagged `last` frees the agent's slot.
- **S30 Response program results.** `ar_log` events are grouped per agent (tenant check per
  agent) and handled by siem-api like the old agents' response log lines: live-response
  results, tamper protection, YARA results and their alerts (`on_agent_ar_lines`).
- **S31 To the engine.** Events of kind windows_eventchannel, logfile, command, rootcheck,
  fim, registry, and sca with a text message go to the engine: Windows channels on the
  event-channel queue, rootcheck on its queue, sca on its queue, fim and registry converted to
  the engine's file-integrity message form on its queue, the rest on the log queue. Each event
  needs a location. The hand-off labels the source with agent id (3 digits), name and address
  ("any" when empty), marks it as coming from the platform, and counts every datagram sent.
  Assessment summaries in the batch are watched (S43).
- **S32 Engine unreachable.** When the hand-off fails, those events are stored through
  siem-api's own path instead (warning with the count), so nothing is lost.
- **S33 Inventory.** `system_inventory` and `system_inventory_delta` of a known ProVigil agent
  are written to provigil-db in the background (S42).
- **S34 Everything else** (agent status, upgrade notification, the Linux prototype's events,
  legacy telemetry) goes through siem-api's in-process rule engine, its SCA / FIM / inventory
  handling, the event store in ClickHouse and the live window; alerts are recorded.
- **S35** A batch with nothing usable → 400 (unless it carried handled `ar_log` / `fim_state` /
  engine events).
- **S36 Engine lag.** Every 500 ms siem-api asks the engine for its load (fullest queue usage and
  the platform datagrams it received), with a 1 s limit. Lag = datagrams sent − received,
  tracked across readings: a lower received count means the engine restarted (lag reset); no
  movement at all means the rest was lost, not waiting. "Behind" = lag above 2,000 or queue
  above 25 % or no answer within 1 s; "not running" = open. Each change is logged once.

### 2.6 Results, live queries, config, YARA, upgrades (`main.rs`, `provigil_manager.rs`, `agent_config.rs`, `agent_grpc.rs`)

- **S37 Result.** `POST /api/v1/agents/:id/response_result` / gRPC Result: tenant checks,
  logged, handed to a live query waiting for that command id **from that agent**. HTTPS answer:
  acknowledged with the agent id.
- **S38 Live query** (console, user token): `GET /api/v1/agents/:id/live/config|state`.
  Another tenant's agent or unknown kind → 404; an agent not seen on the ProVigil protocol by
  this siem-api → 409; queues `getconfig` / `getstate` and waits 30 s → the agent's result, else
  504. A query whose caller left or timed out is removed from the queue if not yet handed out.
- **S39 Config.** `GET /api/v1/agents/:id/config` / gRPC Config: bearer only; not enrolled → 404;
  the `agent.conf` of each of the agent's groups (tenant group names mapped to manager names),
  translated in group order into the agent's JSON settings; version = first 8 bytes of SHA-256
  of that JSON, in hex.
- **S40 YARA.** `GET /api/v1/agents/:id/yara-rules` / gRPC Yara: bearer; the rule file, else 404.
- **S41 Upgrade download.** gRPC Upgrade streams the file in 1 MiB chunks read as sent; file name
  in `x-file-name`, default the agent program; only published package files, anything else
  (including paths) → NOT_FOUND; for the agent program, an asked version different from the
  published one → FAILED_PRECONDITION. HTTPS: the agent downloads `/downloads/...` URLs with its
  bearer (`transport.rs`); siem-api serves `/downloads/*` publicly (also used by the install
  script, whose files are checked against `agent_files`).
- **S42 Inventory state** (`http_agent_state.rs`): a full inventory replaces the tables (OS,
  hardware, packages, hotfixes, processes, ports, network with protocols and addresses,
  services, users, groups, browser extensions), sets the agent's OS row, and asks a
  vulnerability re-scan when the software fingerprint changed. A delta removes and adds rows by
  item hash, then compares each table's count and hash with the agent's; a mismatch queues
  `inventory_full` (at most once an hour per agent); packages / hotfixes / OS changes ask a
  re-scan. Statements stay under provigil-db's 64 KiB message size.
- **S43 Assessment watch.** Summaries sent to the engine are checked every 15 s against
  provigil-db once the engine stored them (given up after 600 s); a difference queues
  `sca_full` for that policy (at most once an hour). This exists because the engine's own
  "dump" request only reaches agents of the old gateway.
- **S44 Console upgrade** (`POST /api/v1/agents/:id/upgrade`, manage right): a ProVigil agent
  gets a queued `upgrade` command with the agent file's SHA-256 and version and the list of
  published files with their hashes (old agents go through the upgrade module).

### 2.7 Command queue and console actions (`main.rs`, `provigil_manager.rs`, `persist.rs`)

- **S45 ProVigil queue.** In memory, per agent, at most 200 commands (the oldest dropped), lost
  when siem-api restarts.
- **S46 Command forms.** Console actions are written in the old active-response text form and
  turned into agent commands: "scan" for a file-integrity/rootcheck restart, else "ar" with the
  response message. Other command types: `upgrade`, `getconfig`, `getstate`,
  `fim_state_allowed`, `inventory_full`, `sca_full`. Each has a `command_id`.
- **S47 Console actions** (`POST /api/v1/agent/commands`): restart; file-integrity / rootcheck
  scan; assessment scan; block an address (timeouts rounded up to 600 / 3,600 / 86,400 s;
  firewall rule or null route on Windows, firewall-drop on Linux; decision gate; record kept);
  unblock refused with an explanation; kill process, quarantine, restore, isolate, release,
  YARA scan (Windows agents, decision gate except release and YARA); live response; tamper
  lock / off / window. Isolation keeps the manager addresses reachable (`SIEM_LAN_IP` or
  `MANAGER_IP` plus `EDR_ISOLATION_ALLOW`).
- **S48 Legacy command routes** (Linux prototype agent): fetch by `?agent_id=` or by path with
  `X-Agent-Key` (taken commands marked delivered in ClickHouse); command ack route
  (unauthenticated, only logs); agent state route `GET /api/v1/agent/state?agent_id=`
  (unauthenticated: active, deactivated or removed).

### 2.8 Known gaps found while writing this (today's behaviour, to fix in the gateway)

- Engine-triggered active responses (rules with automatic responses, and "dump" requests) go to
  the old gateway's queue and never reach ProVigil agents (`send_ar_queue` only intercepts
  console actions).
- A keepalive with status "stopping" (`transport.rs`) is ignored; the agent shows active until
  it times out. The old gateway sent an "agent stopped" event (R27).
- The manager-added labels (manager host, node, agent version; R32) are not written for
  ProVigil agents.
- The ProVigil command queue and the "talks the ProVigil protocol" mark are memory only: a
  siem-api restart loses queued commands, and for up to one keepalive after a restart console
  commands go to the old gateway, which cannot reach the agent.
- HTTPS ingest parses up to 16 MiB of JSON before any key check, and accepts events for
  unenrolled agent ids with no key at all (S12), into `default` when no tenant key is sent.
- Over gRPC there is no "too large" answer the agent understands; only the agent's 1 MiB batch
  cap keeps batches small.
- The certificate is renewed only at start.
- The lag signal assumes siem-api is the only sender of platform datagrams.

---

## 3. The gateway design

### 3.1 What it is

`provigil-gateway` is a separate process (its own crate, `crates/provigil-gateway`, one binary
and one library). It owns every agent-facing listener. It is stateless apart from caches: all
shared state lives in ClickHouse (3.3), agent state in provigil-db, events go to the engine.
It uses `provigil-proto` unchanged, so agents need no change to move to it.

Design rules:

- **G-R1** Nothing per message on the hot path may write to disk, hold a lock shared by all
  requests, or wait on ClickHouse or provigil-db (lesson of F1). Keepalives and events touch
  only memory and the engine link; database writes are batched in the background.
- **G-R2** No unauthenticated work beyond TLS, connection limits and reading headers, except on
  the three public routes (enroll, public downloads, legacy agent state), which have their own
  small limits.
- **G-R3** Nothing is dropped silently: every refusal and every drop has a counter and a log
  line (rate-limited: the first, then a summary every minute).
- **G-R4** Every queue is bounded; when one is full the agent is told to come back later (429 or
  503, which the agent retries) rather than losing data.
- **G-R5** No new files (the storage rule): no state file, no local cache file, no spool.

### 3.2 What moves out of siem-api and what stays

Moves to the gateway (the agent's traffic):

- the gRPC listener (S1) and the agent part of the HTTPS listener (S2), the long accept queue
  (S3), TLS from the install CA (S5, S6) with renewal;
- authentication and tenant rules (S8-S13) against cached shared state;
- keepalive (S15-S25), except the in-memory agent list and `siem_agents` row (S16), which
  siem-api already rebuilds from provigil-db every 10 s (`provigil_manager.rs` agent status
  loop);
- events: batch ids, backpressure, baseline, hand-off to the engine, inventory and assessment
  state (S26-S29, S31, S33, S35, S36, S42, S43);
- results (S37), config (S39), YARA (S40), upgrade downloads and the agent's authenticated
  downloads (S41);
- the legacy Linux routes (S48) while that agent exists;
- delivery of engine-triggered active responses and dump requests (new, see 3.6);
- counters and state (3.9).

Stays in siem-api:

- the console, every user API, `/api/server-info` (its `https_url` / `grpc_url` now name the
  gateway's public addresses, from `GATEWAY_PUBLIC_HOSTS` or the same host list as today);
- **enrollment**: id allocation (one atomic counter), name and group rules, keystore,
  registry, provigil-db registration and rollback stay where they are, because they need the
  tenant and group logic and are rare. The gateway receives Enroll on its listeners and
  forwards it to siem-api's internal API (3.4) with the tenant key and the peer address;
- console actions, live queries, the console upgrade request, agent removal and deactivation:
  they now write to and read from the shared command queue (3.3) instead of memory;
- the handling of `ar_log` lines (S30) and of "everything else" events (S34): the gateway
  forwards them to siem-api's internal API; they are low volume for ProVigil agents;
- storage of the engine's output (the acknowledged stream of `AGENT-REVIEW-FIXES.md` parts M
  and N), the agent status loop, the key service for the other manager daemons, the syslog
  receivers (`syslog_tenancy.rs`, which already replace R42).

### 3.3 Shared state: ClickHouse

Choice: **ClickHouse**, with the gateway holding in-memory copies refreshed by change polling.

Why ClickHouse and not the others:

- It is already the master copy of all four things: agent keys (`agent_keys_store.rs`,
  encrypted with `AGENT_KEYS_SECRET`), the agent registry with tenant binding, removed and
  disabled flags (`db.rs` `agent_registry`), tenant agent keys (`tenant_agent_keys`) and the
  tenant list with its active flag (`tenancy.rs`). The legacy command list is there too
  (`persist.rs`). Nothing has to be copied or migrated except the in-memory ProVigil queue.
- Every gateway host can reach it; siem-api does not have to be up for the gateway to work, so
  siem-api is not in the hot path and its restarts do not stop agents.
- The owner's storage rule: platform data in ClickHouse, agent state in provigil-db, no files.
- provigil-db is a local socket on one host, holds agent state rather than platform data, and
  is due to be replaced (`specs/README.md` step 5). A small internal API on siem-api would put
  siem-api back in the path for every key change and every command, and would need its own
  durability for the queue.

How it is used:

- **Caches.** At start the gateway loads keys (decrypted with `AGENT_KEYS_SECRET`), registry,
  tenant keys and tenants. Every 2 s it reads rows changed since its last watermark
  (`updated_at`). A removed or deactivated agent, a rotated tenant key, an inactive tenant takes
  effect within about 2 s on every gateway. Keys are indexed by a hash of the key so the bearer
  alone identifies the agent (3.7). A key change for an agent clears the gateway's per-agent
  caches (labels, versions, group status, batch ids), as S14 does today.
- **Command queue.** One table in the shared database (not per tenant, so a gateway polls one
  table): tenant, agent id, command id, the command exactly as the agent receives it, origin
  (console user, engine, gateway), created, expires, state (queued, handed out, done, failed,
  expired, cancelled), state time, handing gateway, result, and a version for "last row wins".
  siem-api writes queued commands (console actions, live queries, upgrades, legacy commands);
  the gateway writes handed-out, done/failed with the result, expired; siem-api writes cancelled
  (a live query whose caller left).
- **Command rules.** At most 200 waiting commands per agent: the oldest is expired and counted,
  never silently removed. Each command has an expiry (default 24 h; time-bound responses such as
  a 600 s block expire after their duration; live queries after 30 s). An expired command is
  never handed out. Handing out: the gateway takes the agent's waiting commands from its cache
  when answering the keepalive and records "handed out" in a batched write (within 1 s). Results
  are written as they arrive (batched within 1 s).
- **Not lost, not doubled.** A handed-out command with no result after 120 s, for an agent that
  has kept sending keepalives, is offered again once, but only for repeatable types (scan,
  getconfig, getstate, inventory_full, sca_full, fim_state_allowed, upgrade; the agent answers
  "upgrade in progress" for a repeat). Responses (`ar` commands such as kill or quarantine) are
  not offered again until the agent drops repeated command ids (owner decision 3); they are
  marked "no result" for the console instead. Two gateways cannot hand out the same command for
  one keepalive: an agent's keepalives are 10 s apart and "handed out" reaches every gateway
  within about 3 s.
- **"Talks the ProVigil protocol".** Set in the registry by the gateway on the agent's first
  bearer keepalive. siem-api reads it to route console actions (replaces S18's memory mark, so
  a restart no longer misroutes commands) and for the live query's 409.
- **Live queries.** siem-api writes the query, then reads its row every 500 ms for up to 30 s.

### 3.4 Internal API on siem-api (only for the rare, siem-api-owned work)

A small listener on siem-api bound to loopback (or a private address when gateways run on other
hosts), each call carrying `GATEWAY_INTERNAL_TOKEN` (constant-time check), or mutual TLS with a
certificate from the install CA when not on loopback. Calls:

- enroll (the agent's request, its tenant key, the peer address) → the S14 answer;
- `ar_log` lines of an authenticated agent (agent id, tenant) → S30;
- "everything else" events of an authenticated agent (agent id, tenant) → S34.

siem-api trusts the agent id and tenant the gateway sends (the gateway checked them). When
siem-api is down or slow (5 s limit), the gateway answers 503 for that request and the agent
retries; enrollment answers UNAVAILABLE.

### 3.5 The engine link

- The gateway hands events to the engine exactly as S31 describes, on the engine's local input,
  and counts every datagram it sent.
- Backpressure as S36, with the same thresholds, read every 500 ms. With more than one gateway
  feeding one engine, "lag" needs the engine to report received datagrams **per sender** (each
  gateway marks its datagrams with its id). Until the engine does, a gateway that knows other
  senders exist uses queue usage only, with a lower threshold (15 %) (owner decision 4).
- Engine not answering or not running → the gateway answers **503** to event batches that need
  it (no in-process fallback: S32 is dropped, see part 4) and keeps answering keepalives.
- Engine restart (received counter goes down) → logged as an error with the lag at that moment
  ("up to N events may have been in the engine's buffer"), counted. Zero loss across an engine
  restart needs an acknowledged engine input (owner decision 4); until then this window is
  counted, not silent.
- The gateway re-resolves the engine's local address on every reconnect (the F6 lesson: never
  keep sending to an address the engine no longer listens on).

### 3.6 Engine-triggered active responses (new; fixes a gap)

The gateway reads the engine's active-response requests and its assessment "dump" requests and
turns each into a queued command in the shared queue: a response for the event's agent or a named
agent; "all agents" expands to every ProVigil agent heard from within the disconnection time
(10 min); a dump becomes `sca_full` for that policy. Invalid requests are logged and counted.
While the old gateway still runs for the prototype agents it owns those queues; the engine then
needs a second destination for them (owner decision 5). The siem-api assessment watch (S43)
stays as a safety net.

### 3.7 Security

- **TLS only.** No plain listener, except an optional one bound to `127.0.0.1` for the load tool
  and tests, off by default (`GATEWAY_PLAIN_LOOPBACK=1`). TLS 1.2 and 1.3 with the safe default
  suites, ALPN h2 and http/1.1, 10 s handshake limit. The certificate comes from the install CA
  (read from `data/tls/` on the same host; for gateways on other hosts, the CA key stored
  encrypted in ClickHouse like the syslog CA, decision 6). Renewed 30 days before expiry and when
  the host list changes, swapped without dropping connections. `SIEM_GRPC_TLS_CERT` /
  `SIEM_GRPC_TLS_KEY` still override it.
- **Order of checks, before any body is read:** connection limits → TLS → request headers →
  bearer key looked up by its hash (constant-time compare of the full key) → the id in
  `x-agent-id` or the path must be that key's agent → removed 404 / deactivated 410 / tenant key
  401, 403, 409 → per-agent rate limits → only then the body is read and decoded. On gRPC this
  check runs as a layer on the request headers before the message is decoded.
- **One agent per request.** Every event in a batch must carry the authenticated agent's id (or
  none, then it is filled in); a batch with another agent's id is refused with 400 and counted.
  The body's tenant id is ignored. Unenrolled agent ids are refused with 401 (S12 dropped).
- **Public routes** (no key yet): enroll (body at most 16 KiB, 5 per minute per source address,
  100 per second in total, then 429), public downloads (only the published package files and
  the deploy script's files, at most 2 at a time per source address), legacy agent state
  (60 per minute per source address).
- **Input limits.** Headers 16 KiB; at most 8 concurrent calls per connection; 14 s per call;
  events body 16 MiB (HTTPS and gRPC, as today); keepalive 64 KiB; result 1 MiB; config / YARA /
  upgrade requests have no body. One event larger than the engine's maximum message (64 KiB) is
  dropped from its batch, the rest accepted, counted and logged per agent (no batch is refused
  forever).
- **Limits per agent:** at most 4 open connections per key (the newest wins, the oldest is
  closed); at most one events request in flight; keepalive at most 1 per second (more → 429);
  events at most `GATEWAY_AGENT_MAX_EPS` (default 2,000/s, then 429).
- **Limits per gateway:** at most `GATEWAY_MAX_CONNECTIONS` (default 25,000) open connections,
  new ones refused beyond; at most 50 new TLS handshakes per second per source address.
- **Cloned identities** (replaces R17): the same key seen from two different source addresses
  within 60 s is counted and logged once per hour per agent, and flagged in the gateway state.
- **Network-restricted keys** (R14): a key whose allowed address is not "any" is only accepted
  from inside that network. Behind a balancer this needs the PROXY protocol
  (`GATEWAY_PROXY_PROTOCOL=1`), which is also needed for per-address limits.
- **Secrets:** `AGENT_KEYS_SECRET`, ClickHouse credentials, `GATEWAY_INTERNAL_TOKEN` from the
  environment of the service account; agent keys and tenant keys never logged.
- **Isolation allow list:** every gateway address agents use must be in `EDR_ISOLATION_ALLOW`
  (siem-api `isolation_allow`), or an isolated host cannot be released.

### 3.8 Reliability

- The agent's own buffer is the event queue: the gateway holds no event queue of its own. A
  batch is answered 2xx only after it was handed to the engine (and its baseline rows stored),
  else 429 or 503 and the agent keeps it (`transport.rs` re-queues on 429, 5xx and network
  errors; drops on other 4xx).
- Order inside one batch: everything that can refuse comes first (baseline rows in provigil-db,
  forwards to siem-api), the engine hand-off last, so a refused batch was not partly handed on.
- Keepalives are never refused for engine load: commands such as isolation must still reach
  agents during an attack.
- Background writes are bounded: provigil-db operations (10,000), ClickHouse command marks and
  results (50,000 rows). When full: inventory and baseline batches get 503, results get 503
  (the agent keeps up to 100), keepalive marks coalesce per agent (bounded by the agent count).
- Every refusal and drop is counted by reason (3.9).
- **Restart of a gateway.** On stop it stops accepting, tells HTTP/2 clients to go away, finishes
  calls in progress (at most 14 s), writes its pending command marks and keepalive flush, then
  exits. Agents reconnect (their failover and retry) to the same address. Queued commands are
  in ClickHouse and come back into the cache at start; events not answered stay in the agents'
  buffers. A crash can lose up to 10 s of "last keepalive" times (the next keepalive fixes them)
  and may let a batch that was handed on but not answered come again: the batch-id memory is
  per process, so after a crash that batch can be processed twice (at-least-once). The gateway
  cannot see such a repeat, so it is documented here rather than counted; a planned stop drains
  first and does not cause it.
- **Restart of siem-api.** Agents keep working: keepalives, events, commands already queued,
  results. Enrollment, `ar_log` lines and "everything else" events get 503 until it is back.
- **ClickHouse down.** Agents keep working with the cached keys; new commands are not seen;
  command marks and results wait in the bounded buffer, then results get 503. At start without
  ClickHouse the gateway listens but answers UNAVAILABLE / 503 (and its health says not ready)
  until the caches are loaded, retrying every 5 s.

### 3.9 Observability

- An internal listener (`GATEWAY_STATS_ADDR`, default `127.0.0.1:9101`, token when not loopback)
  serves `GET /metrics` (Prometheus text), `GET /state` (JSON: global counters, effective
  settings without secrets, cache ages) and `GET /state/agents` (per-agent counters, 150 per page
  from a last id, like R43), and `GET /health` (ready only with a certificate, loaded caches and
  an answering engine link).
- Every 60 s one row in ClickHouse (`gateway_state`: gateway id, host, version, start time, the
  counters) for siem-api's manager status page. No state file (G-R5; replaces R55).
- Counters (global unless said): uptime; open connections by listener; TLS handshakes ok, failed,
  timed out; bytes in and out; calls by kind and outcome (ok, 400, 401, 403, 404, 409, 410, 413,
  429 by reason, 503 by reason, time limit); keepalives received, coalesced, rows flushed, flush
  failures; events received, handed to the engine per queue, repeated batch ids, too large,
  forwarded to siem-api, baseline rows stored, inventories and deltas applied, full sends asked;
  engine behind (yes/no), lag, queue usage, age of the last load answer, restarts seen,
  datagrams possibly lost at a restart; commands cached, handed out, offered again, expired,
  results stored; engine responses received, invalid, queued, "all agents" expansions; caches:
  keys, registry rows, tenants, last poll age, poll failures; background write backlog; cloned
  identities. Per agent: keepalives, events, commands handed out, results, refusals by reason,
  last seen, protocol (gRPC / HTTPS).
- Logs: transitions (engine behind / open, ClickHouse lost / back) once each; a full queue warns
  once per episode with the count at the end.

### 3.10 Several gateways behind one address

- A gateway keeps nothing that another one needs: keys, registry, tenants and commands are in
  ClickHouse; agent state in provigil-db; the per-process memory is only caches, batch ids,
  baseline slots and counters. Any gateway can serve any call of any agent.
- On one host: several gateway processes share the agent ports (Linux: port reuse across
  processes; Windows: one process per port pair behind a TCP balancer). The main use is rolling
  restarts with no gap; one process already uses every core.
- Across hosts: a TCP (layer 4) balancer with TLS passed through, or DNS, or the agent's own list
  of managers; source-address affinity keeps an agent's retries on one gateway (fewer repeated
  batches). This needs the engine input and provigil-db to be reachable from every host, which
  today are local sockets on the manager host (owner decision 7; `specs/README.md` step 5).
- Baseline slots (S21) are counted per gateway: each gateway gives `20 / number of gateways`
  per tenant (`GATEWAY_COUNT`, default 1), so the tenant total stays 20.

### 3.11 Switch-over, with the console working throughout

1. siem-api moves its ProVigil command queue and the "talks the ProVigil protocol" mark to the
   shared table and registry (3.3), and gets the internal API (3.4). Its own agent handlers keep
   running and use them. Nothing visible changes; the restart gaps of 2.8 are gone.
2. The gateway runs on other ports (for example 9089 / 9443) against the same ClickHouse,
   provigil-db and engine. The load tool and a test tenant use it; real agents stay on siem-api.
   Console actions reach agents on either front door, because both read the same queue.
3. siem-api stops listening on 8089 / 8443 (`SIEM_AGENT_FRONT_DOOR=gateway`) and the gateway
   takes those ports; `/api/server-info` names the gateway. Agents reconnect to the same
   address with no change. Rollback = the flag back and the gateway stopped.
4. siem-api's agent handlers, its TLS listeners and the lag loop are moved to `old-code/` after
   the line-by-line review (owner rule). The plain port keeps answering 426 for agent routes.
   `start-all.bat` and `stop-all.bat` start and stop the gateway.

### 3.12 Settings

Environment, each checked against a range at start (`--test-config` checks and exits):
`GATEWAY_GRPC_PORT` (8089), `GATEWAY_TLS_PORT` (8443), `GATEWAY_BIND` (all addresses, IPv4 and
IPv6), `GATEWAY_ID` (host name + port), `GATEWAY_COUNT` (1), `GATEWAY_PUBLIC_HOSTS`,
`GATEWAY_STATS_ADDR`, `GATEWAY_INTERNAL_TOKEN`, `SIEM_API_INTERNAL_URL`, `GATEWAY_MAX_CONNECTIONS`,
`GATEWAY_AGENT_MAX_EPS`, `GATEWAY_PROXY_PROTOCOL`, `GATEWAY_PLAIN_LOOPBACK`,
`PROVIGIL_MANAGER_HOME` (engine sockets, provigil-db socket, group folders, published agent
files), `CLICKHOUSE_URL` / `_USER` / `_PASSWORD`, `AGENT_KEYS_SECRET`, `SIEM_GRPC_TLS_CERT` /
`_KEY`, the disconnection time (10 min). Command line: `--version`, `--help`, `-d` / `-dd`,
`--test-config`.

---

## 4. Feature list

Keep = the gateway (or siem-api where it says so) does it as described. Replace-by = the same
need met differently. Drop = not done, with the reason.

### 4.1 Old gateway features

| Id | Feature | Decision |
|---|---|---|
| R1 | Listeners from configuration (port, TCP/UDP, local address, IPv6, several blocks) | replace-by: gRPC and HTTPS listeners, `GATEWAY_BIND` / ports, IPv4 and IPv6 |
| R2 | Fatal start on bad configuration or a port that cannot be bound | keep (also: no certificate) |
| R3 | Accept loop, no-delay, session counter, accept errors logged | keep (S3 queue, 100 ms pause, connection counters) |
| R4 | Framed messages with a size limit, oversize closes | replace-by: HTTP/2 message and body limits (3.7) |
| R5 | UDP transport | drop: TLS only; own protocol is over TCP |
| R6 | Bounded receive queue, discard counted, warn once | replace-by: no event queue; 429 to the agent (3.8), counted, warn once per episode |
| R7 | Worker pool; counter verification needs one worker | replace-by: async runtime on all cores; per-agent order from one events request at a time |
| R8 | Per-connection send buffer, wait once then drop | replace-by: HTTP/2 flow control; commands ride on answers, nothing pushed |
| R9 | Socket close bookkeeping, "dequeued after close" | drop: no per-agent push socket to track in a request/answer protocol |
| R10 | Tuning options with ranges, reported | replace-by: gateway settings with ranges (3.12), reported in `/state`; unused old options not carried |
| R11 | Command line (version, help, debug, test config, config file, home, no-merged) | replace-by: `--version`, `--help`, `-d`, `--test-config`; home from `PROVIGIL_MANAGER_HOME`; no-merged dropped with R46 |
| R12 | Keys from file or siem-api key service | replace-by: keys from ClickHouse, decrypted, cached (3.3) |
| R13 | No keys is fatal unless allowed | drop: a new install has no agents; the gateway starts and logs it |
| R14 | Sender by id with network check, or by exact address | replace-by: bearer key; network-restricted keys still checked (3.7) |
| R15 | Unknown sender: refused, counted, key request | replace-by: 401, counted; the agent enrolls again after 3 refusals |
| R16 | Unauthenticated ping/pong | replace-by: HTTP/2 and TCP keepalive (no unauthenticated application work) |
| R17 | One live connection per key, overtake after idle time | replace-by: at most 4 connections per key, newest wins; cloned-identity detection |
| R18 | Empty message refused | keep (400) |
| R19 | Decryption, replay protection, error kinds | replace-by: TLS; batch ids for repeats |
| R20 | Receive counters on disk | drop: TLS replay protection; no files |
| R21 | Last-received time decides "connected" | keep (last seen in memory, flushed to provigil-db; "all agents" uses it) |
| R22 | Key reload on change, keeping network state | replace-by: 2 s change polling; per-agent caches cleared on a key change; reload counter |
| R23 | Key request link to the enrollment daemon | drop: no key-request daemon; agents re-enroll themselves |
| R24 | Sender counter file kept open | drop: no per-message counters; its lesson is rule G-R1 |
| R25 | Session bookkeeping per control message | drop: stateless requests |
| R26 | Startup: version kept; newer than manager refused; no version refused; status codes | replace-by: version from every keepalive (S19); an agent newer than the published one is flagged in state, not refused (decision 8) |
| R27 | Shutdown: "agent stopped" event, disconnected with reason | replace-by: keepalive status "stopping" → disconnected with reason "stopped" at once and an "agent stopped" event to the engine (fixes 2.8) |
| R28 | Keepalive text cleaning | drop: the keepalive is JSON |
| R29 | Acknowledgement of startup and keepalive | replace-by: the keepalive answer |
| R30 | Control queue keyed by agent, newest wins, counted | replace-by: last-seen map flushed every 10 s (S24); counted received / coalesced / flushed |
| R31 | Keepalive parsed into OS fields, version, checksums, labels | replace-by: JSON keepalive (S19, S22) and the inventory's OS (S42) |
| R32 | Manager-added labels (manager host, node, agent version) | keep (new for ProVigil agents; fixes 2.8) |
| R33 | Unchanged keepalive writes only "last keepalive" | replace-by: S24 writes only what changed |
| R34 | Group lookup, guess by checksum, default group, worker asks master | replace-by: groups from enrollment and the console (siem-api); no guessing (agents report no bundle checksum) |
| R35 | Group configuration status and push when different | replace-by: S20 and the agent's Config call |
| R36 | Agent row written per keepalive | replace-by: S24 batched flush, S22 labels, S42 OS row |
| R37 | Reset every agent's connection status at start | drop: with several gateways one start must not mark others' agents disconnected; siem-api's agent monitor decides by last-seen age |
| R38 | Per-agent statistics pruned to active agents | keep (pruned after the disconnection time) |
| R39 | Event hand-off with agent source label | keep (S31) |
| R40 | Engine link reconnects, resends once, logs; malformed message logged | replace-by: 3.5 (503 while down, re-resolve on reconnect, counted) |
| R41 | Inventory forwarding to inventory and vulnerability providers | replace-by: S42 (provigil-db tables, vulnerability re-scan request) |
| R42 | Remote syslog with allow / deny lists | replace-by: siem-api `syslog_tenancy.rs` (TLS 6514, plain with address-to-tenant map); not in the gateway |
| R43 | Local statistics and configuration commands with error meanings | replace-by: `/metrics`, `/state`, `/state/agents` (3.9) |
| R44 | Request relay with pool, retries, timeouts, error kinds | replace-by: live queries through the shared queue (S38), at most 4 waiting per agent and 200 in total, 30 s |
| R45 | Answers matched by request number | replace-by: results matched by command id and agent (S37) |
| R46 | Group bundles (scan, binary file refusal, path limit, checksum, atomic write) | replace-by: Config (S39) translates each group's `agent.conf`; an unreadable file is logged once until it changes |
| R47 | Multi-group bundles | replace-by: Config merges the agent's groups in order |
| R48 | No bundles on a worker / flag | drop: no bundles |
| R49 | Remote group files from URLs (YAML, poll) | drop: group settings are edited in the console; nobody uses URLs (decision 9) |
| R50 | Bundle push in pieces, UDP pacing | replace-by: the agent pulls Config when the version differs |
| R51 | Engine active responses (all / one / raw), counted | replace-by: queued commands (3.6; fixes 2.8) |
| R52 | Assessment dump requests to the agent | replace-by: `sca_full` command (3.6), S43 kept |
| R53 | Encrypted send; "not found" and "disconnected" refuse | replace-by: commands wait in the queue until handed out or expired |
| R54 | Global and per-agent counters | replace-by: the counters of 3.9 |
| R55 | State file | replace-by: `/state` and the `gateway_state` row (no files) |
| R56 | Cached clock | drop: implementation detail |
| F1 | No per-message disk write or shared lock (16 Oct) | keep (G-R1, tested in part 5) |
| F5 | Unique ids under concurrent enrollment (16 Oct) | keep (siem-api) |
| F6 | Engine restart must not make the gateway send into nothing (16 Oct) | keep (3.5) |

### 4.2 siem-api agent front door features

| Id | Feature | Decision |
|---|---|---|
| S1 | gRPC TLS listener, 8089, 16 MiB, keepalives 60 s, 8 calls per connection, 14 s, cert override | keep (gateway) |
| S2 | HTTPS 8443 serving the whole router | replace-by: the gateway serves only agent routes, public downloads and legacy agent routes; the console stays on siem-api (smaller attack surface; decision 10) |
| S3 | Accept queue 65,535, address reuse | keep (gateway) |
| S4 | Plain port 426 for agent routes, loopback allowed, `SIEM_AGENT_PLAIN` | keep in siem-api for the plain port; loopback testing moves to the gateway's optional loopback listener |
| S5 | Install-wide CA, private key, never replaced | keep (siem-api creates it; the gateway reads it) |
| S6 | Server certificate for the host list, renewed at start | keep + renewal timer and hot swap (3.7) |
| S7 | `/api/server-info` fields | keep (siem-api, URLs name the gateway) |
| S8 | Bearer key + agent id, constant time | keep + lookup by key hash before the body (3.7) |
| S9 | `X-Agent-Key` for the Linux prototype | keep until that agent is retired |
| S10 | Tenant key rules 401 / 403 / 409, body tenant ignored | keep |
| S11 | Removed 404, deactivated 410 | keep (within 2 s of the change) |
| S12 | Unenrolled ids accepted without a key and bound to a tenant | drop: unauthenticated ingest into a tenant; refused with 401 (decision 1) |
| S13 | gRPC status mapping | keep exactly |
| S14 | Enrollment (all rules, rollback, answer fields) | keep in siem-api; the gateway forwards Enroll (3.4) with rate limits |
| S15 | Keepalive tenant checks | keep |
| S16 | In-memory agent list and throttled `siem_agents` row | replace-by: siem-api's agent status loop from provigil-db (already there) |
| S17 | Commands handed out once (legacy and ProVigil lists) | replace-by: one shared queue (3.3) |
| S18 | "Talks the ProVigil protocol" mark in memory | replace-by: registry flag (3.3; fixes 2.8) |
| S19 | Version kept (validated) | keep |
| S20 | Group config status on change | keep |
| S21 | Baseline slots 20 per tenant, 10 min, freed by last batch | keep (split per gateway, 3.10) |
| S22 | Labels and agent address on change | keep (+ R32 labels) |
| S23 | provigil-db writes never delay the answer | keep (G-R1) |
| S24 | 10 s keepalive flush, 1,000 per statement, version/node/address on change, hourly refresh | keep |
| S25 | HTTPS answer shapes | keep exactly |
| S26 | Batch ids, 64 per agent, forgotten when not taken | keep |
| S27 | 429 while the engine is behind, before the id counts | keep |
| S28 | Body forms, 16 MiB limit, fallback agent "001" | keep the forms the agent sends and 16 MiB; drop the "001" fallback (the id comes from the key) |
| S29 | Baseline rows first, 503 when not stored, slot freed | keep |
| S30 | `ar_log` handling | keep in siem-api; the gateway forwards (3.4) |
| S31 | Engine hand-off by kind, conversions, source label, sent counter, summaries watched | keep |
| S32 | Engine down → stored through siem-api's own path | drop: those events skipped the real rules; 503 and the agent's buffer keeps them |
| S33 | Inventory to provigil-db in the background | keep (bounded, 503 when full) |
| S34 | Everything else through siem-api's in-process engine and event store | keep in siem-api; the gateway forwards (3.4) |
| S35 | Nothing usable → 400 | keep |
| S36 | Engine lag loop (500 ms, 2,000, 25 %, 1 s, restart and loss handling, logged changes) | keep + per-sender counts with several gateways (3.5) |
| S37 | Result handed to the live query of that agent | replace-by: result row in the shared queue |
| S38 | Live query 404 / 409 / 504, removed when the caller leaves | keep in siem-api over the shared queue |
| S39 | Config call and version | keep (the translation is shared library code, used by both) |
| S40 | YARA rules | keep |
| S41 | Upgrade stream (1 MiB chunks, name allow list, version check); authenticated and public downloads | keep (public downloads limited, 3.7) |
| S42 | Inventory state, delta checks, `inventory_full` once an hour, re-scan requests | keep |
| S43 | Assessment watch and `sca_full` | keep (gateway), plus R52 |
| S44 | Console upgrade queues `upgrade` with files and hashes | keep in siem-api (writes the shared queue) |
| S45 | In-memory queue, 200 per agent, lost on restart | replace-by: shared queue, 200 per agent with counted expiry, durable |
| S46 | Command forms (text form translated; command types) | replace-by: siem-api writes the agent's command JSON directly; the agent sees the same commands |
| S47 | Console actions and isolation allow list | keep in siem-api; the allow list must name every gateway address |
| S48 | Legacy Linux routes (fetch, ack, agent state) | keep until the Linux prototype is retired; ack now needs `X-Agent-Key`; agent state rate-limited |

### 4.3 Counts

| | Keep | Replace-by | Drop |
|---|---|---|---|
| Old gateway (R1-R56, F1, F5, F6: 59 rows) | 10 | 37 | 12 |
| siem-api front door (S1-S48: 48 rows) | 39 | 7 | 2 |
| Total (107 rows) | 49 | 44 | 14 |

- Keep, old gateway: R2, R3, R18, R21, R32, R38, R39, F1, F5, F6.
- Drop, old gateway: R5, R9, R13, R20, R23, R24, R25, R28, R37, R48, R49, R56.
- Replace-by, siem-api: S2, S16, S17, S18, S37, S45, S46.
- Drop, siem-api: S12, S32. Inside S28 (a keep) the "001" fallback id is also dropped.
- "Keep" for siem-api includes rows that stay in siem-api unchanged and that the gateway only
  forwards to (S14, S30, S34) and rows kept with an added fix (S6 renewal, S8 key-hash lookup,
  S21 per-gateway split, S36 per-sender lag).

---

## 5. Tests and load-test targets

### 5.1 Tests (each in the gateway crate unless said)

Listeners and TLS:
- real agent links (`provigil-agent` `GrpcLink`, `HttpsLink`) against the gateway with a
  generated CA: enroll (through a stand-in siem-api internal API), keepalive, events, result,
  config, YARA, upgrade; a foreign CA and no CA are refused; a wrong host name is refused;
- certificate renewed from the same CA is trusted by an agent that pinned the old CA, swapped
  while a connection stays open;
- a burst of 10,000 connections waits in the accept queue (none refused);
- the optional loopback plain listener refuses a non-loopback peer; siem-api's plain port still
  answers 426 (existing test kept).

Authentication and limits:
- no key, wrong key, another agent's id, removed (404), deactivated (410), unknown tenant key
  (401), inactive tenant (403), other tenant's key (409), unenrolled id (401), on both protocols,
  with the same codes as today's `agent_grpc.rs` test;
- a 16 MiB events body with a wrong key is refused before the body is read (bytes read by the
  server stay under the header size);
- a batch containing another agent's id → 400, nothing handed on;
- removal in ClickHouse takes effect within 3 s;
- per-agent limits: fifth connection closes the oldest; second concurrent events request 429;
  keepalives above 1/s 429; enroll rate limit 429 per address; public download concurrency.

Keepalive and commands:
- a keepalive answers within 50 ms with provigil-db and ClickHouse both unreachable, and hands
  out the queued commands;
- 1,000 keepalives in 10 s produce one flush statement per 1,000 agents, version/node/address
  only on change (existing `http_agent_state.rs` tests kept);
- labels, manager labels, group status written only on change; "stopping" marks disconnected
  and sends the "agent stopped" event;
- baseline slots per tenant and per gateway count (existing test adapted);
- a command written by siem-api is handed out once across two gateways; expired commands are
  never handed out; the 201st command expires the oldest (counted); a repeatable command with no
  result is offered once more after 120 s; a response command is not;
- live query end to end (siem-api writes, gateway hands out, agent answers, siem-api reads within
  30 s); a caller that leaves cancels a command not yet handed out;
- an engine active response for one agent, for "all agents" (only recently seen ProVigil
  agents) and a dump request become queued commands.

Events and engine:
- batch id: repeat answered and not processed; a refused batch is processed when sent again
  (existing `a_refused_batch_is_taken_when_sent_again` behaviour);
- a slow stand-in engine makes events answer 429 before its queue drops anything, and the engine
  dropped counter stays 0 (part O.3); an engine not running gives 503; keepalives still answered;
- an engine restart (received counter lower) is logged and counted; lost datagrams do not keep
  ingest closed (existing test kept);
- fim / registry conversion, baseline rows, inventory delta, assessment watch tests of
  `http_agent_state.rs` moved with the code;
- an oversize event is dropped from its batch and counted, the rest accepted;
- siem-api internal API down: `ar_log` and other events get 503 and nothing of the batch reached
  the engine.

Restart and switch-over:
- graceful stop with calls in flight: every answered batch reached the engine, unanswered ones
  come again, command marks written;
- kill the gateway mid-run under load: after restart, sent = stored (+ counted repeats only);
- siem-api and the gateway serving at the same time (step 2 of 3.11): a console action reaches an
  agent on either front door;
- ClickHouse down at start: not ready, agents get UNAVAILABLE / 503, ready within 5 s of
  ClickHouse returning.

### 5.2 Load targets (measured live with `crates/provigil-loadtest`)

Runs, each with TLS (`--url grpcs://HOST:8089 --ca ca.pem`, and once with `https://`), in the
`loadtest` tenant, ramped over 30 s, then `--verify` (events sent vs stored in ClickHouse, engine
counters, process CPU and memory, with `--api-process provigil-gateway` and again for siem-api)
and `--cleanup`. The live run needs the owner's OK (it uses the shared manager).

| Run | Target |
|---|---|
| 1,000 agents x 1 EPS, 3 min | sent = stored, 0 dropped anywhere, keepalive p99 under 20 ms |
| 5,000 agents x 1 EPS (5,000 EPS), 3 min (16 Oct target) | sent = stored, 0 discarded, 0 dropped, engine dropped 0 |
| 10,000 agents x 0.5 EPS + 1,000 keepalives/s (16 Oct target) | sent = stored, gateway queues empty, keepalive p99 under 100 ms |
| 10,000 agents, each with its first full SCA burst and inventory, then deltas only (part P) | sent = stored; 429s are re-sent and counted (the load tool re-queues like an agent, part O.6) |
| 10,000 connections opened in a burst (part O.5) | no connection refused |
| Gateway killed and restarted during the 5,000-agent run | sent = stored; commands queued before the kill are handed out after it |
| Engine overloaded on purpose (5 EPS per agent, 1,000 agents) | 429 instead of engine drops: engine dropped stays 0, every 429'd batch stored later |

Limits to report each run: gateway CPU (cores) and memory (target under 500 MB at 10,000
agents; the old gateway used about 190 MB with 10,000 connections), siem-api CPU and memory,
keepalive and batch latency p50 / p99, 429 and 503 counts by reason, engine queue usage and lag.
Enrollment of 10,000 agents through the gateway: at least 50 per second (part O.4), no agent left
that the client does not know.

---

## 6. Owner decisions

1. Unenrolled agent ids: today HTTPS ingest accepts them with no key and binds them to a tenant
   (default when no tenant key). The gateway refuses them (401). Confirm, or name the prototype
   that still needs it.
2. Enrollment without a tenant key lands in `default` from any address that reaches the port.
   Keep, or require a tenant key on the gateway.
3. Agent change (small): drop repeated command ids (remember the last 256). It makes it safe to
   offer response commands again after a lost answer. Optional with it: map gRPC OUT_OF_RANGE
   to 413 so a too-large batch is halved over gRPC as over HTTPS.
4. Engine changes: received counts per sender (needed for more than one gateway) and an
   acknowledged input (needed for zero loss across an engine restart). Now, or with the engine's
   replacement (step 5).
5. While `siem-remoted` still runs for the prototype agents it owns the engine's
   active-response and dump queues; the engine then needs a second destination for the gateway.
   Alternatively retire `siem-remoted` (and port 1514) when the prototype agents go.
6. Gateways on other hosts need the CA key there: store it encrypted in ClickHouse like the
   syslog CA, or issue gateway certificates from siem-api.
7. Gateways on several hosts need the engine input and provigil-db reachable over the network
   (step 5). Until then, several gateways run on the manager host only.
8. Agents newer than the published version: flagged, not refused (the old gateway refused agents
   newer than the manager by default).
9. Remote group files from URLs (R49) are dropped.
10. Port 8443 serves only agent routes after the switch; nobody may rely on the console there.

## Owner decisions (2026-11-05)

Accepted as recommended:
1. Events from agent ids that have no key: refused (401).
2. Enrollment without a tenant key: refused (no default tenant from any address).
3. The agent ignores a command id it has already run (so commands can be sent again safely).
4. Engine changes (received counts per sender; acknowledged input for zero loss on engine restart): now.
5. `provigil-remoted` (port 1514) retires when the gateway takes over.
6. Gateways on other hosts: later; first on the manager host, several instances allowed there.
7. Agents newer than the published version are flagged, not refused; group files fetched from URLs are dropped;
   port 8443 serves agent traffic only once the gateway takes over.

The ProVigil command queue table is being built now in siem-api (`AGENT-REVIEW-FIXES.md` part R item 3):
the gateway uses that table.
