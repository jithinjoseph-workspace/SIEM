# gRPC transport between provigil-agent and siem-api

Written 2026-11-04. ProVigil's own design. Contains no code. Libraries: `tonic` and `prost` (MIT),
messages declared with prost derive macros in Rust (no `.proto` build step, no `protoc` needed).

## Why and how it relates to HTTPS

The agent talks HTTPS/JSON today (`transport.rs`). gRPC is added as the preferred transport; HTTPS
stays as the fallback, so agents and managers of both kinds keep working. The JSON shapes of
every event, command and result do not change: gRPC carries them as JSON text inside the
messages, so nothing else on either side changes.

## Service `provigil.agent.v1.AgentService` (siem-api)

Shared crate `crates/provigil-proto` (new): the message structs, the service trait (tonic server
and client) and the constant service name. Messages:

- `EnrollRequest { name, os_type, groups, force, hostname, version }` →
  `EnrollReply { agent_id, agent_name, agent_ip, raw_key, tenant_id, groups }` (same rules as the
  HTTPS enroll endpoint; the tenant key in metadata `x-tenant-key`).
- `KeepaliveRequest { body_json }` → `KeepaliveReply { commands_json: repeated string }`.
- `EventsRequest { events_json: repeated string }` → `EventsReply { accepted: u32 }` (same handling
  as `/api/v1/events/ingest`, including analysis-engine forwarding and state writes).
- `ResultRequest { result_json }` → `Empty`.
- `ConfigRequest {}` → `ConfigReply { version, config_json }`.
- `YaraRequest {}` → `YaraReply { data: bytes }`.
- `UpgradeChunkRequest { version }` → server stream of `Chunk { data: bytes }` (the published
  agent package; replaces the HTTP download for gRPC agents).

Authentication: metadata `authorization: Bearer <agent key>` for everything except Enroll; the
agent id in metadata `x-agent-id`. The server checks them exactly like the HTTPS routes
(`agent_bearer_ok`, tenant resolution, deleted / disabled agents refused with
`Unauthenticated` / `NotFound` / `PermissionDenied`).

The handlers call the same functions as the HTTPS routes (refactor each route's body into a
function both use), so behaviour is identical.

Server: listens on `SIEM_GRPC_PORT` (default 8089) on the same addresses as the HTTP API, with TLS
when `SIEM_GRPC_TLS_CERT` / `SIEM_GRPC_TLS_KEY` are set, plain otherwise. Max message 16 MiB.
`/api/server-info` adds `grpc_url` (e.g. `grpc://<host>:8089`, `grpcs://...` with TLS) so the
console's install command can put it in `provigil-agent.json`.

## Agent

- `manager_url` / `manager_urls` entries may be `grpc://host:port` or `grpcs://host:port` (gRPC)
  or `http(s)://...` (HTTPS). New optional `grpc_url`: when set, gRPC is tried first for that
  manager; after 3 consecutive gRPC connection failures the agent uses the HTTPS URL for 10 minutes,
  then tries gRPC again (log each switch).
- `transport.rs` gets a trait with the operations above and two implementations (HTTPS, gRPC);
  the rest of the agent uses the trait. Failover (several managers) works across both.
- gRPC with TLS verifies the server certificate unless `tls_insecure: true` (needed for
  self-signed lab certificates; default false — note: the HTTPS client today accepts any
  certificate; change it to the same rule).

## Console install command (`ndr-ui/src/services/siem/agent-deploy.ts`)

When `/api/server-info` returns `grpc_url`, the generated `provigil-agent.json` also gets
`grpc_url`.

## Tests

- A siem-api integration test starting the gRPC server on a random port with a test state: enroll,
  keepalive returns a queued command, events accepted, config returned, YARA bytes returned,
  upgrade stream returns the file; a wrong key is refused.
- Agent: gRPC transport against an in-process test server implementing the trait; fallback to
  HTTPS after 3 failures and back after the interval (time injected).
- Message structs encode/decode round trip.

Then build and test both crates, clippy clean on changed files (`--no-deps`), `npx tsc --noEmit`
for the UI.
