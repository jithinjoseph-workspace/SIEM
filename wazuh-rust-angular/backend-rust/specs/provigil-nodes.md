# ProVigil nodes on Apple Mac Studio (and Ubuntu)

Owner decision 2026-11-27: ProVigil is sold as a family of identical boxes. Every box is the same
Apple Mac Studio, and the software gives each box one role. The smallest system is three boxes. Ubuntu
x86 servers get the same roles (same design, Linux installer). Related: `provigil-cluster.md`
(processing workers for very large agent counts), `provigil-packages.md` (installers).

## 1. Roles and sizes

| Role | Runs | On the Mac |
|---|---|---|
| **Master** | console, sign-in, siem-api (gateway, rules engine, agent database, scanner), NDR engines, Kafka, Vector, Valkey, OpenSearch, Qdrant, the Nodes registry; optional NDR sensor | Linux VM (Colima, Apple virtualization) with ARM images; the sensor runs directly on macOS |
| **AI node** | the local model server (Ollama) | directly on macOS, Apple GPU (Metal); no VM |
| **Data lake node** | ClickHouse (one shard or replica) and, on the first three nodes, ClickHouse Keeper | Linux VM (Colima) with the ARM ClickHouse image, data on the 8 TB SSD |
| Sensor (optional) | Zeek + Suricata on a mirror port | on the master (10 GbE port or a Thunderbolt 10 GbE adapter) up to about 1 Gbps; a separate Ubuntu box beyond |

| Size | Master | AI nodes | Data lake nodes | Boxes |
|---|---|---|---|---|
| Small | 1 | 1 | 1 (nightly backup, no second copy) | 3 |
| Mid | 1 | 3 | 2 (one shard, two copies) | 6 |
| Enterprise | 1 | 8 | 4 (two shards, two copies each) | 13 |
| Large | 1 | 20+ | 8+ | 29+ |

Hardware per box: Mac Studio M4 Max, 16-core CPU, 40-core GPU, 128 GB, 8 TB SSD, 10 GbE.

## 2. Installing a box

One macOS installer (`provigil-install-macos.sh`, later a signed `.pkg`), run on each Mac:

1. The master first: `install --role master --licence licence.jwt`. It installs Colima (MIT licence,
   not Docker Desktop), starts a VM sized for the role (14 cores, 112 GB, disk on the SSD), runs the
   normal Linux installer inside it with the ARM images, sets up the sensor if a capture port is chosen,
   and prints a **join token** (also in the console: Nodes, Add node).
2. Every other box: `install --join https://<master> --token <token>`. The box reports its hardware,
   the console shows it under Nodes, and the operator assigns **AI node** or **Data lake node** (or the
   token already carries the role). The master then sends that role's setup and the box applies it.
3. Node to master traffic: mutual TLS with certificates issued by the master's own CA at join; a token
   is single-use and expires in 24 hours.

## 3. The Nodes page (master console)

Each node: name, role, address, version, state (joining, ready, draining, down), CPU, memory, disk,
for AI nodes the model and queue length, and for data lake nodes the shard, replica, used space and
replication delay. Actions: add (token), drain, remove, upgrade. A node sends a heartbeat every 10 s to
the master (stored in ClickHouse `cluster_nodes`); 30 s without one marks it down and raises an alert.

## 4. AI nodes: shared work

- The master keeps the list of ready AI nodes. The console's existing **AI providers** become this list
  automatically; a hand-added provider (cloud key) still works as before.
- Every AI job (copilot answers, case summaries, parser drafts, NDR AI analysis, UEBA narratives) goes
  to the ready node with the fewest jobs in progress; each node runs at most N jobs at once (set from
  its memory and model size).
- A node that fails or times out is marked down, its job goes to the next node, and it is retried every
  30 s. With no AI node ready, jobs wait (bounded queue) and the console shows "AI busy" instead of
  failing.
- More nodes run more jobs at the same time. A single answer is not faster.
- Model per AI node: chosen in the console (default a 20B model; 128 GB holds 70B-class models).

## 5. Data lake nodes: shared storage

- The master writes the ClickHouse cluster layout from the Nodes list: shards of two replicas
  (pairs of nodes). With an odd count, the last node joins the previous shard as a third copy.
- Each table becomes a local `Replicated*MergeTree` table on every node plus a `Distributed` table
  (same name as today) that the programs read and write. Writes spread over shards by a key per table
  (tenant and time); queries run on all shards at once.
- ClickHouse Keeper: three members (the master and the first two data lake nodes). With one data lake
  node, Keeper runs on the master and that node.
- Adding a shard: new data goes to the new shard by weight; existing data is not moved (it ages out
  with retention). Losing one node of a shard: the other copy serves reads and writes, and the node
  catches up when it returns.
- Small (one data lake node) has a single copy: a nightly backup (ClickHouse BACKUP) to an external
  disk or NAS, set in the console.

## 6. Mac appliance setup (each box)

- Starts with the power: `pmset autorestart 1`, no sleep, no display or disk sleep; the services are
  launchd daemons (they start before anyone signs in).
- Colima VM and Ollama start at boot and are restarted if they stop.
- Firewall: pf rules allow only the master and the nodes on the cluster ports; the console port only on
  the master.
- Remote access: SSH keys only; password sign-in off for SSH.
- Updates: automatic macOS updates off; ProVigil applies tested updates from the console.
- Disk encryption: see open question 1.

## 7. Phases

| # | Phase | Needs a Mac | Effort |
|---|---|---|---|
| N1 | ARM images of siem-api, ndr-engine, provigil-auth, ndr-ui (multi-arch release) | no (test needs one) | 1 week |
| N2 | Join token, node registry, heartbeats, mTLS, Nodes page | no (test on PCs) | 1–2 weeks |
| N3 | AI nodes share work (least busy, failover, queue) | no | 1 week |
| N4 | Data lake shards and copies, Keeper of three, backups for Small | no (test with Docker) | 1–2 weeks |
| N5 | macOS installer: master and data lake (Colima), AI node (Ollama), launchd, pf, pmset | yes | 1–2 weeks |
| N6 | macOS sensor: Zeek and Suricata on the capture port, sending to the master's NDR engine | yes, and a mirror port | 1 week |
| N7 | Live test: Small on 3 Macs, then node failure tests (AI node off, data lake node off) | 3 Macs | 1 week |
| N8 | The same roles on Ubuntu x86 (Linux installer already has the roles) | no | 1 week |

## 8. Open questions for the owner

1. **FileVault versus unattended start.** With FileVault on, a Mac waits for a password after a power
   cut, so the appliance does not come back alone. Choices: FileVault off and the ClickHouse data
   encrypted at rest instead; or FileVault on and an operator unlocks after outages.
2. **Small: one data lake node with backups, or two data lake nodes (copies)?**
3. **Sensor on the master box or always a separate sensor** for the Mac family?
4. **Default AI model** for AI nodes (size versus speed).

## 9. Research 2026-11-27: capacity and Mac risks

Capacity (Small, 2,000 events/s):
- Measured: 2,500 events/s with no loss on the dev PC (ClickHouse limited to 5 GB). Rules engine 13,000
  events/s on one thread, 31,000 with workers. A Mac master (VM with about 14 cores) is expected to
  carry 5,000-10,000 events/s for the SIEM; to be measured.
- Storage: 2,000 events/s is about 173 million events a day, about 140 GB raw, 15-30 GB in ClickHouse
  after compression: 8 TB holds roughly 9-18 months (NDR data on top).
- Adding AI or data lake nodes does not raise the events/s the system takes in: the master takes in
  everything. Past the master's limit a fourth role is needed: **worker nodes** (gateway + rules engine,
  `provigil-cluster.md` phases C1-C2).
- AI runs on alerts, cases and questions, not on every event (2,000 model calls a second is not
  possible on any hardware). Measured by others: gpt-oss-20b on an M4 Max Mac Studio with Ollama about
  81 tokens/s for one request, about 20 tokens/s each with 8 at once (about 160 in total): a case
  summary takes seconds; more AI nodes add capacity more than more parallel requests per node.

Mac risks to test first (none blocks the plan; each has a fallback):
1. Colima at boot without sign-in: not official; `colima start --foreground` under a launchd daemon
   (community setups). Fallback: auto sign-in of a service user.
2. Agent connections through the VM: Colima's default port forwarding may not carry thousands of
   connections; use a VM address on the network (`--network-address`). Test with the load generator.
3. ClickHouse in the VM: no published Mac benchmarks; data on the VM's own disk (not a shared folder).
   Test with the load generator.
4. Capture on macOS (BPF): no published 10 GbE figures; Apple's libpcap writes pcapng (a Zeek reading
   issue was reported). Plan for about 1 Gbps; test with a traffic generator.
5. Ollama parallel requests on Mac: the newer MLX runner was reported to handle requests one at a time
   even with OLLAMA_NUM_PARALLEL; check the server log, measure.
6. FileVault blocks unattended start (open question 1); no ECC, RAID or remote power: data lake copies
   and backups matter more than on servers.
7. Build: no x86-only code found (ring and rdkafka build on ARM). The siem-api image cross-builds the
   Windows agent: keep that stage on x86 and copy the result into the ARM image. Building ARM images
   under emulation on an x86 PC is slow (hours): build them on the Mac itself or an ARM build machine.

Order decided: N2 (join, Nodes page) and N3 (AI sharing) first, they need no hardware; N8 (Ubuntu) next,
it is the lowest-risk platform; N1 (ARM images) on the Mac when it arrives, then N5-N7.

## 10. Three product lines (owner decision 2026-11-27)

| Line | Master | AI nodes | Data lake nodes |
|---|---|---|---|
| A. Full Mac | Mac Studio (Linux VM; sensor on macOS with a TAP box beside it, about 1 Gbps) | Mac Studio (Ollama on macOS) | Mac Studio (ClickHouse in the Linux VM) |
| B. Hybrid | Linux x86 server (ProVigil OS, TAP or bypass card inside, full-speed sensor, no VM) | Mac Studio | Mac Studio |
| C. Full Linux | Linux x86 server | Linux x86 server with NVIDIA GPU | Linux x86 server |

- One design for all three: a node joins with a token whatever it runs on; the master does not care
  whether an AI node is a Mac or an NVIDIA server (both answer the same OpenAI-style API), and
  ClickHouse replicas may be on Linux servers and Mac VMs in the same cluster (data parts do not
  depend on the processor; to be confirmed in the N7 test).
- Line B removes the Mac's weakest parts from the master (VM networking for thousands of agents,
  capture speed, start without sign-in) and keeps the Mac where it is strongest (AI). The data lake on
  a Mac keeps risk 3 (ClickHouse in the VM, to be load-tested); a Linux data lake node can be mixed in.
- Linux on the Mac Studio itself is not possible (Asahi Linux has no M4 installer or GPU driver as of
  August 2026), so a Mac node always runs macOS, with the Linux VM where Linux is needed.
- ProVigil OS for x86: an Ubuntu-based installer image (USB) that installs Ubuntu and ProVigil and
  asks only the role and the licence; supports TAP or bypass network cards on the master.
