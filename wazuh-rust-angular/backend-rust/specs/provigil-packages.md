# ProVigil packages: one installer, the licence picks the modules, the role picks the PC's job

Written 2026-11-24 (owner: "one install ... if I need only NDR it must include the NDR module and
its pages ... make it an MSI package ... download only that ... and the three-PC plan").

## 1. Goals

- **One installer per operating system**, the same file for every customer and every version's
  customers. The customer's **licence** decides which modules are set up and which console pages
  show. Nothing is compiled per customer.
- **Two ways to get the parts:** online (a small installer downloads only the licensed parts) and
  offline (one zip with the installer, the parts and the licence, for sites without internet).
- **Every part is signed** with ProVigil's licence key (`provigil-license sign`); a changed part does
  not install.
- **Roles for the three-PC plan:** the installer asks what this PC is: all-in-one, master, data
  lake, or AI node. The licence goes to the master only.

## 2. Which package for which customer

| Customer bought | Master package | Why |
| --- | --- | --- |
| SIEM (± SOAR, threat intel, AI) | `ProVigil-Setup.msi` (Windows) or `provigil-install.sh` (Ubuntu) | the SIEM runs on both |
| NDR only | `provigil-install.sh` (Ubuntu) | NDR needs Linux: packet capture (Zeek, Suricata), Kafka |
| NDR + SIEM | `provigil-install.sh` (Ubuntu) | as above, every module |

The data lake and the AI node are Ubuntu in every case (`install-datalake.sh`, `install-ainode.sh`,
already built), now started from the same installer as a role.

## 3. Parts (built and signed once per release)

| Part | Contains | Needed for |
| --- | --- | --- |
| `core` | sign-in service, siem-api (platform server), console, Valkey | always |
| `siem` | gateway, the analysis services, agent kit, Sigma and rules data | `siem` |
| `ndr` | ndr-engine, Kafka, Vector, sensor kit | `ndr` |
| `datalake` | ClickHouse setup, schema, backups | data lake role (or all-in-one) |
| `ainode` | model server setup | AI node role (optional, `ai`) |

SOAR, threat intel and AI are inside `core` and `siem`: the licence turns them on; they need no
files of their own. On Linux a part is a set of Docker images (pulled only when licensed); on
Windows a part is a signed zip of programs and data.

## 4. Where parts are downloaded from

Now: **GitHub, NDR-Demo** (owner, 2026-11-24; to change later, each is one setting):

| What | From | Setting |
| --- | --- | --- |
| `provigil-install.sh`, `provigil-kit-<v>.tar.gz`, their `.sig`, offline `images-*.tar.gz` | GitHub Releases of NDR-Demo | `PROVIGIL_DOWNLOAD_URL` (releases API address); `PROVIGIL_DOWNLOAD_TOKEN` while it is private |
| ProVigil's images online (`provigil-auth`, `siem-api`, `ndr-ui`, `ndr-engine`) | GitHub's registry (GHCR), pushed by `release.sh` | `PROVIGIL_REGISTRY`; the registry token |
| Other images online (ClickHouse, Kafka, nginx, ...) | Docker Hub | none |

NDR-Demo is private today, so customers get a read-only download token from ProVigil. The private
source repository is never a download place.

## 5. The flow

```
Super admin: Tenants -> Licensed Features -> License -> Generate -> [Download installer]
  online : licence text + the installer link
  offline: ProVigil-<customer>.zip = installer + licence.jwt + the licensed parts + README.txt

Customer, PC by PC:
  data lake PC : installer, role "data lake"  -> prints CLICKHOUSE_URL/USER/PASSWORD
  AI node PC   : installer, role "AI node"    -> prints the model server address (optional)
  master PC    : installer, role "master"     -> licence, data lake address and password,
                 AI node address -> installs core + the licensed parts -> console opens
  small site   : installer, role "all-in-one" -> the three on one PC
```

The master checks the data lake and AI node before it finishes (the checks of
`connect-master.ps1`), creates the client's admin account at first start, and sets the AI node as
the first AI provider (`local-ai`).

**Adding a module later:** a new licence, then the installer again with role master: it adds only
the missing parts. **Updates:** the same parts, newer version, checked by signature.

## 6. Steps

Built 2026-11-24: steps 1, 2 and 4 (Linux). `ndr/provigil-install.sh` (roles, licence and kit
signatures, data lake check), `ndr/install-customer.sh` (only the licensed images and services;
external data lake; offline images), `ndr/release-kit.sh` (kit, signatures, offline parts,
customer zip, upload), nginx starts without absent modules (`resolve`), the data lake also loads the
NDR schema, and the console's Licence window has **Download installer** (`POST /api/license/installer`:
licence.jwt + install.sh + README). Tested in Ubuntu containers: good kit and licence pass; a
changed kit, a forged licence, a changed installer and a key-less copy are refused; the master
reaches a real ClickHouse data lake and installs only the licensed modules.

1. Linux installer from the licence: reads the modules, pulls only their images; roles; online
   and offline (zip).
2. Release step: build, sign and upload the parts and `parts.json` to the download place.
3. Windows MSI (WiX): roles master and all-in-one (data lake must then be a Linux PC or the local
   Docker ClickHouse), Windows services, licence from file or pasted, both ways.
4. Console: "Download installer" on the Licence window (online text, offline zip).

Built 2026-11-24: step 3 (Windows MSI), `packaging/windows/`:

- `build-msi.ps1 -PublicKey public.pem [-Key private.pem] [-Version X.Y.Z]`: release build in
  `target\msi` (ProVigil's public key built in; the dev `target\release` is not touched), the
  console (`ng build`), Caddy 2.8.4 checked against its published SHA-512, the stage folder, then
  `ProVigil-Setup-<v>.msi` with WiX 5.0.2 (a local dotnet tool: `dotnet tool restore`; WiX 6 has a
  paid maintenance-fee licence) and its `.sig`. `release-kit.sh --msi` publishes it with the release
  and puts it in customer zips.
- The MSI: programs in `Program Files\ProVigil` (bin, console, ruleset), data and settings in
  `ProgramData\ProVigil`; four Windows services through `provigil-service.exe` (crate
  `provigil-service`: ProVigilAuth, ProVigilSiemApi, ProVigilGateway, ProVigilConsole; a program
  that ends is started again, 5 s doubling to 60 s); firewall rules (443, 80, 8089, 8443, 514/udp,
  601, 6514, 9201); a settings dialog (data lake address, user, password, session store, licence
  file). Its `configure` step writes `provigil.env` (secrets made once and kept by upgrades; the
  file readable by SYSTEM and administrators only) and checks the licence against the built-in key:
  a bad licence stops the install. Silent install: `msiexec /i ProVigil-Setup-<v>.msi /qn
  DATALAKE_URL=... DATALAKE_PASSWORD=... VALKEY_URL=...`.
- The console: Caddy with `packaging/windows/Caddyfile` and the shared `caddy/routes.caddy`
  (also used by the Docker Caddy), certificates from Caddy's own CA issued on demand for whatever
  name or address users type; `HTTPS_PORT` / `HTTP_PORT` in `provigil.env` when IIS holds 443/80
  (then open that port in the firewall too).
- Windows has no ClickHouse or Valkey: the Windows master always uses a Linux data lake, installed
  with `--with-valkey` (provigil-install.sh asks), which adds a password-protected session store
  open to the master only.
- Tested: the MSI builds and unpacks with the right layout; its `provigil-service configure`
  accepts a good licence and refuses a forged one with the built-in key; its console service serves
  the built console and reaches sign-in and siem-api; the session store setup on Ubuntu 24.04
  refuses connections without the password. Not yet tested: a real install on a clean Windows PC
  (services, firewall, upgrade) — this PC runs the dev services on the same ports.

Fixed 2026-11-24: the Linux (Docker) master had no agents' gateway and no manager programs, so
ProVigil agents could not connect (the MSI had them). The siem-api image
(`docker/siem-api.Dockerfile`) now carries the same set as the MSI: siem-api, provigil-gateway,
the manager programs (provigil-db, analysisd, modulesd, execd, agentlessd, firewall-drop), the
default ruleset (`PROVIGIL_SOURCE_DIR=/app/ruleset-src`), and the agent package (Linux agents from
git, the Windows agent's programs cross-built in the image). `docker/siem-api-start.sh` runs the
gateway beside siem-api in the same container (they talk over 127.0.0.1, as on Windows), started
once siem-api has made the agents' CA; when either ends the container restarts. The installer
sets `PROVIGIL_MANAGER=1` when the licence has SIEM (NDR-only keeps siem-api's platform role
only). Ports 8089 (gRPC) and 8443 (enrollment, updates); the CA and the manager's home are
volumes (`siem-tls`, `siem-manager`), so agents keep trusting the master across upgrades. The old
ports 1514/1515 are not used.

Also fixed with it: the rules engine needs the `provigil` service user (the image makes it; the
manager's home is group provigil with set-group-ID folders, umask 002, so what the root programs
make there is the group's); `GATEWAY_INTERNAL_TOKEN` (made once by the installer and kept, as the
MSI does; without it enrollment through the gateway is off); `provigil-mitredb` and
`ruleset/mitre` (alerts' MITRE data; the MSI lacked them too); and provigil-db listened only on a
loopback TCP port (the Windows way) on Linux too, where the other programs look for the Unix
socket `queue/db/wdb`: it now uses provigil_ipc::local (Unix socket 0660 on Linux, port file on
Windows), also for its router link. Tested in the Ubuntu 24.04 install: 5 simulated agents
(provigil-loadtest, `grpcs://` with the CA from /api/server-info and the tenant key) enrolled,
880 events sent and 880 stored, alerts made by the rules engine, the agents active in the console.

## 7. Decisions (owner delegated)

- No per-customer build: a licence file next to the same installer, like every major vendor.
- Console pages are not removed from a package: the licence hides them and every server refuses
  unlicensed APIs, which is the real protection.
- The licence is installed on the master only; the data lake and AI node need none.
- Windows services through an own small service host (provigil-service), not a third-party
  wrapper; the console's web server is Caddy (one pinned, checksum-checked program).
