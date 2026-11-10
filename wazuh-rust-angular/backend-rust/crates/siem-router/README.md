# siem-router

Port of Wazuh 4.14.7's router shared module (`src/shared_modules/router`)
and the utils socket layer it runs on (`socketWrapper.hpp`,
`socketServer.hpp`, `socketClient.hpp`, `epollWrapper.hpp`). Linux only.

* Broker (`router_start`, run by wazuh-modulesd): the registration server
  on `queue/router/subscription.sock` (`InitProvider`, `RemoveSubscriber`)
  and a publisher per topic on `queue/router/<topic>`.
* Remote providers (`router_provider_create(topic, false)`) register the
  topic, connect and push packets with the header `P`; remote subscribers
  register, connect and send `{"subscriberId":...,"type":"subscribe"}`.
* Framing: `[u32 packet size][u32 header size][header][body]`, little
  endian, non-blocking sockets with an unsent packet queue.
* Flatbuffers publications:
  * `router_provider_send_fb_json(handle, message, agent_ctx, msg_type)`
    is what remoted uses for syscollector deltas and rsync messages. It runs
    `SchemaAdapter` (`adapter.rs`, with a simdjson 3.13.0 DOM subset in
    `sjson.rs`), then a per-thread flatbuffers parser for each schema.
  * `router_provider_send_fb(handle, message, schema)` parses with a fresh
    parser.
  * `fb.rs` is the flatbuffers 23.5.26 parser and `FlatBufferBuilder`,
    including Wazuh's `zero_on_float_to_int` patch.
  * `schemas.rs` holds the schema texts, as the `*_schema.h` headers
    embed them.

Faithful details include:

* the single dispatch thread per topic, which ends when a delivery fails
  (a remote subscriber that went away);
* the `Failed to set socket options` messages of unprivileged processes
  (`SO_RCVBUFFORCE`);
* log messages cut at the first NUL, as `msg.c_str()` does;
* flatbuffers' error texts, schema warnings included, with line and
  column;
* numbers converted with the C library's `strtod`/`strtoll`.

The schema parser covers what Wazuh's schemas use and a little more:

* namespaces, tables, enums, unions of tables, scalars, strings;
* vectors of scalars, strings and tables;
* defaults, including `= null`;
* the attributes `deprecated`, `required`, `id` and `original_order`.

It refuses the following with a `siem-router:` error:

* structs, vectors of unions, string union members;
* includes and rpc services;
* the attributes that change the binary in ways not ported: `key`,
  `shared`, `hash`, `force_align`, `bit_flags`, `flexbuffer`,
  `nested_flatbuffer`, `offset64` and `vector64`.

## Verification

* `tools/oracle/interop.sh <wazuh src> <router_tool example>` builds a
  tool on Wazuh's real `routerFacade.cpp`. It runs every combination of C++
  and Rust broker, provider and subscriber (`cargo build --example
  router_tool`).
* `tools/oracle/fb_build.sh <wazuh src> <flatbuffers src> <simdjson src>`
  builds `~/fb_oracle/fb_oracle` from `fb_harness.cpp`. The harness holds
  router.cpp's two send functions verbatim over the real `SchemaAdapter`,
  flatbuffers and simdjson (deps/54 sources). `tests/fb_oracle.rs`
  compares logs, sent buffers and return values on a corpus and on seeded
  byte-level and structural mutations. Run it with
  `SIEM_FB_ORACLE=~/fb_oracle/fb_oracle`, plus optionally `SIEM_FB_FUZZ`,
  `SIEM_FB_SEED` and `SIEM_FB_KEEP`.
