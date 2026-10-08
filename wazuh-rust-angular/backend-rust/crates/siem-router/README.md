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

Faithful details include the single dispatch thread per topic that ends
when a delivery fails (a remote subscriber that went away), and the
`Failed to set socket options` messages of unprivileged processes
(`SO_RCVBUFFORCE`).

Not ported yet: the flatbuffers schema adapter
(`router_provider_send_fb`, `router_provider_send_fb_json`).

## Verification

`tools/oracle/interop.sh <wazuh src> <router_tool example>` builds a tool on
Wazuh's real `routerFacade.cpp` and runs every combination of C++ and Rust
broker, provider and subscriber (`cargo build --example router_tool`).
