//! The stand-ins of `tests/stub` as a process, for benches with `provigil-loadtest`: the engine and
//! provigil-db at `PROVIGIL_MANAGER_HOME`, siem-api's internal API on a random port, a test CA.
//!   CLICKHOUSE_URL=... AGENT_KEYS_SECRET=... PROVIGIL_MANAGER_HOME=... GATEWAY_CA_DIR=... stub_manager <tenant> <tenant key>
//! Prints `api <url>` and keeps running.

#[path = "../tests/stub/mod.rs"]
mod stub;

#[tokio::main]
async fn main() {
    let env = |k: &str| std::env::var(k).unwrap_or_else(|_| panic!("{k}"));
    let mut a = std::env::args().skip(1);
    let (tenant, key) = (a.next().expect("tenant"), a.next().expect("tenant key"));
    // a test CA for the gateway to read, as siem-api makes the install's
    let dir = std::path::PathBuf::from(env("GATEWAY_CA_DIR"));
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let ca = provigil_agent_server::tls::named_ca_params(provigil_agent_server::tls::CA_CN).self_signed(&ca_key).unwrap();
    std::fs::write(dir.join("ca.key.pem"), ca_key.serialize_pem()).unwrap();
    std::fs::write(dir.join("ca.crt.pem"), ca.pem()).unwrap();
    let db = stub::prepare(&env("CLICKHOUSE_URL")).await;
    stub::add_tenant(&db, &tenant, &key, 1).await;
    let s = std::sync::Arc::new(stub::Stub::default());
    s.start_sockets(std::path::Path::new(&env("PROVIGIL_MANAGER_HOME"))).await;
    let url = s.start_api(db, &env("AGENT_KEYS_SECRET"), [(key, tenant)].into_iter().collect()).await;
    println!("api {url}");
    std::future::pending::<()>().await;
}
