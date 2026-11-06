//! `provigil.agent.v1.AgentService`: each call the same as its HTTPS route. The gate has checked
//! the key before the message is decoded and left the agent in the request.

// tonic::Status is the service's error type
#![allow(clippy::result_large_err)]

use std::sync::Arc;

use provigil_agent_server::published;
use provigil_proto::*;
use serde_json::{json, Value};
use tonic::{Request, Response, Status};

use crate::agents::AgentRt;
use crate::cache::Authed;
use crate::core::{self, Gw, Refuse};
use crate::http::{file_chunks, grpc_status};
use crate::server::Conn;

pub struct Service(pub Arc<Gw>);

fn who<T>(r: &Request<T>) -> Result<(Authed, Arc<AgentRt>), Status> {
    let a = r.extensions().get::<Authed>().cloned();
    let rt = r.extensions().get::<Arc<AgentRt>>().cloned();
    a.zip(rt).ok_or_else(|| Status::unauthenticated("invalid agent key"))
}

fn refused(r: Refuse) -> Status {
    grpc_status(r.0, r.1)
}

#[tonic::async_trait]
impl AgentService for Service {
    async fn enroll(&self, r: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
        let tk = r.metadata().get("x-tenant-key").and_then(|v| v.to_str().ok()).unwrap_or_default().to_string();
        let peer = r.extensions().get::<Conn>().map(|c| c.peer.ip().to_string()).unwrap_or_default();
        let q = r.into_inner();
        let body = json!({ "name": q.name, "os_type": q.os_type, "groups": q.groups, "force": q.force, "hostname": q.hostname, "version": q.version });
        let v = core::enroll(&self.0, &body, &tk, &peer).await.map_err(|(code, msg)| grpc_status(code, &msg))?;
        let s = |k: &str| v[k].as_str().unwrap_or_default().to_string();
        Ok(Response::new(EnrollReply { agent_id: s("agent_id"), agent_name: s("agent_name"), agent_ip: s("agent_ip"), raw_key: s("raw_key"), tenant_id: s("tenant_id"), groups: s("groups") }))
    }

    async fn keepalive(&self, r: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
        let (a, rt) = who(&r)?;
        let commands_json = core::keepalive(&self.0, &a, &rt, r.get_ref().body_json.as_bytes()).map_err(refused)?;
        Ok(Response::new(KeepaliveReply { commands_json }))
    }

    async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
        let (a, rt) = who(&r)?;
        let q = r.into_inner();
        let items = q.events_json.iter().map(|e| serde_json::from_str::<Value>(e)).collect::<Result<Vec<_>, _>>().map_err(|e| Status::invalid_argument(e.to_string()))?;
        let accepted = core::events(&self.0, &a, &rt, &q.batch_id, items).await.map_err(refused)?;
        Ok(Response::new(EventsReply { accepted }))
    }

    async fn result(&self, r: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
        let (a, rt) = who(&r)?;
        let v: Value = serde_json::from_str(&r.get_ref().result_json).map_err(|e| Status::invalid_argument(e.to_string()))?;
        core::result(&self.0, &a, &rt, &v).map_err(refused)?;
        Ok(Response::new(Empty {}))
    }

    async fn config(&self, r: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
        let (a, _) = who(&r)?;
        let v = core::config(&self.0, &a).map_err(refused)?;
        Ok(Response::new(ConfigReply { version: v["version"].as_str().unwrap_or_default().to_string(), config_json: v["config"].to_string() }))
    }

    async fn yara(&self, r: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
        who(&r)?;
        let data = core::yara(&self.0).await.map_err(refused)?;
        Ok(Response::new(YaraReply { data }))
    }

    async fn upgrade(&self, r: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status> {
        use futures_util::StreamExt;
        who(&r)?;
        // the file's name comes in `x-file-name`: the agent program, or a response program
        let name = r.metadata().get("x-file-name").and_then(|v| v.to_str().ok()).unwrap_or(published::AGENT_EXE).to_string();
        let not_published = || Status::not_found(format!("{name} is not published"));
        let path = core::package_file(&self.0, &name, &r.get_ref().version).await.map_err(|e| if e.0 == 404 { not_published() } else { Status::failed_precondition(format!("the published agent is not version '{}'", r.get_ref().version)) })?;
        let file = tokio::fs::File::open(&path).await.map_err(|_| not_published())?;
        let chunks = file_chunks(file, ()).map(|c| c.map(|data| Chunk { data }).map_err(|e| Status::internal(e.to_string())));
        Ok(Response::new(Box::pin(chunks)))
    }
}
