//! `provigil.agent.v1.AgentService`, the gRPC service between the ProVigil agent and the
//! manager API: the messages, the server trait and service, and the client. Events, commands,
//! results and configuration travel as the same JSON text the HTTPS routes carry.

// tonic::Status is the service's error type, as in tonic's own generated code
#![allow(clippy::result_large_err)]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tonic::codec::ProstCodec;
use tonic::codegen::{http, tokio_stream::Stream, Body, BoxFuture, StdError};
use tonic::server::{Grpc, NamedService, ServerStreamingService, UnaryService};
use tonic::transport::Channel;
use tonic::{Request, Response, Status, Streaming};

pub const SERVICE: &str = "provigil.agent.v1.AgentService";
const ENROLL: &str = "/provigil.agent.v1.AgentService/Enroll";
const KEEPALIVE: &str = "/provigil.agent.v1.AgentService/Keepalive";
const EVENTS: &str = "/provigil.agent.v1.AgentService/Events";
const RESULT: &str = "/provigil.agent.v1.AgentService/Result";
const CONFIG: &str = "/provigil.agent.v1.AgentService/Config";
const YARA: &str = "/provigil.agent.v1.AgentService/Yara";
const UPGRADE: &str = "/provigil.agent.v1.AgentService/Upgrade";

#[derive(Clone, PartialEq, prost::Message)]
pub struct EnrollRequest {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub os_type: String,
    #[prost(string, tag = "3")]
    pub groups: String,
    #[prost(bool, tag = "4")]
    pub force: bool,
    #[prost(string, tag = "5")]
    pub hostname: String,
    #[prost(string, tag = "6")]
    pub version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EnrollReply {
    #[prost(string, tag = "1")]
    pub agent_id: String,
    #[prost(string, tag = "2")]
    pub agent_name: String,
    #[prost(string, tag = "3")]
    pub agent_ip: String,
    #[prost(string, tag = "4")]
    pub raw_key: String,
    #[prost(string, tag = "5")]
    pub tenant_id: String,
    #[prost(string, tag = "6")]
    pub groups: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct KeepaliveRequest {
    #[prost(string, tag = "1")]
    pub body_json: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct KeepaliveReply {
    #[prost(string, repeated, tag = "1")]
    pub commands_json: Vec<String>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EventsRequest {
    #[prost(string, repeated, tag = "1")]
    pub events_json: Vec<String>,
    /// The same for a batch sent again: the manager takes it once.
    #[prost(string, tag = "2")]
    pub batch_id: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct EventsReply {
    #[prost(uint32, tag = "1")]
    pub accepted: u32,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ResultRequest {
    #[prost(string, tag = "1")]
    pub result_json: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Empty {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct ConfigReply {
    #[prost(string, tag = "1")]
    pub version: String,
    #[prost(string, tag = "2")]
    pub config_json: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct YaraRequest {}

#[derive(Clone, PartialEq, prost::Message)]
pub struct YaraReply {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct UpgradeChunkRequest {
    #[prost(string, tag = "1")]
    pub version: String,
}

#[derive(Clone, PartialEq, prost::Message)]
pub struct Chunk {
    #[prost(bytes = "vec", tag = "1")]
    pub data: Vec<u8>,
}

/// The published agent package, in chunks.
pub type ChunkStream = Pin<Box<dyn Stream<Item = Result<Chunk, Status>> + Send>>;

/// The manager's side of the service.
#[tonic::async_trait]
pub trait AgentService: Send + Sync + 'static {
    async fn enroll(&self, r: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status>;
    async fn keepalive(&self, r: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status>;
    async fn events(&self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status>;
    async fn result(&self, r: Request<ResultRequest>) -> Result<Response<Empty>, Status>;
    async fn config(&self, r: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status>;
    async fn yara(&self, r: Request<YaraRequest>) -> Result<Response<YaraReply>, Status>;
    async fn upgrade(&self, r: Request<UpgradeChunkRequest>) -> Result<Response<ChunkStream>, Status>;
}

/// [`AgentService`] as a tonic service (`Server::add_service`).
pub struct AgentServiceServer<T> {
    inner: Arc<T>,
    max_decoding: Option<usize>,
    max_encoding: Option<usize>,
}

impl<T> Clone for AgentServiceServer<T> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), max_decoding: self.max_decoding, max_encoding: self.max_encoding }
    }
}

impl<T: AgentService> AgentServiceServer<T> {
    pub fn new(inner: T) -> Self {
        Self { inner: Arc::new(inner), max_decoding: None, max_encoding: None }
    }

    pub fn max_decoding_message_size(mut self, n: usize) -> Self {
        self.max_decoding = Some(n);
        self
    }

    pub fn max_encoding_message_size(mut self, n: usize) -> Self {
        self.max_encoding = Some(n);
        self
    }
}

impl<T> NamedService for AgentServiceServer<T> {
    const NAME: &'static str = SERVICE;
}

/// One unary method: the closure calls the trait.
struct Unary<F>(F);

impl<Q, A, F, Fut> UnaryService<Q> for Unary<F>
where
    F: FnMut(Request<Q>) -> Fut,
    Fut: Future<Output = Result<Response<A>, Status>>,
{
    type Response = A;
    type Future = Fut;
    fn call(&mut self, r: Request<Q>) -> Fut {
        (self.0)(r)
    }
}

struct Upgrade<T>(Arc<T>);

impl<T: AgentService> ServerStreamingService<UpgradeChunkRequest> for Upgrade<T> {
    type Response = Chunk;
    type ResponseStream = ChunkStream;
    type Future = BoxFuture<Response<ChunkStream>, Status>;
    fn call(&mut self, r: Request<UpgradeChunkRequest>) -> Self::Future {
        let s = self.0.clone();
        Box::pin(async move { s.upgrade(r).await })
    }
}

impl<T, B> tonic::codegen::Service<http::Request<B>> for AgentServiceServer<T>
where
    T: AgentService,
    B: Body + Send + 'static,
    B::Error: Into<StdError> + Send + 'static,
{
    type Response = http::Response<tonic::body::BoxBody>;
    type Error = std::convert::Infallible;
    type Future = BoxFuture<Self::Response, Self::Error>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: http::Request<B>) -> Self::Future {
        let (s, dec, enc) = (self.inner.clone(), self.max_decoding, self.max_encoding);
        macro_rules! unary {
            ($m:ident) => {
                Box::pin(async move {
                    let mut g = Grpc::new(ProstCodec::default()).apply_max_message_size_config(dec, enc);
                    let call = move |r| {
                        let s = s.clone();
                        async move { s.$m(r).await }
                    };
                    Ok(g.unary(Unary(call), req).await)
                })
            };
        }
        match req.uri().path() {
            ENROLL => unary!(enroll),
            KEEPALIVE => unary!(keepalive),
            EVENTS => unary!(events),
            RESULT => unary!(result),
            CONFIG => unary!(config),
            YARA => unary!(yara),
            UPGRADE => Box::pin(async move {
                let mut g = Grpc::new(ProstCodec::default()).apply_max_message_size_config(dec, enc);
                Ok(g.server_streaming(Upgrade(s), req).await)
            }),
            _ => Box::pin(async move { Ok(Status::unimplemented("").into_http()) }),
        }
    }
}

/// The agent's side of the service.
#[derive(Clone)]
pub struct AgentServiceClient {
    inner: tonic::client::Grpc<Channel>,
}

impl AgentServiceClient {
    pub fn new(channel: Channel) -> Self {
        Self { inner: tonic::client::Grpc::new(channel) }
    }

    pub fn max_decoding_message_size(mut self, n: usize) -> Self {
        self.inner = self.inner.max_decoding_message_size(n);
        self
    }

    pub fn max_encoding_message_size(mut self, n: usize) -> Self {
        self.inner = self.inner.max_encoding_message_size(n);
        self
    }

    async fn unary<Q, A>(&mut self, r: Request<Q>, path: &'static str) -> Result<Response<A>, Status>
    where
        Q: prost::Message + Send + Sync + 'static,
        A: prost::Message + Default + Send + Sync + 'static,
    {
        self.inner.ready().await.map_err(|e| Status::unavailable(e.to_string()))?;
        self.inner.unary(r, http::uri::PathAndQuery::from_static(path), ProstCodec::default()).await
    }

    pub async fn enroll(&mut self, r: Request<EnrollRequest>) -> Result<Response<EnrollReply>, Status> {
        self.unary(r, ENROLL).await
    }

    pub async fn keepalive(&mut self, r: Request<KeepaliveRequest>) -> Result<Response<KeepaliveReply>, Status> {
        self.unary(r, KEEPALIVE).await
    }

    pub async fn events(&mut self, r: Request<EventsRequest>) -> Result<Response<EventsReply>, Status> {
        self.unary(r, EVENTS).await
    }

    pub async fn result(&mut self, r: Request<ResultRequest>) -> Result<Response<Empty>, Status> {
        self.unary(r, RESULT).await
    }

    pub async fn config(&mut self, r: Request<ConfigRequest>) -> Result<Response<ConfigReply>, Status> {
        self.unary(r, CONFIG).await
    }

    pub async fn yara(&mut self, r: Request<YaraRequest>) -> Result<Response<YaraReply>, Status> {
        self.unary(r, YARA).await
    }

    pub async fn upgrade(&mut self, r: Request<UpgradeChunkRequest>) -> Result<Response<Streaming<Chunk>>, Status> {
        self.inner.ready().await.map_err(|e| Status::unavailable(e.to_string()))?;
        self.inner.server_streaming(r, http::uri::PathAndQuery::from_static(UPGRADE), ProstCodec::default()).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use prost::Message;

    fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug>(m: M) {
        assert_eq!(M::decode(m.encode_to_vec().as_slice()).unwrap(), m);
    }

    #[test]
    fn messages_round_trip() {
        round_trip(EnrollRequest { name: "pc".into(), os_type: "windows".into(), groups: "a,b".into(), force: true, hostname: "PC".into(), version: "1.0.0".into() });
        round_trip(EnrollReply { agent_id: "001".into(), agent_name: "pc".into(), agent_ip: "any".into(), raw_key: "k".into(), tenant_id: "t".into(), groups: "default".into() });
        round_trip(KeepaliveRequest { body_json: r#"{"status":"active"}"#.into() });
        round_trip(KeepaliveReply { commands_json: vec!["{}".into(), r#"{"type":"scan"}"#.into()] });
        round_trip(EventsRequest { events_json: vec![r#"{"event_type":"fim"}"#.into()], batch_id: "b-1".into() });
        round_trip(EventsReply { accepted: 7 });
        round_trip(ResultRequest { result_json: r#"{"status":"done"}"#.into() });
        round_trip(Empty {});
        round_trip(ConfigRequest {});
        round_trip(ConfigReply { version: "ab12".into(), config_json: "{}".into() });
        round_trip(YaraRequest {});
        round_trip(YaraReply { data: vec![0, 1, 255] });
        round_trip(UpgradeChunkRequest { version: "9.9.9".into() });
        round_trip(Chunk { data: vec![7; 1000] });
        // an empty message is no bytes, and unknown fields of a newer peer are skipped
        assert!(Empty {}.encode_to_vec().is_empty());
        assert_eq!(Empty::decode(EventsReply { accepted: 3 }.encode_to_vec().as_slice()).unwrap(), Empty {});
    }
}
