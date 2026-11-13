//! The message router (spec M-2): one listener per topic at `queue/router/<topic>` (port file on
//! Windows). Frames are `[u32 size][u32 header size][header][body]`, little endian, `size`
//! counting what follows it. A frame with header `P` publishes its body; one without a header
//! registers a remote subscriber (`{"subscriberId":..}`, answered `{"Result":"OK"}`), which then
//! gets every message of the topic on that connection. The registration socket
//! `queue/router/subscription.sock` takes `{"MessageType":"InitProvider","EndpointName":..}` (opens
//! a topic) and `{"MessageType":"RemoveSubscriber","EndpointName":..,"SubscriberId":..}`.
//! Messages reach the subscribers in this process through a queue, in order, one thread per topic.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};

use provigil_daemon::Log;
use provigil_ipc::local::{self, Stream};
use serde_json::{json, Value};

pub const TAG: &str = "provigil-modulesd:router";
const SUBSCRIPTION_SOCKET: &str = "subscription.sock";
/// The largest frame a client may send.
const MAX_FRAME: usize = 1 << 24;

type Callback = Arc<dyn Fn(&[u8]) + Send + Sync>;

/// One frame: `[u32 size][u32 header size][header][body]`.
pub fn frame(header: &[u8], body: &[u8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(8 + header.len() + body.len());
    b.extend_from_slice(&((4 + header.len() + body.len()) as u32).to_le_bytes());
    b.extend_from_slice(&(header.len() as u32).to_le_bytes());
    b.extend_from_slice(header);
    b.extend_from_slice(body);
    b
}

/// Reads one frame: (header, body); None when the peer closed or sent something unusable.
fn read_frame(s: &mut Stream) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut n = [0u8; 4];
    s.read_exact(&mut n).ok()?;
    let total = u32::from_le_bytes(n) as usize;
    if total > MAX_FRAME {
        return None;
    }
    let mut buf = vec![0u8; total];
    s.read_exact(&mut buf).ok()?;
    if total < 4 {
        return Some((Vec::new(), Vec::new()));
    }
    let hs = (u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize).min(total - 4);
    Some((buf[4..4 + hs].to_vec(), buf[4 + hs..].to_vec()))
}

#[derive(Default)]
struct Topic {
    local: Vec<(String, Callback)>,
    remote: Vec<(String, Stream)>,
    queue: Option<Sender<Vec<u8>>>,
}

pub struct Router {
    dir: PathBuf,
    log: Arc<Log>,
    topics: Mutex<HashMap<String, Arc<Mutex<Topic>>>>,
}

impl Router {
    /// A router serving `home/queue/router/`.
    pub fn new(home: &Path, log: Arc<Log>) -> Arc<Router> {
        Arc::new(Router { dir: home.join("queue/router"), log, topics: Mutex::new(HashMap::new()) })
    }

    /// Opens the registration socket.
    pub fn start(self: &Arc<Router>) -> std::io::Result<()> {
        let l = local::bind(&self.dir.join(SUBSCRIPTION_SOCKET))?;
        let me = self.clone();
        std::thread::Builder::new().name("router-registration".into()).spawn(move || {
            for s in l.incoming().flatten() {
                let me = me.clone();
                let _ = std::thread::Builder::new().name("router-registration-client".into()).spawn(move || me.registration_client(s));
            }
        })?;
        Ok(())
    }

    fn registration_client(&self, mut s: Stream) {
        while let Some((_, body)) = read_frame(&mut s) {
            let Ok(m) = serde_json::from_slice::<Value>(&body) else { return };
            let text = |k: &str| m.get(k).and_then(Value::as_str).map(str::to_string);
            let result = match text("MessageType").as_deref() {
                Some("InitProvider") => match text("EndpointName") {
                    Some(name) => self.topic(&name).map(|_| ()).map_err(|e| e.to_string()),
                    None => return,
                },
                Some("RemoveSubscriber") => match (text("EndpointName"), text("SubscriberId")) {
                    (Some(name), Some(id)) => self.remove_subscriber(&name, &id),
                    _ => return,
                },
                Some(_) => Err("Invalid message type".to_string()),
                None => return,
            };
            let answer = json!({ "Result": result.err().unwrap_or_else(|| "OK".into()) }).to_string();
            if s.write_all(&frame(b"", answer.as_bytes())).is_err() {
                return;
            }
        }
    }

    /// The topic, its listener opened on first use.
    fn topic(self: &Router, name: &str) -> std::io::Result<Arc<Mutex<Topic>>> {
        let mut topics = self.topics.lock().unwrap();
        if let Some(t) = topics.get(name) {
            return Ok(t.clone());
        }
        let topic = Arc::new(Mutex::new(Topic::default()));
        let listener = local::bind(&self.dir.join(name))?;
        // deliveries run on their own thread, in arrival order
        let (tx, rx) = channel::<Vec<u8>>();
        topic.lock().unwrap().queue = Some(tx);
        let t = topic.clone();
        let tag = name.to_string();
        std::thread::Builder::new().name(format!("router-{tag}")).spawn(move || {
            for msg in rx {
                deliver(&t, &msg);
            }
        })?;
        let t = topic.clone();
        let log = self.log.clone();
        std::thread::Builder::new().name(format!("router-listen-{name}")).spawn(move || {
            for s in listener.incoming().flatten() {
                let (t, log, tag) = (t.clone(), log.clone(), tag.clone());
                let _ = std::thread::Builder::new().name("router-client".into()).spawn(move || client(t, s, &log, &tag));
            }
        })?;
        topics.insert(name.to_string(), topic.clone());
        Ok(topic)
    }

    /// Delivers the topic's messages to `cb` in this process.
    pub fn subscribe(&self, topic: &str, id: &str, cb: Callback) -> Result<(), String> {
        let t = self.topic(topic).map_err(|e| format!("Couldn't open the topic '{topic}': {e}"))?;
        t.lock().unwrap().local.push((id.to_string(), cb));
        Ok(())
    }

    fn remove_subscriber(&self, topic: &str, id: &str) -> Result<(), String> {
        let topics = self.topics.lock().unwrap();
        let Some(t) = topics.get(topic) else { return Err(format!("Provider not exist: {topic}")) };
        let mut t = t.lock().unwrap();
        t.local.retain(|(i, _)| i != id);
        t.remote.retain(|(i, _)| i != id);
        Ok(())
    }

    /// Publishes from this process.
    pub fn publish(&self, topic: &str, body: &[u8]) {
        if let Some(t) = self.topics.lock().unwrap().get(topic) {
            if let Some(q) = &t.lock().unwrap().queue {
                let _ = q.send(body.to_vec());
            }
        }
    }
}

/// One connection to a topic: publishers' frames are queued; a subscription request makes it a
/// remote subscriber.
fn client(topic: Arc<Mutex<Topic>>, mut s: Stream, log: &Log, name: &str) {
    while let Some((header, body)) = read_frame(&mut s) {
        if header == b"P" {
            if let Some(q) = &topic.lock().unwrap().queue {
                let _ = q.send(body);
            }
        } else if header.is_empty() {
            let id = serde_json::from_slice::<Value>(&body).ok().and_then(|v| v.get("subscriberId").and_then(Value::as_str).map(str::to_string));
            let Some(id) = id else { return };
            let Ok(out) = local::try_clone(&s) else { return };
            // added before the answer, so nothing published after the answer is missed
            topic.lock().unwrap().remote.push((id.clone(), out));
            if s.write_all(&frame(b"", br#"{"Result":"OK"}"#)).is_err() {
                return;
            }
            log.tagged(TAG, "DEBUG", format!("Remote subscriber '{id}' added to '{name}'."));
        }
    }
}

fn deliver(topic: &Arc<Mutex<Topic>>, msg: &[u8]) {
    let (local, mut remote) = {
        let mut t = topic.lock().unwrap();
        (t.local.clone(), std::mem::take(&mut t.remote))
    };
    for (_, cb) in &local {
        cb(msg);
    }
    // a remote subscriber that cannot be written to is dropped
    remote.retain_mut(|(_, s)| s.write_all(&frame(b"", msg)).is_ok());
    let mut t = topic.lock().unwrap();
    remote.append(&mut t.remote);
    t.remote = remote;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn connect(home: &Path, topic: &str) -> Stream {
        local::connect(&home.join("queue/router").join(topic)).unwrap()
    }

    #[test]
    fn publish_subscribe_and_registration() {
        let home = tempfile::tempdir().unwrap();
        let r = Router::new(home.path(), Arc::new(Log::null()));
        r.start().unwrap();
        let got: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
        let g = got.clone();
        r.subscribe("wdb-agent-events", "scanner", Arc::new(move |m: &[u8]| g.lock().unwrap().push(m.to_vec()))).unwrap();

        // a remote subscriber of the same topic
        let mut sub = connect(home.path(), "wdb-agent-events");
        sub.write_all(&frame(b"", br#"{"subscriberId":"far"}"#)).unwrap();
        assert_eq!(read_frame(&mut sub).unwrap().1, br#"{"Result":"OK"}"#);

        // two publishes on one connection, in order
        let mut p = connect(home.path(), "wdb-agent-events");
        p.write_all(&frame(b"P", br#"{"n":1}"#)).unwrap();
        p.write_all(&frame(b"P", br#"{"n":2}"#)).unwrap();
        sub.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        assert_eq!(read_frame(&mut sub).unwrap().1, br#"{"n":1}"#);
        assert_eq!(read_frame(&mut sub).unwrap().1, br#"{"n":2}"#);
        assert_eq!(*got.lock().unwrap(), vec![br#"{"n":1}"#.to_vec(), br#"{"n":2}"#.to_vec()]);

        // the registration socket opens a topic and removes subscribers
        let mut reg = local::connect(&home.path().join("queue/router/subscription.sock")).unwrap();
        reg.write_all(&frame(b"", br#"{"MessageType":"InitProvider","EndpointName":"other"}"#)).unwrap();
        assert_eq!(read_frame(&mut reg).unwrap().1, br#"{"Result":"OK"}"#);
        assert!(local::connect(&home.path().join("queue/router/other")).is_ok());
        reg.write_all(&frame(b"", br#"{"MessageType":"RemoveSubscriber","EndpointName":"wdb-agent-events","SubscriberId":"scanner"}"#)).unwrap();
        assert_eq!(read_frame(&mut reg).unwrap().1, br#"{"Result":"OK"}"#);
        reg.write_all(&frame(b"", br#"{"MessageType":"Nope"}"#)).unwrap();
        assert_eq!(read_frame(&mut reg).unwrap().1, br#"{"Result":"Invalid message type"}"#);
        p.write_all(&frame(b"P", br#"{"n":3}"#)).unwrap();
        assert_eq!(read_frame(&mut sub).unwrap().1, br#"{"n":3}"#);
        assert_eq!(got.lock().unwrap().len(), 2, "removed subscriber gets nothing more");
    }
}
