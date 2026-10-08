//! Port of Wazuh's router (shared_modules/router): topics published by
//! providers and delivered to subscribers, locally or through the
//! `queue/router/` unix sockets.
//!
//! * [`socket`]: the utils socket layer (framing, epoll server/client).
//! * The broker side (`router_start`, run by wazuh-modulesd): the
//!   registration server on `queue/router/subscription.sock` and one
//!   [`Publisher`] per topic on `queue/router/<topic>`.
//! * Remote providers register the topic (`InitProvider`), connect to its
//!   publisher socket and push packets with the header `P`; remote
//!   subscribers register it too, connect and send
//!   `{"subscriberId":...,"type":"subscribe"}`.
//! * The C API (`router_provider_create`, `router_provider_send`, ...) with
//!   the module log callback.
//!
//! Linux only, like the C++ (epoll).

#![cfg(target_os = "linux")]

pub mod socket;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

use parking_lot::{Condvar, Mutex, RwLock};
use siem_njson::Value;
use socket::{OnRead, SocketClient, SocketServer};

/// `DEFAULT_SOCKET_PATH`
pub const DEFAULT_SOCKET_PATH: &str = "queue/router/";
/// `REMOTE_SUBSCRIPTION_ENDPOINT`
pub const REMOTE_SUBSCRIPTION_ENDPOINT: &str = "queue/router/subscription.sock";

/// `modules_log_level_t` names: "DEBUG", "INFO", "WARNING", "ERROR",
/// "ERROR_EXIT", "DEBUG_VERBOSE".
pub type LogFn = Arc<dyn Fn(&str, &str) + Send + Sync>;

static LOG: OnceLock<LogFn> = OnceLock::new();

/// `logMessage`
pub fn log_message(level: &str, msg: &str) {
    if !msg.is_empty() {
        if let Some(f) = LOG.get() {
            f(level, msg);
        }
    }
}

// ------------------------------------------------------------ dispatcher

/// `Observer` / `Subscriber<const std::vector<char>&>`
pub struct Subscriber {
    id: String,
    callback: Box<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>,
}

impl Subscriber {
    pub fn new(id: &str, callback: impl Fn(&[u8]) -> Result<(), String> + Send + Sync + 'static) -> Arc<Subscriber> {
        Arc::new(Subscriber { id: id.to_string(), callback: Box::new(callback) })
    }
}

/// `Subject` (inside `Provider`)
#[derive(Default)]
struct Subject {
    observers: Mutex<Vec<Arc<Subscriber>>>,
}

impl Subject {
    fn attach(&self, s: Arc<Subscriber>) {
        let mut o = self.observers.lock();
        if !o.iter().any(|x| x.id == s.id) {
            o.push(s);
        }
    }

    fn detach(&self, id: &str) -> Result<(), String> {
        let mut o = self.observers.lock();
        match o.iter().position(|x| x.id == id) {
            Some(i) => {
                o.remove(i);
                Ok(())
            }
            None => Err("Observer not found".into()),
        }
    }

    /// `notifyObservers`: an observer error stops the notification.
    fn notify(&self, data: &[u8]) -> Result<(), String> {
        let o = self.observers.lock();
        for s in o.iter() {
            (s.callback)(data)?;
        }
        Ok(())
    }
}

/// `AsyncDispatcher` over a `SafeQueue`, one thread (the publishers').
struct Dispatcher {
    queue: Arc<(Mutex<(VecDeque<Job>, bool)>, Condvar)>,
    running: Arc<AtomicBool>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

enum Job {
    Data(Vec<u8>),
    Rundown(Arc<(Mutex<bool>, Condvar)>),
}

impl Dispatcher {
    fn new(functor: impl Fn(&[u8]) -> Result<(), String> + Send + 'static) -> Dispatcher {
        let queue: Arc<(Mutex<(VecDeque<Job>, bool)>, Condvar)> = Arc::new((Mutex::new((VecDeque::new(), false)), Condvar::new()));
        let running = Arc::new(AtomicBool::new(true));
        let (q, r) = (queue.clone(), running.clone());
        let t = std::thread::spawn(move || {
            while r.load(Ordering::SeqCst) {
                let job = {
                    let mut g = q.0.lock();
                    while g.0.is_empty() && !g.1 {
                        q.1.wait(&mut g);
                    }
                    if g.1 {
                        None
                    } else {
                        g.0.pop_front()
                    }
                };
                match job {
                    Some(Job::Data(d)) => {
                        if let Err(e) = functor(&d) {
                            // the dispatch thread ends on an exception
                            eprintln!("Dispatch handler error, {e}");
                            return;
                        }
                    }
                    Some(Job::Rundown(p)) => {
                        *p.0.lock() = true;
                        p.1.notify_all();
                    }
                    None => {}
                }
            }
        });
        Dispatcher { queue, running, thread: Mutex::new(Some(t)) }
    }

    fn push(&self, d: Vec<u8>) {
        if self.running.load(Ordering::SeqCst) {
            let mut g = self.queue.0.lock();
            if !g.1 {
                g.0.push_back(Job::Data(d));
                self.queue.1.notify_one();
            }
        }
    }

    fn cancel(&self) {
        self.running.store(false, Ordering::SeqCst);
        {
            let mut g = self.queue.0.lock();
            g.1 = true;
            self.queue.1.notify_all();
        }
        if let Some(t) = self.thread.lock().take() {
            let _ = t.join();
        }
    }

    /// `rundown`: waits for the queued data (unless the thread died), then cancels.
    fn rundown(&self) {
        if self.running.load(Ordering::SeqCst) {
            let p = Arc::new((Mutex::new(false), Condvar::new()));
            {
                let mut g = self.queue.0.lock();
                if !g.1 {
                    g.0.push_back(Job::Rundown(p.clone()));
                    self.queue.1.notify_one();
                }
            }
            let alive = self.thread.lock().as_ref().map(|t| !t.is_finished()).unwrap_or(false);
            if alive {
                let mut g = p.0.lock();
                while !*g {
                    // the thread may die before reaching the promise
                    if p.1.wait_for(&mut g, std::time::Duration::from_millis(100)).timed_out()
                        && self.thread.lock().as_ref().map(|t| t.is_finished()).unwrap_or(true)
                    {
                        break;
                    }
                }
            }
            self.cancel();
        }
    }
}

impl Drop for Dispatcher {
    fn drop(&mut self) {
        self.cancel();
    }
}

// -------------------------------------------------------------- publisher

/// `Publisher`: the broker side of a topic.
pub struct Publisher {
    subject: Arc<Subject>,
    server: Option<Arc<SocketServer>>,
    dispatcher: Dispatcher,
}

impl Publisher {
    pub fn new(endpoint: &str, socket_path: &str) -> Result<Publisher, String> {
        let subject = Arc::new(Subject::default());
        let s = subject.clone();
        let dispatcher = Dispatcher::new(move |d: &[u8]| s.notify(d));
        let server = Arc::new(SocketServer::new(&format!("{socket_path}{endpoint}")));
        let (subj, srv) = (subject.clone(), Arc::downgrade(&server));
        let disp_q = dispatcher.queue.clone();
        let disp_running = dispatcher.running.clone();
        let on_read: OnRead = Arc::new(move |fd, body: &[u8], header: &[u8]| {
            if !header.is_empty() {
                if header == b"P" && disp_running.load(Ordering::SeqCst) {
                    let mut g = disp_q.0.lock();
                    if !g.1 {
                        g.0.push_back(Job::Data(body.to_vec()));
                        disp_q.1.notify_one();
                    }
                }
            } else {
                // the exceptions end the read silently (processRead)
                let Ok(json) = siem_njson::parse(body) else { return };
                let Ok(id) = json.at("subscriberId").and_then(|v| v.get_ref_str()) else { return };
                let id = String::from_utf8_lossy(id).into_owned();
                let w = srv.clone();
                subj.attach(Subscriber::new(&id, move |m: &[u8]| match w.upgrade() {
                    Some(server) => server.send(fd, m, b""),
                    None => Err("Client not found".into()),
                }));
                if let Some(server) = srv.upgrade() {
                    let _ = server.send(fd, br#"{"Result":"OK"}"#, b"");
                }
            }
        });
        server.listen(on_read)?;
        Ok(Publisher { subject, server: Some(server), dispatcher })
    }

    /// `addSubscriber` (local)
    pub fn add_subscriber(&self, s: Arc<Subscriber>) {
        self.subject.attach(s);
    }

    pub fn remove_subscriber(&self, id: &str) -> Result<(), String> {
        self.subject.detach(id)
    }

    pub fn push(&self, data: &[u8]) {
        self.dispatcher.push(data.to_vec());
    }
}

impl Drop for Publisher {
    fn drop(&mut self) {
        self.server.take();
        self.dispatcher.rundown();
    }
}

// ----------------------------------------------------------------- remote

/// `RemoteSubscriptionManager::sendInitProviderMessage`
fn send_init_provider_message(endpoint: &str, on_success: Arc<dyn Fn() + Send + Sync>) -> Arc<SocketClient> {
    let client = Arc::new(SocketClient::new(REMOTE_SUBSCRIPTION_ENDPOINT));
    let msg = Value::object_of(&[("EndpointName", endpoint.as_bytes()), ("MessageType", b"InitProvider")]);
    let msg = msg.dump().unwrap_or_default();
    let weak = Arc::downgrade(&client);
    client.connect(
        Arc::new(move |body: &[u8], _h: &[u8]| match siem_njson::parse(body) {
            Ok(r) => {
                let ok = matches!(r.at("Result"), Ok(Value::Str(s)) if s == b"OK");
                if ok {
                    on_success();
                } else {
                    let what = match r.at("Result") {
                        Ok(Value::Str(s)) => String::from_utf8_lossy(s).into_owned(),
                        Ok(v) => format!("[json.exception.type_error.302] type must be string, but is {}", v.type_name()),
                        Err(e) => String::from_utf8_lossy(&e).into_owned(),
                    };
                    eprintln!("Invalid result: {what}");
                }
            }
            Err(e) => eprintln!("Invalid result: {}", String::from_utf8_lossy(&e)),
        }),
        Arc::new(move || {
            if let Some(c) = weak.upgrade() {
                c.send(&msg, b"");
            }
        }),
    );
    client
}

/// `RemoteProvider`
pub struct RemoteProvider {
    client: Arc<SocketClient>,
    _registration: Arc<SocketClient>,
}

impl RemoteProvider {
    pub fn new(endpoint: &str, socket_path: &str, on_connect: Arc<dyn Fn() + Send + Sync>) -> RemoteProvider {
        let client = Arc::new(SocketClient::new(&format!("{socket_path}{endpoint}")));
        let c = client.clone();
        let registration = send_init_provider_message(
            endpoint,
            Arc::new(move || {
                let oc = on_connect.clone();
                c.connect(Arc::new(|_: &[u8], _: &[u8]| {}), Arc::new(move || oc()));
            }),
        );
        RemoteProvider { client, _registration: registration }
    }

    pub fn push(&self, data: &[u8]) {
        self.client.send(data, b"P");
    }
}

/// `RemoteSubscriber`
pub struct RemoteSubscriber {
    _client: Arc<SocketClient>,
    _registration: Arc<SocketClient>,
}

impl RemoteSubscriber {
    pub fn new(
        endpoint: &str,
        subscriber_id: &str,
        callback: Arc<dyn Fn(&[u8]) + Send + Sync>,
        socket_path: &str,
        on_connect: Arc<dyn Fn() + Send + Sync>,
    ) -> RemoteSubscriber {
        let client = Arc::new(SocketClient::new(&format!("{socket_path}{endpoint}")));
        let registered = Arc::new(AtomicBool::new(false));
        let (c, id) = (client.clone(), subscriber_id.to_string());
        let registration = send_init_provider_message(
            endpoint,
            Arc::new(move || {
                let (reg, cb, oc, id2, wc) = (registered.clone(), callback.clone(), on_connect.clone(), id.clone(), Arc::downgrade(&c));
                c.connect(
                    Arc::new(move |body: &[u8], _h: &[u8]| {
                        if !reg.load(Ordering::SeqCst) {
                            match siem_njson::parse(body) {
                                Ok(j) => match j.at("Result").and_then(|v| v.get_ref_str()) {
                                    Ok(s) if s == b"OK" => {
                                        reg.store(true, Ordering::SeqCst);
                                        oc();
                                    }
                                    Ok(_) => eprintln!("RemoteSubscriber: Invalid result: Connection refused"),
                                    Err(e) => eprintln!("RemoteSubscriber: Invalid result: {}", String::from_utf8_lossy(&e)),
                                },
                                Err(e) => eprintln!("RemoteSubscriber: Invalid result: {}", String::from_utf8_lossy(&e)),
                            }
                        } else {
                            cb(body);
                        }
                    }),
                    Arc::new(move || {
                        let m = Value::object_of(&[("subscriberId", id2.as_bytes()), ("type", b"subscribe")]);
                        if let (Ok(s), Some(c)) = (m.dump(), wc.upgrade()) {
                            c.send(&s, b"");
                        }
                    }),
                );
            }),
        );
        RemoteSubscriber { _client: client, _registration: registration }
    }
}

// ----------------------------------------------------------------- facade

/// `RouterFacade`
#[derive(Default)]
pub struct RouterFacade {
    providers: RwLock<HashMap<String, Arc<Publisher>>>,
    registration_server: Mutex<Option<Arc<SocketServer>>>,
    remote_subscribers: Mutex<HashMap<String, Arc<RemoteSubscriber>>>,
    remote_providers: Mutex<HashMap<String, Arc<RemoteProvider>>>,
}

static FACADE: OnceLock<RouterFacade> = OnceLock::new();

impl RouterFacade {
    pub fn instance() -> &'static RouterFacade {
        FACADE.get_or_init(RouterFacade::default)
    }

    /// `initialize`: the registration server of the broker.
    pub fn initialize(&self) -> Result<(), String> {
        let mut g = self.registration_server.lock();
        if g.is_some() {
            return Err("Already initialized".into());
        }
        let server = Arc::new(SocketServer::new(REMOTE_SUBSCRIPTION_ENDPOINT));
        let srv = Arc::downgrade(&server);
        server.listen(Arc::new(move |fd, body: &[u8], _h: &[u8]| {
            // a parse error ends the read silently
            let Ok(message) = siem_njson::parse(body) else { return };
            let result: Result<(), Vec<u8>> = (|| {
                let mt = message.at("MessageType")?.get_str()?.to_vec();
                if mt == b"InitProvider" {
                    let name = message.at("EndpointName")?.get_ref_str()?;
                    RouterFacade::instance().init_provider_local(&String::from_utf8_lossy(name)).map_err(|e| e.into_bytes())?;
                } else if mt == b"RemoveSubscriber" {
                    let name = String::from_utf8_lossy(message.at("EndpointName")?.get_ref_str()?).into_owned();
                    let id = String::from_utf8_lossy(message.at("SubscriberId")?.get_ref_str()?).into_owned();
                    RouterFacade::instance().remove_subscriber_local(&name, &id).map_err(|e| e.into_bytes())?;
                } else {
                    return Err(b"Invalid message type".to_vec());
                }
                Ok(())
            })();
            let r: &[u8] = match &result {
                Ok(()) => b"OK",
                Err(e) => e,
            };
            let out = Value::object_of(&[("Result", r)]).dump().unwrap_or_default();
            if let Some(s) = srv.upgrade() {
                let _ = s.send(fd, &out, b"");
            }
        }))?;
        *g = Some(server);
        Ok(())
    }

    /// `destroy`
    pub fn destroy(&self) -> Result<(), String> {
        let mut g = self.registration_server.lock();
        if g.is_none() {
            return Err("Not initialized".into());
        }
        self.remote_subscribers.lock().clear();
        self.remote_providers.lock().clear();
        g.take();
        self.providers.write().clear();
        Ok(())
    }

    pub fn init_provider_local(&self, name: &str) -> Result<(), String> {
        let mut p = self.providers.write();
        if !p.contains_key(name) {
            p.insert(name.to_string(), Arc::new(Publisher::new(name, DEFAULT_SOCKET_PATH)?));
        }
        Ok(())
    }

    pub fn remove_provider_local(&self, name: &str) -> Result<(), String> {
        let mut p = self.providers.write();
        if p.remove(name).is_none() {
            return Err("Provider not exist: ".into());
        }
        Ok(())
    }

    pub fn init_provider_remote(&self, name: &str, on_connect: Arc<dyn Fn() + Send + Sync>) -> Result<(), String> {
        let mut p = self.remote_providers.lock();
        if p.contains_key(name) {
            return Err("initProviderRemote: Provider already exist".into());
        }
        p.insert(name.to_string(), Arc::new(RemoteProvider::new(name, DEFAULT_SOCKET_PATH, on_connect)));
        Ok(())
    }

    pub fn remove_provider_remote(&self, name: &str) -> Result<(), String> {
        let mut p = self.remote_providers.lock();
        if p.remove(name).is_none() {
            return Err("removeProviderRemote: provider not exist".into());
        }
        Ok(())
    }

    pub fn add_subscriber(&self, name: &str, id: &str, callback: Arc<dyn Fn(&[u8]) + Send + Sync>) -> Result<(), String> {
        let mut p = self.providers.write();
        if !p.contains_key(name) {
            p.insert(name.to_string(), Arc::new(Publisher::new(name, DEFAULT_SOCKET_PATH)?));
        }
        p[name].add_subscriber(Subscriber::new(id, move |d: &[u8]| {
            callback(d);
            Ok(())
        }));
        Ok(())
    }

    pub fn add_subscriber_remote(
        &self,
        name: &str,
        id: &str,
        callback: Arc<dyn Fn(&[u8]) + Send + Sync>,
        on_connect: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<(), String> {
        let mut s = self.remote_subscribers.lock();
        if s.contains_key(name) {
            return Err("addSubscriberRemote: Subscriber already exist".into());
        }
        s.insert(name.to_string(), Arc::new(RemoteSubscriber::new(name, id, callback, DEFAULT_SOCKET_PATH, on_connect)));
        Ok(())
    }

    pub fn remove_subscriber_remote(&self, name: &str, _id: &str) {
        self.remote_subscribers.lock().remove(name);
    }

    pub fn remove_subscriber_local(&self, name: &str, id: &str) -> Result<(), String> {
        let p = self.providers.read();
        if let Some(pb) = p.get(name) {
            pb.remove_subscriber(id)?;
        }
        Ok(())
    }

    /// `push`: the remote provider of the topic, or its local publisher.
    pub fn push(&self, name: &str, data: &[u8]) -> Result<(), String> {
        let r = self.remote_providers.lock();
        if let Some(rp) = r.get(name) {
            rp.push(data);
            return Ok(());
        }
        let p = self.providers.read();
        match p.get(name) {
            Some(pb) => {
                pb.push(data);
                Ok(())
            }
            None => Err("Provider not exist: ".into()),
        }
    }
}

// --------------------------------------------------------------- C API

/// A provider handle (`ROUTER_PROVIDER_HANDLE`).
pub type ProviderHandle = u64;

struct RouterProvider {
    topic: String,
    is_local: bool,
}

impl Drop for RouterProvider {
    /// The C++ handle owns the provider: destroying it stops it.
    fn drop(&mut self) {
        let f = RouterFacade::instance();
        let _ = if self.is_local { f.remove_provider_local(&self.topic) } else { f.remove_provider_remote(&self.topic) };
    }
}

static PROVIDERS: OnceLock<RwLock<HashMap<ProviderHandle, Arc<RouterProvider>>>> = OnceLock::new();
static NEXT_HANDLE: AtomicU64 = AtomicU64::new(1);

fn providers() -> &'static RwLock<HashMap<ProviderHandle, Arc<RouterProvider>>> {
    PROVIDERS.get_or_init(|| RwLock::new(HashMap::new()))
}

/// `router_initialize(callbackLog)`
pub fn router_initialize(log: LogFn) -> i32 {
    let _ = LOG.set(log);
    log_message("DEBUG", "Router initialized successfully.");
    0
}

/// `router_start` (the broker)
pub fn router_start() -> i32 {
    match RouterFacade::instance().initialize() {
        Ok(()) => {
            log_message("DEBUG", "Router started successfully.");
            0
        }
        Err(_) => -1,
    }
}

/// `router_stop`
pub fn router_stop() -> i32 {
    match RouterFacade::instance().destroy() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("Error stopping router: {e}");
            -1
        }
    }
}

/// `router_provider_create(name, isLocal)`: 0 is the NULL handle.
pub fn router_provider_create(name: &str, is_local: bool) -> ProviderHandle {
    if name.is_empty() {
        log_message("ERROR", "Error creating provider. Topic name is empty");
        return 0;
    }
    let f = RouterFacade::instance();
    let started = if is_local { f.init_provider_local(name) } else { f.init_provider_remote(name, Arc::new(|| {})) };
    if started.is_err() {
        log_message("ERROR", "Error creating provider");
        return 0;
    }
    let h = NEXT_HANDLE.fetch_add(1, Ordering::SeqCst);
    providers().write().insert(h, Arc::new(RouterProvider { topic: name.to_string(), is_local }));
    h
}

/// `router_provider_send(handle, message, size)`
pub fn router_provider_send(handle: ProviderHandle, message: &[u8]) -> i32 {
    let r: Result<(), String> = (|| {
        if message.is_empty() {
            return Err("Error sending message to provider. Message is empty".into());
        }
        let p = providers().read();
        let Some(p) = p.get(&handle) else {
            return Err("map::at".into());
        };
        RouterFacade::instance().push(&p.topic, message)
    })();
    match r {
        Ok(()) => 0,
        Err(e) => {
            log_message("ERROR", &format!("Error sending message to provider: {e}"));
            -1
        }
    }
}

/// `router_provider_destroy(handle)`
pub fn router_provider_destroy(handle: ProviderHandle) {
    providers().write().remove(&handle);
}

/// A subscription (`RouterSubscriber`): unsubscribes when dropped.
pub struct RouterSubscriber {
    topic: String,
    id: String,
    is_local: bool,
}

impl RouterSubscriber {
    pub fn new(topic: &str, id: &str, is_local: bool) -> RouterSubscriber {
        RouterSubscriber { topic: topic.to_string(), id: id.to_string(), is_local }
    }

    /// `subscribe(callback, onConnect)`
    pub fn subscribe(&self, callback: Arc<dyn Fn(&[u8]) + Send + Sync>, on_connect: Arc<dyn Fn() + Send + Sync>) -> Result<(), String> {
        let f = RouterFacade::instance();
        if self.is_local {
            f.add_subscriber(&self.topic, &self.id, callback)?;
            on_connect();
            Ok(())
        } else {
            f.add_subscriber_remote(&self.topic, &self.id, callback, on_connect)
        }
    }
}

impl Drop for RouterSubscriber {
    fn drop(&mut self) {
        let f = RouterFacade::instance();
        if self.is_local {
            if f.remove_subscriber_local(&self.topic, &self.id).is_err() {
                eprintln!("Error in ~RouterSubscriber()");
            }
        } else {
            f.remove_subscriber_remote(&self.topic, &self.id);
        }
    }
}
