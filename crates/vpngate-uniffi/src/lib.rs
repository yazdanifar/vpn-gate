//! The in-process engine of the Android app, exposed to Kotlin through UniFFI.
//!
//! There is no daemon on Android, so the app talks to the same IPC core the desktop daemon serves, over an in-memory
//! pipe instead of a socket: Kotlin sends one JSON request per call to [`AndroidEngine::send`] and receives every
//! reply and state event as one JSON line through [`LineListener`]. The lines are exactly the IPC v9 protocol of
//! `docs/cross-platform/IPC.md` (`listServers`, `refreshServers`, `syncDat`, `probe`, `validateAccount`, `connect`,
//! `disconnect`, `status`), so the Kotlin models are mirrors of the golden-checked types the other UIs use.
//!
//! The platform half is [`VpnHostCallbacks`]: `establish` turns the engine's [`TunnelPlanRecord`] into a
//! `VpnService.Builder` tunnel and returns the descriptor, and `protect` is `VpnService.protect`.

#![cfg(unix)] // Android is Linux; the crate is empty where the descriptor-based tunnel cannot exist.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use vpngate_daemon::backend::client_environment;
use vpngate_daemon::engine::Engine;
use vpngate_daemon::ipc_server::IpcCore;
use vpngate_net::entropy::{Entropy, SystemEntropy};
use vpngate_net::host_unique_id::HostUniqueId;
use vpngate_net::session::{
    softether_transport, tls_stream_factory, DnsProxyService, Session, SessionDependencies, SessionTiming, SocksService,
};
use vpngate_platform::android::{AndroidBackend, TunnelPlan, VpnHost};
use vpngate_platform::{protect, NetConfiguring, PlatformError, TunDevice};

uniffi::setup_scaffolding!();

/// File names inside the app's files directory.
const UNIQUE_ID_FILE: &str = "host-unique-id";
const SERVER_CACHE_FILE: &str = "servers.cache";
/// The pipe between Kotlin and the IPC core; a full pipe only slows the sender down.
const PIPE_BYTES: usize = 256 * 1024;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// What `VpnService.Builder` is given. Routes and addresses are `a.b.c.d/len` strings.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct TunnelPlanRecord {
    pub address: String,
    pub prefix_length: u8,
    /// `addRoute`.
    pub routes: Vec<String>,
    /// `excludeRoute` on API 33+; on older releases Kotlin splits `routes` around these.
    pub excluded_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    /// Add `::/0` as a route so IPv6 traffic enters the tunnel and is dropped there instead of leaking.
    pub block_ipv6: bool,
}

impl From<&TunnelPlan> for TunnelPlanRecord {
    fn from(p: &TunnelPlan) -> Self {
        TunnelPlanRecord {
            address: p.address.clone(),
            prefix_length: p.prefix_length,
            routes: p.routes.clone(),
            excluded_routes: p.excluded_routes.clone(),
            dns_servers: p.dns_servers.clone(),
            mtu: p.mtu,
            block_ipv6: p.block_ipv6,
        }
    }
}

/// The answer to `establish`: the tun descriptor (ownership passes to the engine, `detachFd()`), or why there is none.
#[derive(uniffi::Record, Debug, Clone, PartialEq, Eq)]
pub struct EstablishResult {
    pub fd: i32,
    pub error: Option<String>,
}

/// The `VpnService` side, implemented in Kotlin. Called from engine threads, never from the main thread.
#[uniffi::export(with_foreign)]
pub trait VpnHostCallbacks: Send + Sync {
    /// `Builder.establish()` with the plan; blocks until the system has created the interface.
    fn establish(&self, plan: TunnelPlanRecord) -> EstablishResult;
    /// `VpnService.protect(fd)`: keeps the relay, UDP and direct-DNS sockets out of the tunnel.
    fn protect(&self, fd: i32) -> bool;
    /// The engine closed the tunnel (disconnect, failure, reconnect): stop the foreground notification if idle.
    fn tunnel_closed(&self);
}

/// Receives every JSON line the engine produces: replies to requests and connection state events.
#[uniffi::export(with_foreign)]
pub trait LineListener: Send + Sync {
    fn on_line(&self, line: String);
}

#[derive(uniffi::Error, Debug)]
pub enum EngineError {
    Failed { message: String },
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let EngineError::Failed { message } = self;
        f.write_str(message)
    }
}

impl std::error::Error for EngineError {}

struct HostAdapter(Arc<dyn VpnHostCallbacks>);

impl VpnHost for HostAdapter {
    fn establish(&self, plan: &TunnelPlan) -> Result<i32, String> {
        let r = self.0.establish(plan.into());
        match r.error {
            Some(e) => Err(e),
            None => Ok(r.fd),
        }
    }

    fn protect(&self, fd: i32) -> bool {
        self.0.protect(fd)
    }

    fn tunnel_closed(&self) {
        self.0.tunnel_closed();
    }
}

struct Unsupported(&'static str);

impl DnsProxyService for Unsupported {
    fn start(&self) -> Result<(), PlatformError> {
        Err(PlatformError::new(self.0))
    }
    fn stop(&self) {}
    fn set_servers(&self, _tunnel: Vec<String>, _direct: Vec<String>) {}
}

impl SocksService for Unsupported {
    fn start(&self) -> Result<(), PlatformError> {
        Err(PlatformError::new(self.0))
    }
    fn bound_port(&self) -> u16 {
        0
    }
    fn stop(&self) {}
}

/// The session's factories for Android: the real SoftEther transport, the host-backed tunnel, and no DNS proxy or SOCKS
/// server (domain routing rules and SOCKS5 mode report a plain error on connect).
pub fn android_dependencies(host: Arc<dyn VpnHost>, unique_id_path: &std::path::Path) -> SessionDependencies {
    let unique_id = HostUniqueId::load(unique_id_path, |n| SystemEntropy.bytes(n));
    let environment = client_environment();
    let backend = AndroidBackend::new(host);
    let (tun_backend, net_backend) = (backend.clone(), backend);
    SessionDependencies {
        make_transport: Arc::new(move |config, port| {
            softether_transport(config, port, &unique_id, &environment, tls_stream_factory(config))
        }),
        make_tun: Arc::new(move || tun_backend.make_tun().map(|t| t as Arc<dyn TunDevice>)),
        make_net: Arc::new(move || net_backend.make_net() as Arc<dyn NetConfiguring>),
        make_dns_proxy: Arc::new(|_, _| {
            Err(PlatformError::new("Domain routing rules are not available on Android yet"))
                as Result<Arc<dyn DnsProxyService>, PlatformError>
        }),
        make_socks: Arc::new(|_, _, _| {
            Arc::new(Unsupported("SOCKS5 mode is not available on Android")) as Arc<dyn SocksService>
        }),
    }
}

/// The engine: one per app process.
#[derive(uniffi::Object)]
pub struct AndroidEngine {
    runtime: Mutex<Option<Runtime>>,
    session: Arc<Session>,
    /// Requests, in order, on their way to the IPC core.
    requests: Mutex<Option<UnboundedSender<Vec<u8>>>>,
    core: IpcCore,
}

#[uniffi::export]
impl AndroidEngine {
    /// `files_dir` is the app's private directory (the unique id and the server-list cache live there);
    /// `bundle_path` is the shipped `VPNGate.dat` copied out of the APK assets, used until the first sync.
    #[uniffi::constructor]
    pub fn new(
        files_dir: String,
        bundle_path: Option<String>,
        host: Arc<dyn VpnHostCallbacks>,
        listener: Arc<dyn LineListener>,
    ) -> Result<Arc<Self>, EngineError> {
        Self::build(files_dir, bundle_path, host, listener, |_| {})
    }

    /// Sends one request (a JSON object, no newline needed). Replies and events come back through the listener.
    pub fn send(&self, request_json: String) {
        let mut line = request_json.into_bytes();
        if !line.ends_with(b"\n") {
            line.push(b'\n');
        }
        if let Some(tx) = lock(&self.requests).as_ref() {
            let _ = tx.send(line);
        }
    }

    /// Disconnects and stops the engine. The object is unusable afterwards.
    pub fn shutdown(&self) {
        self.session.disconnect();
        lock(&self.requests).take();
        self.core.close_clients();
        protect::set_protector(None);
        if let Some(rt) = lock(&self.runtime).take() {
            rt.shutdown_background();
        }
    }
}

impl AndroidEngine {
    /// `customize` lets tests replace parts of the session's dependencies (the relay transport).
    fn build(
        files_dir: String,
        bundle_path: Option<String>,
        host: Arc<dyn VpnHostCallbacks>,
        listener: Arc<dyn LineListener>,
        customize: impl FnOnce(&mut SessionDependencies),
    ) -> Result<Arc<Self>, EngineError> {
        let fail = |e: &dyn std::fmt::Display| EngineError::Failed { message: e.to_string() };
        let dir = PathBuf::from(files_dir);
        std::fs::create_dir_all(&dir).map_err(|e| fail(&e))?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("vpngate-engine")
            .enable_all()
            .build()
            .map_err(|e| fail(&e))?;

        let protector = host.clone();
        protect::set_protector(Some(Arc::new(move |fd| protector.protect(fd))));
        let mut deps = android_dependencies(Arc::new(HostAdapter(host)), &dir.join(UNIQUE_ID_FILE));
        customize(&mut deps);
        let session = Session::new(deps, SessionTiming::default());
        let core = IpcCore::new(session.clone());
        core.set_engine(Arc::new(Engine::production(
            dir.join(SERVER_CACHE_FILE),
            bundle_path.into_iter().map(PathBuf::from).collect(),
        )));

        // Kotlin's end of the pipe: a writer task for requests, a reader task that splits replies into lines.
        let (client_end, core_end) = duplex(PIPE_BYTES);
        let (tx, mut rx) = unbounded_channel::<Vec<u8>>();
        {
            let _entered = runtime.enter();
            core.attach(core_end);
            let (mut read, mut write) = tokio::io::split(client_end);
            tokio::spawn(async move {
                while let Some(line) = rx.recv().await {
                    if write.write_all(&line).await.is_err() {
                        break;
                    }
                }
            });
            tokio::spawn(async move {
                let mut pending: Vec<u8> = Vec::new();
                let mut chunk = [0u8; 8192];
                loop {
                    match read.read(&mut chunk).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => pending.extend_from_slice(&chunk[..n]),
                    }
                    while let Some(nl) = pending.iter().position(|&b| b == b'\n') {
                        let line: Vec<u8> = pending.drain(..=nl).collect();
                        if let Ok(text) = String::from_utf8(line[..nl].to_vec()) {
                            listener.on_line(text);
                        }
                    }
                }
            });
        }
        Ok(Arc::new(AndroidEngine {
            runtime: Mutex::new(Some(runtime)),
            session,
            requests: Mutex::new(Some(tx)),
            core,
        }))
    }
}

/// The engine's protocol and build versions, for the app's About screen and a sanity check on load.
#[uniffi::export]
pub fn engine_ipc_version() -> i64 {
    vpngate_core::ipc::IPC_VERSION
}

#[cfg(test)]
mod tests;
