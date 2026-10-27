//! Owns one VPN connection: SoftEther session + bridge + tun + routes, with optional auto-reconnect (`Session.swift`).
//!
//! Every `connect`/`disconnect` bumps a generation number. Work started for an older generation never publishes state
//! and never keeps resources: after each `await` it checks `is_current(gen)`, and the old run task is aborted.
//!
//! `connect` spawns on the current Tokio runtime, so it must be called from inside one.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use async_trait::async_trait;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use vpngate_core::cert_pin::ServerCertPolicy;
use vpngate_core::ipc::{
    ConnectConfig, ConnectionState, HelperEvent, ProxyKind, ProxySettings, TunnelMode, DEFAULT_SOCKS_PORT,
    HELPER_VERSION,
};
use vpngate_core::packets::ip_string;
use vpngate_core::routing_rule::{RoutingAction, RoutingConfig};
use vpngate_core::validation;
use vpngate_platform::{NetApply, NetConfiguring, PlatformError, TunDevice};

use crate::connection::{ConnectOptions, ConnectionEvents, SoftEtherConnection};
use crate::connection_pool::{CloseFn, FrameFn};
use crate::dns_proxy::DynamicRuleSink;
use crate::entropy::{ClientEnvironment, SystemEntropy};
use crate::ethernet_bridge::{BridgeTiming, EthernetBridge};
use crate::host_unique_id::HostUniqueId;
use crate::softether_client::{ClientAuth, ClientConfig, SoftEtherClient, Welcome};
use crate::stream::{StreamError, StreamFactory};
use crate::tls::TlsStream;

/// Ports tried after the ones the caller listed.
pub const DEFAULT_PORTS: [i64; 4] = [443, 992, 5555, 1194];
/// Where the DNS proxy listens when domain rules need one; the system resolver is pointed here.
pub const DNS_PROXY_LISTEN_ADDRESS: &str = "127.0.0.1";

pub type EmitFn = Arc<dyn Fn(HelperEvent) + Send + Sync>;

/// An established-or-establishing link to a VPN Gate relay, as seen by the session.
#[async_trait]
pub trait VpnTransport: Send + Sync {
    /// Frames from the relay. Set after `connect`, before the bridge needs them.
    fn set_on_frame(&self, f: Option<FrameFn>);
    /// Called once when the link ends; `None` for a clean close.
    fn set_on_close(&self, f: Option<CloseFn>);
    fn bytes_in(&self) -> u64;
    fn bytes_out(&self) -> u64;
    async fn connect(&self, log: &mut (dyn for<'a> FnMut(&'a str) + Send)) -> Result<Welcome, StreamError>;
    /// Peers the data path talks to directly (after cluster redirects, plus the UDP endpoint); they need routes around
    /// a full tunnel.
    fn bypass_hosts(&self) -> Vec<String> {
        Vec::new()
    }
    /// IPv4 address of the TCP/TLS peer the data really flows to (`None` behind a proxy or when unknown).
    fn remote_ipv4(&self) -> Option<String> {
        None
    }
    fn send_frame(&self, frame: Vec<u8>);
    fn close(&self, error: Option<StreamError>);
}

/// The DNS proxy the session starts when domain routing rules exist. The UDP listener is an OS-facing component, so the
/// session only sees this lifecycle.
pub trait DnsProxyService: Send + Sync {
    fn start(&self) -> Result<(), PlatformError>;
    fn stop(&self);
    /// The tunnel's resolvers and the physical network's own, known once the lease and the routes exist.
    fn set_servers(&self, tunnel: Vec<String>, direct: Vec<String>);
}

/// SOCKS mode: the local proxy that is the only way into the tunnel.
pub trait SocksService: Send + Sync {
    fn start(&self) -> Result<(), PlatformError>;
    fn bound_port(&self) -> u16;
    fn stop(&self);
}

/// Adapts a `NetConfiguring` to the DNS proxy's rule sink.
pub struct NetRuleSink(pub Arc<dyn NetConfiguring>);

impl DynamicRuleSink for NetRuleSink {
    fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction) {
        self.0.apply_dynamic_rule(ip, action);
    }
}

type MakeTransport = Arc<dyn Fn(&ConnectConfig, u16) -> Arc<dyn VpnTransport> + Send + Sync>;
type MakeTun = Arc<dyn Fn() -> Result<Arc<dyn TunDevice>, PlatformError> + Send + Sync>;
type MakeNet = Arc<dyn Fn() -> Arc<dyn NetConfiguring> + Send + Sync>;
type MakeDnsProxy = Arc<
    dyn Fn(Arc<dyn NetConfiguring>, RoutingConfig) -> Result<Arc<dyn DnsProxyService>, PlatformError> + Send + Sync,
>;
type MakeSocks = Arc<dyn Fn(u16, &str, Vec<String>) -> Arc<dyn SocksService> + Send + Sync>;

/// The factories for everything one attempt owns, so tests and each OS backend supply their own.
#[derive(Clone)]
pub struct SessionDependencies {
    pub make_transport: MakeTransport,
    pub make_tun: MakeTun,
    pub make_net: MakeNet,
    pub make_dns_proxy: MakeDnsProxy,
    /// SOCKS mode: the proxy for (listen port, tunnel interface name, the VPN's DNS servers).
    pub make_socks: MakeSocks,
}

#[derive(Debug, Clone)]
pub struct SessionTiming {
    pub reconnect_delay: f64,
    pub max_attempts: i64,
    pub min_renew_seconds: f64,
    pub bridge: BridgeTiming,
}

impl Default for SessionTiming {
    fn default() -> Self {
        SessionTiming {
            reconnect_delay: 3.0,
            max_attempts: 8,
            min_renew_seconds: 60.0,
            bridge: BridgeTiming::default(),
        }
    }
}

/// What the IPC layer needs from a session.
pub trait SessionControlling: Send + Sync {
    fn set_emit(&self, emit: Option<EmitFn>);
    fn snapshot(&self) -> HelperEvent;
    fn connect(&self, config: ConnectConfig);
    fn disconnect(&self);
}

/// The config the legacy `connect(host:port:...)` requests stand for: the VPN Gate client's own account.
#[allow(clippy::too_many_arguments)]
pub fn legacy_connect_config(
    host: &str,
    port: Option<i64>,
    ports: Option<Vec<i64>>,
    proxy: ProxySettings,
    auto_reconnect: bool,
    block_ipv6: bool,
    routing: Option<RoutingConfig>,
    tunnel_mode: TunnelMode,
    socks_port: i64,
) -> ConnectConfig {
    let mut list = ports.unwrap_or_default();
    if let Some(p) = port {
        if !list.contains(&p) {
            list.insert(0, p);
        }
    }
    let mut cfg = ConnectConfig::new(host);
    cfg.ports = if list.is_empty() { DEFAULT_PORTS.to_vec() } else { list };
    cfg.proxy = proxy;
    cfg.max_connection = 1; // the VPN Gate client's own account (client_exe.c:27590)
    cfg.disable_qos = true; // ... and DisableQoS=1 (client_exe.c:27598)
    cfg.auto_reconnect = auto_reconnect;
    cfg.block_ipv6 = block_ipv6;
    cfg.routing = routing;
    cfg.tunnel_mode = tunnel_mode;
    cfg.socks_port = socks_port;
    cfg
}

/// [`legacy_connect_config`] for a full tunnel on the default SOCKS port.
pub fn simple_connect_config(
    host: &str,
    port: Option<i64>,
    proxy: ProxySettings,
    auto_reconnect: bool,
    block_ipv6: bool,
) -> ConnectConfig {
    legacy_connect_config(
        host,
        port,
        None,
        proxy,
        auto_reconnect,
        block_ipv6,
        None,
        TunnelMode::FullTunnel,
        DEFAULT_SOCKS_PORT,
    )
}

// MARK: real transport

/// The production [`VpnTransport`]: a `SoftEtherClient` that turns into a `SoftEtherConnection` on `connect`.
pub struct SoftEtherTransport {
    client: Mutex<Option<SoftEtherClient>>,
    conn: Mutex<Option<SoftEtherConnection>>,
    on_frame: Arc<Mutex<Option<FrameFn>>>,
    on_close: Arc<Mutex<Option<CloseFn>>>,
    closed: AtomicBool,
    options: Mutex<Option<ConnectOptions>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl SoftEtherTransport {
    pub fn new(client: SoftEtherClient) -> Self {
        Self::with_options(client, ConnectOptions::default())
    }

    pub fn with_options(client: SoftEtherClient, options: ConnectOptions) -> Self {
        SoftEtherTransport {
            client: Mutex::new(Some(client)),
            conn: Mutex::new(None),
            on_frame: Arc::default(),
            on_close: Arc::default(),
            closed: AtomicBool::new(false),
            options: Mutex::new(Some(options)),
        }
    }
}

#[async_trait]
impl VpnTransport for SoftEtherTransport {
    fn set_on_frame(&self, f: Option<FrameFn>) {
        *lock(&self.on_frame) = f;
    }

    fn set_on_close(&self, f: Option<CloseFn>) {
        *lock(&self.on_close) = f;
    }

    fn bytes_in(&self) -> u64 {
        lock(&self.conn).as_ref().map_or(0, |c| c.bytes_in())
    }

    fn bytes_out(&self) -> u64 {
        lock(&self.conn).as_ref().map_or(0, |c| c.bytes_out())
    }

    async fn connect(&self, log: &mut (dyn for<'a> FnMut(&'a str) + Send)) -> Result<Welcome, StreamError> {
        let client = lock(&self.client).take().ok_or(StreamError::Closed)?;
        let options = lock(&self.options).take().unwrap_or_default();
        let (frames, closes) = (self.on_frame.clone(), self.on_close.clone());
        let events = ConnectionEvents {
            on_frame: Arc::new(move |f| {
                let cb = lock(&frames).clone();
                if let Some(cb) = cb {
                    cb(f);
                }
            }),
            on_close: Arc::new(move |e| {
                let cb = lock(&closes).clone();
                if let Some(cb) = cb {
                    cb(e);
                }
            }),
        };
        let conn = client.connect(log, events, options).await?;
        let welcome = conn.welcome().clone();
        if self.closed.load(Ordering::SeqCst) {
            conn.close(None);
        }
        *lock(&self.conn) = Some(conn);
        Ok(welcome)
    }

    fn bypass_hosts(&self) -> Vec<String> {
        lock(&self.conn).as_ref().map_or_else(Vec::new, |c| c.bypass_hosts())
    }

    fn remote_ipv4(&self) -> Option<String> {
        lock(&self.conn).as_ref().and_then(|c| c.remote_ipv4())
    }

    fn send_frame(&self, frame: Vec<u8>) {
        if let Some(c) = lock(&self.conn).as_ref() {
            c.send_frame(frame);
        }
    }

    fn close(&self, error: Option<StreamError>) {
        self.closed.store(true, Ordering::SeqCst);
        if let Some(c) = lock(&self.conn).as_ref() {
            c.close(error);
        }
    }
}

/// Builds the production transport for one port of `config` (`SessionDependencies.transport` in Swift).
pub fn softether_transport(
    config: &ConnectConfig,
    port: u16,
    unique_id: &HostUniqueId,
    environment: &ClientEnvironment,
    make_stream: StreamFactory,
) -> Arc<dyn VpnTransport> {
    let auth = match config.auth_type.to_lowercase().as_str() {
        "standard password (sha-0)" | "password" => {
            ClientAuth::HashedPassword(config.password.clone().unwrap_or_default())
        }
        "plain password" | "plain" => ClientAuth::PlainPassword(config.password.clone().unwrap_or_default()),
        "user certificate" | "cert" => {
            ClientAuth::certificate(config.cert_der.clone().unwrap_or_default(), config.private_key_der.clone())
        }
        "ticket" => ClientAuth::Ticket(config.ticket.clone().unwrap_or_default()),
        _ => ClientAuth::Anonymous,
    };
    let mut cc = ClientConfig::new(&config.host, port, config.proxy.clone());
    cc.hub_name = config.hub_name.clone();
    cc.user_name = config.user_name.clone();
    cc.auth = auth;
    cc.max_connections = config.max_connection.max(1) as usize;
    cc.use_compress = config.use_compress;
    cc.use_udp_accel = config.use_udp_accel;
    cc.disable_qos = config.disable_qos;
    cc.half_connection = config.half_connection;
    let client = SoftEtherClient::new(cc, unique_id.clone(), make_stream, Box::new(SystemEntropy), environment.clone());
    Arc::new(SoftEtherTransport::new(client))
}

/// TLS streams checked against the account's certificate policy.
pub fn tls_stream_factory(config: &ConnectConfig) -> StreamFactory {
    let policy = ServerCertPolicy::new(config.check_server_cert, config.server_cert_fingerprint.as_deref());
    Arc::new(move |host, port, proxy| Box::new(TlsStream::new(host, port, proxy, policy.clone())))
}

// MARK: session

/// One-shot signal: `wait()` returns once `fire()` has been called (from any thread, any number of times).
struct AsyncSignal {
    tx: watch::Sender<bool>,
}

impl AsyncSignal {
    fn new() -> Arc<Self> {
        Arc::new(AsyncSignal { tx: watch::channel(false).0 })
    }

    fn fire(&self) {
        self.tx.send_replace(true);
    }

    async fn wait(&self) {
        let mut rx = self.tx.subscribe();
        let _ = rx.wait_for(|fired| *fired).await;
    }
}

#[derive(Default)]
struct Slots {
    client: Option<Arc<dyn VpnTransport>>,
    tun: Option<Arc<dyn TunDevice>>,
    net: Option<Arc<dyn NetConfiguring>>,
    dns_proxy: Option<Arc<dyn DnsProxyService>>,
    socks: Option<Arc<dyn SocksService>>,
    /// Strongly owned here: the tun/transport callbacks only hold it weakly.
    bridge: Option<Arc<EthernetBridge>>,
    counters: Option<JoinHandle<()>>,
    renew: Option<JoinHandle<()>>,
}

/// Everything one connection attempt owns. Released exactly once by `Session::release`.
struct Resources {
    gen: u64,
    link_down: Arc<AsyncSignal>,
    slots: Mutex<Slots>,
}

enum EstablishError {
    /// Superseded by a newer connect/disconnect; nothing to report.
    Cancelled,
    Failed(String),
}

impl From<PlatformError> for EstablishError {
    fn from(e: PlatformError) -> Self {
        EstablishError::Failed(e.0)
    }
}

struct State {
    generation: u64,
    current: HelperEvent,
    res: Option<Arc<Resources>>,
    run_task: Option<JoinHandle<()>>,
}

pub struct Session {
    deps: SessionDependencies,
    timing: SessionTiming,
    me: Weak<Session>,
    state: Mutex<State>,
    emit: Mutex<Option<EmitFn>>,
    active_runs: AtomicUsize,
}

/// Decrements the active-run count when the run task ends, however it ends (including being aborted).
struct RunGuard(Arc<Session>);

impl Drop for RunGuard {
    fn drop(&mut self) {
        self.0.active_runs.fetch_sub(1, Ordering::SeqCst);
    }
}

impl Session {
    pub fn new(deps: SessionDependencies, timing: SessionTiming) -> Arc<Session> {
        Arc::new_cyclic(|me| {
            let mut current = HelperEvent::new(ConnectionState::Disconnected);
            current.helper_version = Some(HELPER_VERSION); // present in every snapshot, even before the first event
            Session {
                deps,
                timing,
                me: me.clone(),
                state: Mutex::new(State { generation: 0, current, res: None, run_task: None }),
                emit: Mutex::new(None),
                active_runs: AtomicUsize::new(0),
            }
        })
    }

    /// True once every connect() task has run to completion (used by tests and shutdown).
    pub async fn wait_until_idle(&self, timeout: Duration) -> bool {
        let end = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < end {
            if self.active_runs.load(Ordering::SeqCst) == 0 {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        false
    }

    fn state(&self) -> MutexGuard<'_, State> {
        lock(&self.state)
    }

    fn is_current(&self, gen: u64) -> bool {
        self.state().generation == gen
    }

    /// Publishes a state change; ignored if `gen` has been superseded.
    fn set(
        &self,
        gen: u64,
        state: ConnectionState,
        server: Option<&str>,
        ip: Option<&str>,
        log: Option<String>,
        error: Option<String>,
    ) {
        let st = self.state();
        if st.generation != gen {
            return;
        }
        self.publish_locked(st, state, server, ip, log, error);
    }

    /// Consumes the lock guard so the event is emitted without holding it.
    fn publish_locked(
        &self,
        mut st: MutexGuard<'_, State>,
        state: ConnectionState,
        server: Option<&str>,
        ip: Option<&str>,
        log: Option<String>,
        error: Option<String>,
    ) {
        let c = &mut st.current;
        c.state = state;
        if state == ConnectionState::Disconnected {
            c.server = None;
            c.virtual_ip = None;
        }
        if let Some(s) = server {
            c.server = Some(s.to_string());
        }
        if let Some(i) = ip {
            c.virtual_ip = Some(i.to_string());
        }
        c.log = log;
        c.error = error;
        c.helper_version = Some(HELPER_VERSION);
        let e = c.clone();
        drop(st);
        self.emit_event(e);
    }

    fn emit_event(&self, e: HelperEvent) {
        let f = lock(&self.emit).clone();
        if let Some(f) = f {
            f(e);
        }
    }

    // MARK: control

    pub fn connect(&self, config: ConnectConfig) {
        let Some(me) = self.me.upgrade() else { return };
        let mut st = self.state();
        st.generation += 1;
        let gen = st.generation;
        let old = st.res.take();
        let old_task = st.run_task.take();
        self.active_runs.fetch_add(1, Ordering::SeqCst);
        // Held across the spawn so the task cannot be replaced by a racing connect before it is recorded.
        let guard = RunGuard(me.clone());
        let task = tokio::spawn(async move {
            let _guard = guard;
            me.run(gen, config).await;
        });
        st.run_task = Some(task);
        drop(st);
        if let Some(t) = old_task {
            t.abort();
        }
        if let Some(old) = old {
            self.release(&old);
        }
    }

    pub fn disconnect(&self) {
        let mut st = self.state();
        st.generation += 1;
        let old = st.res.take();
        let task = st.run_task.take();
        drop(st);
        if let Some(t) = task {
            t.abort();
        }
        if let Some(old) = old {
            self.release(&old);
        }
        let st = self.state();
        self.publish_locked(st, ConnectionState::Disconnected, None, None, None, None);
    }

    pub fn snapshot(&self) -> HelperEvent {
        self.state().current.clone()
    }

    pub fn set_emit(&self, emit: Option<EmitFn>) {
        *lock(&self.emit) = emit;
    }

    // MARK: run loop

    async fn run(self: Arc<Self>, gen: u64, config: ConnectConfig) {
        let mut attempt: i64 = 0;
        while self.is_current(gen) {
            let state = if attempt == 0 { ConnectionState::Connecting } else { ConnectionState::Reconnecting };
            self.set(gen, state, Some(&config.host), None, None, None);
            let r = Arc::new(Resources { gen, link_down: AsyncSignal::new(), slots: Mutex::default() });
            {
                let mut st = self.state();
                if st.generation != gen {
                    return;
                }
                st.res = Some(r.clone());
            }

            let mut failure: Option<String> = None;
            match self.establish(&r, &config).await {
                Ok(()) => {
                    attempt = 0;
                    r.link_down.wait().await;
                }
                Err(EstablishError::Cancelled) => {}
                Err(EstablishError::Failed(m)) => failure = Some(m),
            }

            // Release only if nobody else already did (disconnect/connect hand resources over themselves).
            {
                let mut st = self.state();
                if st.res.as_ref().is_some_and(|x| Arc::ptr_eq(x, &r)) {
                    st.res = None;
                }
            }
            self.release(&r);
            if !self.is_current(gen) {
                return;
            }

            if !config.auto_reconnect {
                let error = failure.unwrap_or_else(|| "Connection lost".to_string());
                self.set(gen, ConnectionState::Disconnected, None, None, None, Some(error));
                return;
            }
            // A custom account's own policy wins when it set one; VPN Gate connections never do (the app retries
            // those itself), so they keep the session's built-in default.
            let max_attempts = config.reconnect_count.unwrap_or(self.timing.max_attempts);
            let reconnect_delay = config.reconnect_interval.unwrap_or(self.timing.reconnect_delay);
            if attempt >= max_attempts {
                self.set(gen, ConnectionState::Disconnected, None, None, None, Some("Gave up reconnecting".into()));
                return;
            }
            attempt += 1;
            self.set(
                gen,
                ConnectionState::Reconnecting,
                Some(&config.host),
                None,
                Some(format!("Reconnecting in {}s (attempt {attempt})", reconnect_delay.ceil() as i64)),
                failure,
            );
            tokio::time::sleep(Duration::from_secs_f64(reconnect_delay.max(0.0))).await;
        }
    }

    /// Runs `body` on `r`'s slots only if its generation is still current.
    fn with_resources(&self, r: &Resources, body: impl FnOnce(&mut Slots)) -> bool {
        let st = self.state();
        if st.generation != r.gen {
            return false;
        }
        body(&mut lock(&r.slots));
        drop(st);
        true
    }

    async fn establish(&self, r: &Arc<Resources>, config: &ConnectConfig) -> Result<(), EstablishError> {
        let gen = r.gen;
        let mut ports: Vec<i64> = Vec::new();
        for &p in config.ports.iter().chain(DEFAULT_PORTS.iter()) {
            if validation::is_valid_port(Some(p)) && !ports.contains(&p) {
                ports.push(p);
            }
        }

        let mut client: Option<Arc<dyn VpnTransport>> = None;
        let mut last_error = StreamError::Closed.to_string();
        for port in ports {
            if !self.is_current(gen) {
                return Err(EstablishError::Cancelled);
            }
            let c = (self.deps.make_transport)(config, port as u16);
            // Registered before connecting so that a disconnect() during the handshake can reach it.
            if !self.with_resources(r, |s| s.client = Some(c.clone())) {
                c.close(None);
                return Err(EstablishError::Cancelled);
            }
            self.set(
                gen,
                ConnectionState::Authenticating,
                Some(&config.host),
                None,
                Some(format!("Connecting to {}:{port}", config.host)),
                None,
            );
            let weak = self.me.clone();
            let mut log = move |m: &str| {
                if let Some(s) = weak.upgrade() {
                    s.set(gen, ConnectionState::Authenticating, None, None, Some(m.to_string()), None);
                }
            };
            match c.connect(&mut log).await {
                Ok(_) => {
                    if !self.is_current(gen) {
                        return Err(EstablishError::Cancelled);
                    }
                    client = Some(c);
                    break;
                }
                Err(e) => {
                    c.close(None);
                    last_error = e.to_string();
                    self.with_resources(r, |s| {
                        if s.client.as_ref().is_some_and(|x| Arc::ptr_eq(x, &c)) {
                            s.client = None;
                        }
                    });
                    if !self.is_current(gen) {
                        return Err(EstablishError::Cancelled);
                    }
                    self.set(
                        gen,
                        ConnectionState::Connecting,
                        None,
                        None,
                        Some(format!("Port {port} failed: {last_error}")),
                        None,
                    );
                }
            }
        }
        let client = client.ok_or(EstablishError::Failed(last_error))?;

        let tun = (self.deps.make_tun)()?;
        if !self.with_resources(r, |s| s.tun = Some(tun.clone())) {
            tun.close();
            return Err(EstablishError::Cancelled);
        }
        let mac = config.virtual_mac_address.as_deref().and_then(validation::parse_mac_address);
        let bridge = EthernetBridge::with(self.timing.bridge.clone(), mac, Box::new(SystemEntropy));
        let socks_mode = config.tunnel_mode == TunnelMode::SocksProxy;
        // In SOCKS mode only IPv4 sockets bound to the interface ever use it, so there is no IPv6 to carry.
        let ipv6 = !config.block_ipv6 && !socks_mode;
        bridge.set_handle_ipv6(ipv6);
        tun.set_forward_ipv6(ipv6);
        if !self.with_resources(r, |s| s.bridge = Some(bridge.clone())) {
            return Err(EstablishError::Cancelled);
        }
        let weak_client = Arc::downgrade(&client);
        let wc = weak_client.clone();
        bridge.set_send_frame(move |f| {
            if let Some(c) = wc.upgrade() {
                c.send_frame(f);
            }
        });
        let weak_tun = Arc::downgrade(&tun);
        let wt = weak_tun.clone();
        bridge.set_deliver_ipv4(move |p| {
            if let Some(t) = wt.upgrade() {
                t.write_ipv4(p);
            }
        });
        bridge.set_deliver_ipv6(move |p| {
            if let Some(t) = weak_tun.upgrade() {
                t.write_ipv6(p);
            }
        });
        let wc = weak_client.clone();
        bridge.set_on_lease_changed(move |_| {
            if let Some(c) = wc.upgrade() {
                c.close(Some(StreamError::Protocol("DHCP address changed".into())));
            }
        });
        bridge.set_on_lease_lost(move || {
            if let Some(c) = weak_client.upgrade() {
                c.close(Some(StreamError::Protocol("DHCP lease lost".into())));
            }
        });
        let wb = Arc::downgrade(&bridge);
        client.set_on_frame(Some(Arc::new(move |f| {
            if let Some(b) = wb.upgrade() {
                b.from_hub(&f);
            }
        })));
        let wb = Arc::downgrade(&bridge);
        tun.set_on_packet(Box::new(move |p| {
            if let Some(b) = wb.upgrade() {
                b.from_host(&p);
            }
        }));
        let (weak_session, link_down, auto_reconnect) = (self.me.clone(), r.link_down.clone(), config.auto_reconnect);
        client.set_on_close(Some(Arc::new(move |err| {
            if let (Some(err), true, Some(s)) = (err, auto_reconnect, weak_session.upgrade()) {
                if s.is_current(gen) {
                    s.set(gen, ConnectionState::Reconnecting, None, None, Some(format!("Link closed: {err}")), None);
                }
            }
            link_down.fire();
        })));

        let tun_name = tun.name();
        self.set(gen, ConnectionState::Dhcp, None, None, Some(format!("Requesting address on {tun_name}")), None);
        let lease = bridge.acquire_lease().await.map_err(|e| EstablishError::Failed(e.to_string()))?;
        if !self.is_current(gen) {
            return Err(EstablishError::Cancelled);
        }
        bridge.gratuitous_arp();
        let net = (self.deps.make_net)();
        if !self.with_resources(r, |s| s.net = Some(net.clone())) {
            return Err(EstablishError::Cancelled);
        }
        let mut connected_log = format!("Connected via {tun_name}, gateway {}", ip_string(lease.router));
        let dns_strings: Vec<String> = lease.dns.iter().map(|d| ip_string(*d)).collect();
        if socks_mode {
            // Nothing global changes: no default route, resolver or IPv6 capture. The proxy is the only way in.
            net.apply_socks(&tun_name, &lease, config.mtu)?;
            let port = config.socks_port.clamp(0, i64::from(u16::MAX)) as u16;
            let server = (self.deps.make_socks)(port, &tun_name, dns_strings);
            server.start()?;
            if !self.with_resources(r, |s| s.socks = Some(server.clone())) {
                server.stop();
                return Err(EstablishError::Cancelled);
            }
            connected_log = format!("SOCKS5 proxy on 127.0.0.1:{} via {tun_name}", server.bound_port());
            tun.start_reading();
        } else {
            // The address the TLS connection really went to, not a second lookup of the name (which could differ, or
            // fail).
            let primary_bypass = if config.proxy.kind != ProxyKind::None {
                config.proxy.host.clone()
            } else if validation::is_ipv4_literal(&config.host) {
                config.host.clone()
            } else {
                client.remote_ipv4().unwrap_or_else(|| config.host.clone())
            };
            // Domain rules need a resolver of our own: IP/CIDR rules alone are handled entirely by routes.
            let needs_dns_proxy = config
                .routing
                .as_ref()
                .is_some_and(|rc| rc.effective_rules().iter().any(|rule| rule.enabled && rule.rule_type.is_domain()));
            let dns_proxy = if needs_dns_proxy {
                let proxy = (self.deps.make_dns_proxy)(net.clone(), config.routing.clone().unwrap_or_default())?;
                proxy.start()?;
                Some(proxy)
            } else {
                None
            };
            if !self.with_resources(r, |s| s.dns_proxy = dns_proxy.clone()) {
                if let Some(p) = &dns_proxy {
                    p.stop();
                }
                return Err(EstablishError::Cancelled);
            }
            net.apply(&NetApply {
                iface: tun_name.clone(),
                lease: lease.clone(),
                bypass_host: primary_bypass.clone(),
                block_ipv6: config.block_ipv6,
                mtu_override: config.mtu,
                routing: config.routing.clone(),
                dns_proxy_address: needs_dns_proxy.then(|| DNS_PROXY_LISTEN_ADDRESS.to_string()),
            })?;
            if let Some(p) = &dns_proxy {
                p.set_servers(dns_strings, net.direct_dns_servers());
            }
            // After a cluster redirect the data flows to another host, and UDP acceleration to its own endpoint: both
            // need their own route around the tunnel.
            for h in client.bypass_hosts() {
                if h != primary_bypass {
                    net.add_bypass(&h);
                }
            }
            // IPv6 (only when not blocked): put the SLAAC address on the tun once a router advertises a prefix.
            let wn = Arc::downgrade(&net);
            bridge.start_ipv6(move |address, prefix_length| {
                if let Some(n) = wn.upgrade() {
                    n.configure_ipv6(std::net::Ipv6Addr::from(address), prefix_length);
                }
            });
            tun.start_reading();
        }

        self.set(gen, ConnectionState::Connected, None, Some(&ip_string(lease.ip)), Some(connected_log), None);
        let counters = self.spawn_counters(gen, &client);
        let wait = (f64::from(lease.seconds) / 2.0).max(self.timing.min_renew_seconds);
        let wb = Arc::downgrade(&bridge);
        let renew = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs_f64(wait)).await;
                let Some(b) = wb.upgrade() else { return };
                b.renew().await;
            }
        });
        let (c2, r2) = (counters.abort_handle(), renew.abort_handle());
        if !self.with_resources(r, |s| {
            s.counters = Some(counters);
            s.renew = Some(renew);
        }) {
            c2.abort();
            r2.abort();
            return Err(EstablishError::Cancelled);
        }
        Ok(())
    }

    fn spawn_counters(&self, gen: u64, client: &Arc<dyn VpnTransport>) -> JoinHandle<()> {
        let (weak_session, weak_client) = (self.me.clone(), Arc::downgrade(client));
        tokio::spawn(async move {
            let mut tick =
                tokio::time::interval_at(tokio::time::Instant::now() + Duration::from_secs(1), Duration::from_secs(1));
            loop {
                tick.tick().await;
                let (Some(s), Some(c)) = (weak_session.upgrade(), weak_client.upgrade()) else { return };
                let mut st = s.state();
                if st.generation != gen {
                    return;
                }
                st.current.bytes_in = c.bytes_in();
                st.current.bytes_out = c.bytes_out();
                st.current.log = None;
                st.current.error = None;
                let e = st.current.clone();
                drop(st);
                s.emit_event(e);
            }
        })
    }

    /// Stops traffic first, then removes routes, then closes the tun. Safe to call more than once.
    fn release(&self, r: &Resources) {
        let slots = std::mem::take(&mut *lock(&r.slots));
        let Slots { client, tun, net, dns_proxy, socks, bridge, counters, renew } = slots;
        for h in [counters, renew].into_iter().flatten() {
            h.abort();
        }
        if let Some(c) = &client {
            c.set_on_close(None);
            c.close(None);
        }
        r.link_down.fire();
        if let Some(s) = socks {
            s.stop();
        }
        if let Some(d) = dns_proxy {
            d.stop();
        }
        if let Some(n) = net {
            n.teardown();
        }
        if let Some(t) = tun {
            t.close();
        }
        drop(bridge);
    }
}

impl SessionControlling for Session {
    fn set_emit(&self, emit: Option<EmitFn>) {
        Session::set_emit(self, emit);
    }

    fn snapshot(&self) -> HelperEvent {
        Session::snapshot(self)
    }

    fn connect(&self, config: ConnectConfig) {
        Session::connect(self, config);
    }

    fn disconnect(&self) {
        Session::disconnect(self);
    }
}

#[cfg(test)]
mod tests;
