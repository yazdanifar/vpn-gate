//! Ports of `SessionTests.swift` plus the SOCKS and bypass cases, run against fake transports, tun and network config.

use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;
use vpngate_core::ipc::{ConnectConfig, ConnectionState, ProxyKind, ProxySettings, TunnelMode, HELPER_VERSION};
use vpngate_core::packets::{be32, ethernet_frame, icmpv6_checksum, ipv4_packet, ipv6_header, ipv6_slaac, Mac};
use vpngate_core::routing_rule::{RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType};
use vpngate_testkit::fakes::{FakeNet, FakeTun};

use super::*;
use crate::testing::fake_network::FakeNetworkServer;

const MY_IP: u32 = 0x0AE9_91B6;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Holds a fake handshake open until released.
#[derive(Clone)]
struct Gate(Arc<watch::Sender<bool>>);

impl Gate {
    fn new() -> Self {
        Gate(Arc::new(watch::channel(false).0))
    }

    fn release(&self) {
        self.0.send_replace(true);
    }

    async fn wait(&self) {
        let _ = self.0.subscribe().wait_for(|open| *open).await;
    }
}

struct FakeTransport {
    port: u16,
    gate: Option<Gate>,
    connect_error: Option<String>,
    network: Arc<FakeNetworkServer>,
    bypass_hosts: Vec<String>,
    remote_ipv4: Option<String>,
    on_frame: Mutex<Option<FrameFn>>,
    on_close: Mutex<Option<CloseFn>>,
    closes: Mutex<usize>,
    sent: Mutex<Vec<Vec<u8>>>,
    bytes_out: Mutex<u64>,
}

impl FakeTransport {
    fn closes(&self) -> usize {
        *lock(&self.closes)
    }

    fn sent(&self) -> Vec<Vec<u8>> {
        lock(&self.sent).clone()
    }

    fn deliver(&self, frame: Vec<u8>) {
        let f = lock(&self.on_frame).clone();
        if let Some(f) = f {
            f(frame);
        }
    }

    /// The link dies underneath the session.
    fn drop_link(&self) {
        let f = lock(&self.on_close).clone();
        if let Some(f) = f {
            f(Some(StreamError::Closed));
        }
    }
}

#[async_trait]
impl VpnTransport for FakeTransport {
    fn set_on_frame(&self, f: Option<FrameFn>) {
        *lock(&self.on_frame) = f;
    }

    fn set_on_close(&self, f: Option<CloseFn>) {
        *lock(&self.on_close) = f;
    }

    fn bytes_in(&self) -> u64 {
        0
    }

    fn bytes_out(&self) -> u64 {
        *lock(&self.bytes_out)
    }

    async fn connect(&self, _log: &mut (dyn for<'a> FnMut(&'a str) + Send)) -> Result<Welcome, StreamError> {
        if let Some(g) = &self.gate {
            g.wait().await;
        }
        if let Some(e) = &self.connect_error {
            return Err(StreamError::Io(e.clone()));
        }
        Ok(Welcome {
            session_name: "SID-FAKE".into(),
            connection_name: "CID".into(),
            timeout_ms: 20000,
            message: None,
            session_key: None,
            max_connection: 1,
            use_compress: false,
            use_encrypt: true,
            half_connection: false,
            qos: false,
            enable_udp_recovery: false,
            use_udp_acceleration: false,
            udp_accel_version: 0,
            udp_server_ip: None,
            udp_server_port: None,
            udp_server_cookie: None,
            udp_client_cookie: None,
            udp_server_key: None,
            udp_fast_disconnect: false,
            udp_plaintext: false,
        })
    }

    fn bypass_hosts(&self) -> Vec<String> {
        self.bypass_hosts.clone()
    }

    fn remote_ipv4(&self) -> Option<String> {
        self.remote_ipv4.clone()
    }

    fn send_frame(&self, frame: Vec<u8>) {
        lock(&self.sent).push(frame.clone());
        *lock(&self.bytes_out) += frame.len() as u64;
        for r in self.network.handle(&frame) {
            let cb = lock(&self.on_frame).clone();
            if let Some(cb) = cb {
                tokio::spawn(async move { cb(r) });
            }
        }
    }

    fn close(&self, error: Option<StreamError>) {
        *lock(&self.closes) += 1;
        let f = lock(&self.on_close).clone();
        if let Some(f) = f {
            f(error);
        }
    }
}

struct FakeDnsProxy {
    listening: AtomicBool,
    servers: Mutex<Option<(Vec<String>, Vec<String>)>>,
}

impl DnsProxyService for FakeDnsProxy {
    fn start(&self) -> Result<(), PlatformError> {
        self.listening.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn stop(&self) {
        self.listening.store(false, Ordering::SeqCst);
    }

    fn set_servers(&self, tunnel: Vec<String>, direct: Vec<String>) {
        *lock(&self.servers) = Some((tunnel, direct));
    }
}

struct FakeSocks {
    port: u16,
    running: AtomicBool,
}

impl SocksService for FakeSocks {
    fn start(&self) -> Result<(), PlatformError> {
        self.running.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn bound_port(&self) -> u16 {
        self.port
    }

    fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

type GateFor = Box<dyn Fn(&str) -> Option<Gate> + Send + Sync>;
type FailFor = Box<dyn Fn(&str, u16) -> bool + Send + Sync>;

#[derive(Default)]
struct Harness {
    network: Arc<FakeNetworkServer>,
    transports: Mutex<Vec<Arc<FakeTransport>>>,
    tuns: Mutex<Vec<Arc<FakeTun>>>,
    nets: Mutex<Vec<Arc<FakeNet>>>,
    dns_proxies: Mutex<Vec<Arc<FakeDnsProxy>>>,
    socks: Mutex<Vec<Arc<FakeSocks>>>,
    gate_for: Mutex<Option<GateFor>>,
    fail_for: Mutex<Option<FailFor>>,
    tun_error: Mutex<Option<String>>,
    bypass_hosts: Mutex<Vec<String>>,
    remote_ipv4: Mutex<Option<String>>,
}

impl Harness {
    fn new() -> Arc<Self> {
        Arc::default()
    }

    fn fail_all(&self) {
        *lock(&self.fail_for) = Some(Box::new(|_, _| true));
    }

    fn transports(&self) -> Vec<Arc<FakeTransport>> {
        lock(&self.transports).clone()
    }

    fn ports(&self) -> Vec<u16> {
        self.transports().iter().map(|t| t.port).collect()
    }

    fn tuns(&self) -> Vec<Arc<FakeTun>> {
        lock(&self.tuns).clone()
    }

    fn nets(&self) -> Vec<Arc<FakeNet>> {
        lock(&self.nets).clone()
    }

    fn deps(self: &Arc<Self>) -> SessionDependencies {
        let (h1, h2, h3, h4, h5) = (self.clone(), self.clone(), self.clone(), self.clone(), self.clone());
        SessionDependencies {
            make_transport: Arc::new(move |config, port| {
                let t = Arc::new(FakeTransport {
                    port,
                    gate: lock(&h1.gate_for).as_ref().and_then(|f| f(&config.host)),
                    connect_error: lock(&h1.fail_for)
                        .as_ref()
                        .is_some_and(|f| f(&config.host, port))
                        .then(|| "test error".to_string()),
                    network: h1.network.clone(),
                    bypass_hosts: lock(&h1.bypass_hosts).clone(),
                    remote_ipv4: lock(&h1.remote_ipv4).clone(),
                    on_frame: Mutex::default(),
                    on_close: Mutex::default(),
                    closes: Mutex::default(),
                    sent: Mutex::default(),
                    bytes_out: Mutex::default(),
                });
                lock(&h1.transports).push(t.clone());
                t
            }),
            make_tun: Arc::new(move || {
                if let Some(e) = lock(&h2.tun_error).clone() {
                    return Err(PlatformError(e));
                }
                let t = FakeTun::new(&format!("utunF{}", lock(&h2.tuns).len()));
                lock(&h2.tuns).push(t.clone());
                Ok(t as Arc<dyn TunDevice>)
            }),
            make_net: Arc::new(move || {
                let n = FakeNet::new();
                lock(&h3.nets).push(n.clone());
                n
            }),
            make_dns_proxy: Arc::new(move |_net, _routing| {
                let p = Arc::new(FakeDnsProxy { listening: AtomicBool::new(false), servers: Mutex::default() });
                lock(&h4.dns_proxies).push(p.clone());
                Ok(p as Arc<dyn DnsProxyService>)
            }),
            make_socks: Arc::new(move |port, _iface, _dns| {
                let s = Arc::new(FakeSocks { port, running: AtomicBool::new(false) });
                lock(&h5.socks).push(s.clone());
                s
            }),
        }
    }

    fn timing() -> SessionTiming {
        SessionTiming {
            reconnect_delay: 0.05,
            bridge: BridgeTiming { dhcp_timeout: 0.5, dhcp_retries: 2, ..BridgeTiming::default() },
            ..SessionTiming::default()
        }
    }

    fn session(self: &Arc<Self>) -> (Arc<Session>, Recorder) {
        self.session_with(Self::timing())
    }

    fn session_with(self: &Arc<Self>, timing: SessionTiming) -> (Arc<Session>, Recorder) {
        let s = Session::new(self.deps(), timing);
        let r = Recorder::default();
        let events = r.events.clone();
        s.set_emit(Some(Arc::new(move |e| lock(&events).push(e))));
        (s, r)
    }
}

#[derive(Default)]
struct Recorder {
    events: Arc<Mutex<Vec<HelperEvent>>>,
}

impl Recorder {
    fn states(&self) -> Vec<ConnectionState> {
        lock(&self.events).iter().map(|e| e.state).collect()
    }

    fn last(&self) -> Option<HelperEvent> {
        lock(&self.events).last().cloned()
    }

    /// States with consecutive duplicates collapsed.
    fn order(&self) -> Vec<ConnectionState> {
        let mut out: Vec<ConnectionState> = Vec::new();
        for s in self.states() {
            if out.last() != Some(&s) {
                out.push(s);
            }
        }
        out
    }

    async fn wait_for(&self, state: ConnectionState, server: Option<&str>) -> bool {
        eventually(5.0, || {
            let ev = lock(&self.events);
            ev.iter().any(|e| e.state == state && server.is_none_or(|s| e.server.as_deref() == Some(s)))
                && ev.last().is_some_and(|e| e.state == state)
        })
        .await
    }

    async fn wait_connected(&self) {
        assert!(self.wait_for(ConnectionState::Connected, None).await, "never connected; states {:?}", self.states());
    }
}

async fn eventually(secs: f64, cond: impl Fn() -> bool) -> bool {
    let end = tokio::time::Instant::now() + Duration::from_secs_f64(secs);
    while tokio::time::Instant::now() < end {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    cond()
}

async fn idle(s: &Session, secs: u64) {
    assert!(s.wait_until_idle(Duration::from_secs(secs)).await, "run task did not finish");
}

fn simple(host: &str, port: Option<i64>, auto_reconnect: bool, block_ipv6: bool) -> ConnectConfig {
    simple_connect_config(host, port, ProxySettings::default(), auto_reconnect, block_ipv6)
}

fn hex6(s: &str) -> [u8; 16] {
    s.parse::<Ipv6Addr>().unwrap().octets()
}

fn host_packet(dst: u32) -> Vec<u8> {
    ipv4_packet(6, MY_IP, dst, &[9, 9, 9, 9])
}

fn ipv4_frame(dst_mac: Mac, src: u32, dst: u32) -> Vec<u8> {
    ethernet_frame(dst_mac, [0, 1, 2, 3, 4, 5], 0x0800, &ipv4_packet(6, src, dst, &[1, 2, 3, 4]))
}

macro_rules! session_test {
    ($name:ident, $body:expr) => {
        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn $name() {
            $body.await
        }
    };
}

session_test!(connects_through_all_states_and_configures_network, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", Some(995), false, true));
    r.wait_connected().await;
    use ConnectionState::*;
    assert_eq!(r.order(), [Connecting, Authenticating, Dhcp, Connected]);
    let last = r.last().unwrap();
    assert_eq!(last.virtual_ip.as_deref(), Some("10.233.145.182"));
    assert_eq!(last.server.as_deref(), Some("1.2.3.4"));
    assert_eq!((h.tuns().len(), h.nets().len()), (1, 1));
    let applied = h.nets()[0].applied();
    assert_eq!(applied[0].bypass_host, "1.2.3.4");
    assert_eq!(applied[0].iface, "utunF0");
    assert!(h.tuns()[0].is_reading(), "tun must be reading once configured");
    assert_eq!(h.transports()[0].port, 995);
    s.disconnect();
    idle(&s, 3).await;
    assert_eq!(s.snapshot().state, Disconnected);
    assert_eq!(s.snapshot().server, None);
    assert_eq!(h.nets()[0].torn_down(), 1);
    assert!(h.tuns()[0].is_closed());
    assert!(h.transports()[0].closes() >= 1);
});

session_test!(dns_proxy_is_started_only_when_domain_routing_rules_are_configured, async {
    let h = Harness::new();
    let (s, r) = h.session();
    let mut cfg = ConnectConfig::new("1.2.3.4");
    cfg.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::DomainSuffix, "example.com", RoutingAction::Direct)],
        ..RoutingConfig::default()
    });
    s.connect(cfg);
    r.wait_connected().await;
    let proxies = lock(&h.dns_proxies).clone();
    assert_eq!(proxies.len(), 1);
    assert!(proxies[0].listening.load(Ordering::SeqCst), "proxy should be listening while connected");
    let applied = h.nets()[0].applied();
    assert_eq!(applied[0].dns_proxy_address.as_deref(), Some(DNS_PROXY_LISTEN_ADDRESS));
    let servers = lock(&proxies[0].servers).clone().expect("servers set after the routes exist");
    assert_eq!(servers.0, ["10.233.254.254", "8.8.8.8"]);
    s.disconnect();
    idle(&s, 3).await;
    assert!(!proxies[0].listening.load(Ordering::SeqCst), "proxy must stop on disconnect");
});

session_test!(no_dns_proxy_for_ip_only_routing_rules, async {
    let h = Harness::new();
    let (s, r) = h.session();
    let mut cfg = ConnectConfig::new("1.2.3.4");
    cfg.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::Cidr, "10.0.0.0/8", RoutingAction::Direct)],
        ..RoutingConfig::default()
    });
    s.connect(cfg);
    r.wait_connected().await;
    assert_eq!(lock(&h.dns_proxies).len(), 0, "IP/CIDR rules alone are handled entirely by routes");
    assert_eq!(h.nets()[0].applied()[0].dns_proxy_address, None);
    s.disconnect();
});

session_test!(uses_proxy_host_for_the_bypass_route, async {
    let h = Harness::new();
    let (s, r) = h.session();
    let proxy = ProxySettings { kind: ProxyKind::Http, host: "10.9.9.9".into(), port: 3128, ..Default::default() };
    s.connect(simple_connect_config("1.2.3.4", None, proxy, false, true));
    r.wait_connected().await;
    assert_eq!(h.nets()[0].applied()[0].bypass_host, "10.9.9.9");
    s.disconnect();
});

session_test!(hostname_bypass_uses_the_address_the_connection_really_went_to, async {
    let h = Harness::new();
    *lock(&h.remote_ipv4) = Some("203.0.113.9".into());
    let (s, r) = h.session();
    s.connect(simple("vpn.example.org", None, false, true));
    r.wait_connected().await;
    assert_eq!(h.nets()[0].applied()[0].bypass_host, "203.0.113.9");
    s.disconnect();
});

session_test!(redirect_and_udp_peers_get_their_own_bypass_routes, async {
    let h = Harness::new();
    *lock(&h.bypass_hosts) = vec!["1.2.3.4".into(), "5.6.7.8".into()];
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    r.wait_connected().await;
    assert_eq!(h.nets()[0].bypassed(), ["5.6.7.8"], "the primary host already has its route");
    s.disconnect();
});

session_test!(disconnect_is_idempotent_and_safe_when_idle, async {
    let h = Harness::new();
    let (s, _r) = h.session();
    s.disconnect();
    s.disconnect();
    assert_eq!(s.snapshot().state, ConnectionState::Disconnected);
    idle(&s, 1).await;
});

session_test!(port_order_listed_port_first_then_defaults, async {
    let h = Harness::new();
    h.fail_all();
    let (s, _r) = h.session();
    s.connect(simple("1.2.3.4", Some(1889), false, true));
    idle(&s, 5).await;
    assert_eq!(h.ports(), [1889, 443, 992, 5555, 1194]);

    let h2 = Harness::new();
    h2.fail_all();
    let (s2, _r2) = h2.session();
    s2.connect(simple("1.2.3.4", Some(443), false, true));
    idle(&s2, 5).await;
    assert_eq!(h2.ports(), [443, 992, 5555, 1194], "no duplicate of the listed port");
});

session_test!(out_of_range_ports_do_not_trap, async {
    for bad in [70000, -5, 0, 65536] {
        let h = Harness::new();
        h.fail_all();
        let (s, _r) = h.session();
        s.connect(simple("1.2.3.4", Some(bad), false, true));
        idle(&s, 5).await;
        assert_eq!(h.ports(), [443, 992, 5555, 1194], "port {bad}");
    }
});

session_test!(falls_back_to_next_port_when_first_fails, async {
    let h = Harness::new();
    *lock(&h.fail_for) = Some(Box::new(|_, p| p == 1889));
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", Some(1889), false, true));
    r.wait_connected().await;
    assert_eq!(h.ports(), [1889, 443]);
    assert_eq!(h.transports()[0].closes(), 1, "failed transport is closed");
    s.disconnect();
});

session_test!(failure_reports_error_and_releases_resources, async {
    let h = Harness::new();
    *lock(&h.tun_error) = Some("test error".into());
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    idle(&s, 5).await;
    let last = r.last().unwrap();
    assert_eq!(last.state, ConnectionState::Disconnected);
    assert_eq!(last.error.as_deref(), Some("test error"));
    assert!(h.transports()[0].closes() >= 1, "transport must be closed when the tun cannot be created");
});

session_test!(dhcp_failure_tears_everything_down, async {
    let h = Harness::new();
    h.network.configure(|c| c.silent = true);
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    idle(&s, 5).await;
    let error = r.last().unwrap().error.unwrap_or_default();
    assert!(error.contains("DHCP"), "error {error}");
    assert!(h.tuns().iter().all(|t| t.is_closed()));
    assert_eq!(h.nets().len(), 0, "no routes before a lease");
});

session_test!(link_drop_reconnects_with_a_fresh_tunnel, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, true, true));
    r.wait_connected().await;
    h.transports()[0].drop_link();
    assert!(
        eventually(5.0, || h.transports().len() == 2
            && r.last().is_some_and(|e| e.state == ConnectionState::Connected))
        .await,
        "states {:?}",
        r.states()
    );
    assert!(r.states().contains(&ConnectionState::Reconnecting));
    assert_eq!(h.tuns().len(), 2);
    assert!(h.tuns()[0].is_closed());
    assert_eq!(h.nets()[0].torn_down(), 1, "old routes removed");
    assert_eq!(h.nets()[1].torn_down(), 0);
    s.disconnect();
    idle(&s, 3).await;
});

session_test!(link_drop_without_auto_reconnect_stays_down, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    r.wait_connected().await;
    h.transports()[0].drop_link();
    assert!(eventually(3.0, || r.last().is_some_and(|e| e.state == ConnectionState::Disconnected)).await);
    assert_eq!(r.last().unwrap().error.as_deref(), Some("Connection lost"));
    idle(&s, 3).await;
    assert_eq!(h.transports().len(), 1);
    assert_eq!(h.nets()[0].torn_down(), 1);
});

session_test!(gives_up_after_max_attempts, async {
    let h = Harness::new();
    h.fail_all();
    let mut t = Harness::timing();
    t.max_attempts = 2;
    let (s, r) = h.session_with(t);
    s.connect(simple("1.2.3.4", None, true, true));
    idle(&s, 5).await;
    assert_eq!(r.last().unwrap().error.as_deref(), Some("Gave up reconnecting"));
    assert_eq!(h.transports().len(), 4 * 3, "3 attempts x 4 default ports");
});

session_test!(custom_accounts_reconnect_policy_overrides_the_defaults, async {
    // The session default (fast timing) is 8 attempts; the account's own count and interval must win instead.
    let h = Harness::new();
    h.fail_all();
    let (s, r) = h.session();
    let mut cfg = ConnectConfig::new("1.2.3.4");
    cfg.reconnect_interval = Some(0.01);
    cfg.reconnect_count = Some(3);
    s.connect(cfg);
    idle(&s, 5).await;
    assert_eq!(r.last().unwrap().error.as_deref(), Some("Gave up reconnecting"));
    assert_eq!(h.transports().len(), 4 * 4, "reconnectCount=3 means 4 establishes x 4 default ports");
});

session_test!(custom_account_without_its_own_policy_keeps_the_session_default, async {
    let h = Harness::new();
    h.fail_all();
    let mut t = Harness::timing();
    t.max_attempts = 2;
    let (s, r) = h.session_with(t);
    s.connect(ConnectConfig::new("1.2.3.4"));
    idle(&s, 5).await;
    assert_eq!(r.last().unwrap().error.as_deref(), Some("Gave up reconnecting"));
    assert_eq!(h.transports().len(), 4 * 3, "maxAttempts=2 means 3 establishes x 4 default ports");
});

session_test!(user_disconnect_stops_reconnect_loop, async {
    let h = Harness::new();
    h.fail_all();
    let (s, _r) = h.session();
    s.connect(simple("1.2.3.4", None, true, true));
    tokio::time::sleep(Duration::from_millis(100)).await;
    s.disconnect();
    idle(&s, 3).await;
    let n = h.transports().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(h.transports().len(), n, "no attempts after disconnect");
});

session_test!(connect_disconnect_cycles_release_everything_once, async {
    let h = Harness::new();
    let (s, r) = h.session();
    for i in 0..40 {
        s.connect(simple("1.2.3.4", None, false, true));
        assert!(eventually(5.0, || r.last().is_some_and(|e| e.state == ConnectionState::Connected)).await, "cycle {i}");
        s.disconnect();
    }
    idle(&s, 5).await;
    assert!(h.nets().iter().all(|n| n.torn_down() == 1), "every applied config torn down once");
    assert!(h.tuns().iter().all(|t| t.is_closed()));
    assert_eq!(s.active_runs.load(Ordering::SeqCst), 0);
});

session_test!(reconnect_to_another_server_replaces_the_stale_attempt, async {
    let h = Harness::new();
    let gate = Gate::new();
    let g = gate.clone();
    *lock(&h.gate_for) = Some(Box::new(move |host| (host == "1.1.1.1").then(|| g.clone())));
    let (s, r) = h.session();
    s.connect(simple("1.1.1.1", None, true, true));
    assert!(eventually(3.0, || h.transports().len() == 1).await);
    s.connect(simple("2.2.2.2", None, true, true));
    assert!(r.wait_for(ConnectionState::Connected, Some("2.2.2.2")).await, "states {:?}", r.states());
    gate.release(); // the stale handshake now completes
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert_eq!(h.tuns().len(), 1, "stale attempt must not create a tun");
    assert_eq!(h.nets().len(), 1, "stale attempt must not touch routes");
    assert_eq!(h.nets()[0].applied()[0].bypass_host, "2.2.2.2");
    assert!(h.transports()[0].closes() >= 1, "stale transport closed");
    assert_eq!(s.snapshot().server.as_deref(), Some("2.2.2.2"));
    assert_eq!(s.snapshot().state, ConnectionState::Connected);
    s.disconnect();
    idle(&s, 3).await;
});

session_test!(block_ipv6_flag_reaches_the_network_config, async {
    for flag in [true, false] {
        let h = Harness::new();
        let (s, r) = h.session();
        s.connect(simple("1.2.3.4", None, false, flag));
        r.wait_connected().await;
        assert_eq!(h.nets()[0].applied()[0].block_ipv6, flag);
        s.disconnect();
    }
});

session_test!(custom_accounts_mtu_override_reaches_the_network_config, async {
    let h = Harness::new();
    let (s, r) = h.session();
    let mut cfg = ConnectConfig::new("1.2.3.4");
    cfg.mtu = Some(1300);
    s.connect(cfg);
    r.wait_connected().await;
    assert_eq!(h.nets()[0].applied()[0].mtu_override, Some(1300));
    s.disconnect();
});

session_test!(no_mtu_override_lets_the_dhcp_lease_decide, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(ConnectConfig::new("1.2.3.4"));
    r.wait_connected().await;
    assert_eq!(h.nets()[0].applied()[0].mtu_override, None);
    s.disconnect();
});

session_test!(ipv6_is_forwarded_and_addressed_only_when_not_blocked, async {
    for block in [true, false] {
        let h = Harness::new();
        let (s, r) = h.session();
        s.connect(simple("1.2.3.4", None, false, block));
        r.wait_connected().await;
        let (tun, t) = (h.tuns()[0].clone(), h.transports()[0].clone());
        assert_eq!(tun.forward_ipv6(), !block, "tun must hand IPv6 to the bridge only when allowed");
        // A Router Advertisement from the hub.
        let ours: [u8; 6] = t.sent()[0][6..12].try_into().unwrap();
        let (src, dst) = (hex6("fe80::1"), hex6("ff02::1"));
        let prefix = hex6("2001:db8:1:2::");
        let mut icmp = vec![134, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 2, 0, 0, 0, 0, 1];
        icmp.extend([3, 4, 64, 0xC0]);
        icmp.extend(be32(86400));
        icmp.extend(be32(14400));
        icmp.extend([0; 4]);
        icmp.extend(prefix);
        let c = icmpv6_checksum(&src, &dst, &icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let mut pkt = ipv6_header(&src, &dst, 58, icmp.len() as u16, 255);
        pkt.extend(&icmp);
        t.deliver(ethernet_frame([0x33, 0x33, 0, 0, 0, 1], [2, 0, 0, 0, 0, 1], 0x86DD, &pkt));
        if block {
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(h.nets()[0].ipv6_addresses().is_empty(), "blocked: no IPv6 address");
        } else {
            assert!(
                eventually(5.0, || h.nets()[0].ipv6_addresses().len() == 1).await,
                "SLAAC address never reached the network config"
            );
            assert_eq!(h.nets()[0].ipv6_addresses()[0], Ipv6Addr::from(ipv6_slaac(&prefix, &ours)));
        }
        s.disconnect();
        idle(&s, 3).await;
    }
});

session_test!(idle_snapshot_already_carries_the_helper_version, async {
    let h = Harness::new();
    let (s, _r) = h.session();
    assert_eq!(s.snapshot().helper_version, Some(HELPER_VERSION));
});

session_test!(events_carry_the_helper_version, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    r.wait_connected().await;
    assert_eq!(r.last().unwrap().helper_version, Some(HELPER_VERSION));
    s.disconnect();
});

session_test!(lost_dhcp_lease_triggers_a_reconnect, async {
    let h = Harness::new();
    h.network.configure(|c| c.lease_seconds = 1);
    let mut t = Harness::timing();
    t.min_renew_seconds = 0.05;
    t.bridge.dhcp_timeout = 0.2;
    let (s, r) = h.session_with(t);
    s.connect(simple("1.2.3.4", None, true, true));
    r.wait_connected().await;
    h.network.configure(|c| c.silent = true); // the server stops answering renewals
    assert!(
        eventually(6.0, || h.transports().len() >= 2).await,
        "no reconnect after the lease was lost; states {:?}",
        r.states()
    );
    assert_eq!(h.nets()[0].torn_down(), 1, "routes of the dead lease removed");
    s.disconnect();
    idle(&s, 3).await;
});

session_test!(counters_are_published_while_connected, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    r.wait_connected().await;
    assert!(
        eventually(4.0, || r.last().is_some_and(|e| e.bytes_out > 0)).await,
        "bytesOut should include the DHCP/ARP traffic"
    );
    s.disconnect();
});

session_test!(traffic_flows_both_ways_through_the_bridge, async {
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    r.wait_connected().await;
    let (tun, t) = (h.tuns()[0].clone(), h.transports()[0].clone());
    tun.inject(host_packet(0x0808_0808)); // host -> internet (gateway resolved via fake ARP)
    assert!(eventually(5.0, || h.network.ipv4_packets().len() == 1).await, "packet not forwarded to the hub");
    // hub -> host: find our MAC from what we sent
    let ours: Mac = t.sent().last().unwrap()[6..12].try_into().unwrap();
    t.deliver(ipv4_frame(ours, 0x0808_0808, MY_IP));
    assert!(eventually(5.0, || tun.written().len() == 1).await, "packet not delivered to the tun");
    s.disconnect();
});

session_test!(packets_read_on_a_plain_os_thread_still_reach_the_hub, async {
    // The real tun reader is a plain OS thread with no Tokio context (regression: "there is no reactor running").
    let h = Harness::new();
    let (s, r) = h.session();
    s.connect(simple("1.2.3.4", None, false, true));
    r.wait_connected().await;
    let tun = h.tuns()[0].clone();
    std::thread::spawn(move || tun.inject(host_packet(0x0808_0808))).join().unwrap();
    assert!(eventually(5.0, || h.network.ipv4_packets().len() == 1).await, "packet not forwarded to the hub");
    s.disconnect();
});

session_test!(socks_mode_starts_the_proxy_and_leaves_the_system_alone, async {
    let h = Harness::new();
    let (s, r) = h.session();
    let mut cfg = ConnectConfig::new("1.2.3.4");
    cfg.tunnel_mode = TunnelMode::SocksProxy;
    cfg.socks_port = 1081;
    cfg.block_ipv6 = false;
    s.connect(cfg);
    r.wait_connected().await;
    let net = h.nets()[0].clone();
    assert_eq!(net.socks_ifaces(), ["utunF0"]);
    assert!(net.applied().is_empty(), "no default route, resolver or IPv6 capture in SOCKS mode");
    assert!(!h.tuns()[0].forward_ipv6(), "no IPv6 in SOCKS mode");
    let socks = lock(&h.socks).clone();
    assert_eq!(socks.len(), 1);
    assert!(socks[0].running.load(Ordering::SeqCst));
    assert_eq!(r.last().unwrap().log.as_deref(), Some("SOCKS5 proxy on 127.0.0.1:1081 via utunF0"));
    assert!(h.tuns()[0].is_reading());
    s.disconnect();
    idle(&s, 3).await;
    assert!(!socks[0].running.load(Ordering::SeqCst), "proxy must stop on disconnect");
});

#[test]
fn legacy_config_puts_the_listed_port_first_and_keeps_the_vpn_gate_account() {
    let cfg = simple_connect_config("1.2.3.4", Some(995), ProxySettings::default(), false, true);
    assert_eq!(cfg.ports, [995]);
    assert_eq!(
        (cfg.hub_name.as_str(), cfg.user_name.as_str(), cfg.auth_type.as_str()),
        ("VPNGATE", "vpn", "anonymous")
    );
    assert_eq!(cfg.max_connection, 1);
    assert!(cfg.disable_qos);
    let cfg = legacy_connect_config(
        "h",
        Some(443),
        Some(vec![992, 443]),
        ProxySettings::default(),
        true,
        true,
        None,
        TunnelMode::FullTunnel,
        1080,
    );
    assert_eq!(cfg.ports, [992, 443], "a port already listed is not repeated");
    assert_eq!(simple_connect_config("h", None, ProxySettings::default(), true, true).ports, DEFAULT_PORTS);
}
