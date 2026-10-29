//! The engine end to end in this process: IPC lines in and out, and a full connect against a fake relay whose tunnel
//! is a socket pair standing in for the descriptor `VpnService` hands over.

use std::os::fd::RawFd;
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{json, Value};
use vpngate_core::packets::ipv4_parse;
use vpngate_net::connection_pool::{CloseFn, FrameFn};
use vpngate_net::session::VpnTransport;
use vpngate_net::softether_client::Welcome;
use vpngate_net::stream::StreamError;
use vpngate_net::testing::fake_network::FakeNetworkServer;

use super::*;

/// The protector is process-wide, so engines of different tests must not overlap.
static ONE_ENGINE_AT_A_TIME: Mutex<()> = Mutex::new(());

fn serial() -> MutexGuard<'static, ()> {
    lock(&ONE_ENGINE_AT_A_TIME)
}

struct Host {
    tun_fd: RawFd,
    plans: Mutex<Vec<TunnelPlanRecord>>,
    protected: Mutex<Vec<i32>>,
    closed: Mutex<u32>,
}

impl VpnHostCallbacks for Host {
    fn establish(&self, plan: TunnelPlanRecord) -> EstablishResult {
        lock(&self.plans).push(plan);
        EstablishResult { fd: self.tun_fd, error: None }
    }
    fn protect(&self, fd: i32) -> bool {
        lock(&self.protected).push(fd);
        true
    }
    fn tunnel_closed(&self) {
        *lock(&self.closed) += 1;
    }
}

struct Lines(Mutex<std::sync::mpsc::Sender<Value>>);

impl LineListener for Lines {
    fn on_line(&self, line: String) {
        let _ = lock(&self.0).send(serde_json::from_str(&line).expect("every line is JSON"));
    }
}

/// Answers DHCP and ARP from the fake network and records what the client sent.
struct Relay {
    network: FakeNetworkServer,
    on_frame: Mutex<Option<FrameFn>>,
    ipv4_dst: Mutex<Vec<u32>>,
}

#[async_trait]
impl VpnTransport for Relay {
    fn set_on_frame(&self, f: Option<FrameFn>) {
        *lock(&self.on_frame) = f;
    }
    fn set_on_close(&self, _f: Option<CloseFn>) {}
    fn bytes_in(&self) -> u64 {
        0
    }
    fn bytes_out(&self) -> u64 {
        0
    }
    async fn connect(&self, _log: &mut (dyn for<'a> FnMut(&'a str) + Send)) -> Result<Welcome, StreamError> {
        Ok(Welcome {
            session_name: "SID-TEST".into(),
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
    fn send_frame(&self, frame: Vec<u8>) {
        if let Some(ip) = frame.get(14..).and_then(ipv4_parse) {
            lock(&self.ipv4_dst).push(ip.dst);
        }
        let replies = self.network.handle(&frame);
        if let Some(f) = lock(&self.on_frame).clone() {
            replies.into_iter().for_each(|r| f(r));
        }
    }
    fn close(&self, _error: Option<StreamError>) {}
}

struct Fixture {
    engine: Arc<AndroidEngine>,
    lines: Receiver<Value>,
    host: Arc<Host>,
    /// The Kotlin-side end of the fake tun.
    vpn_end: RawFd,
    relay: Arc<Relay>,
    _dir: std::path::PathBuf,
}

impl Fixture {
    fn new() -> Fixture {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` has room for two descriptors; datagrams keep packet boundaries like a tun.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) }, 0);
        let host = Arc::new(Host {
            tun_fd: fds[0],
            plans: Mutex::default(),
            protected: Mutex::default(),
            closed: Mutex::default(),
        });
        let (tx, lines) = channel();
        let relay = Arc::new(Relay {
            network: FakeNetworkServer::new(),
            on_frame: Mutex::default(),
            ipv4_dst: Mutex::default(),
        });
        let dir = std::env::temp_dir().join(format!(
            "vpngate-uniffi-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let bundle = concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/Fixtures/VPNGate.dat").to_string();
        let transport = relay.clone();
        let engine = AndroidEngine::build(
            dir.to_string_lossy().into_owned(),
            Some(bundle),
            host.clone(),
            Arc::new(Lines(Mutex::new(tx))),
            move |deps| deps.make_transport = Arc::new(move |_, _| transport.clone() as Arc<dyn VpnTransport>),
        )
        .unwrap();
        Fixture { engine, lines, host, vpn_end: fds[1], relay, _dir: dir }
    }

    /// The next line for which `want` holds (other lines, such as periodic state events, are skipped).
    fn wait_for(&self, what: &str, want: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(v) if want(&v) => return v,
                Ok(_) => {}
                Err(_) => panic!("timed out waiting for {what}"),
            }
        }
    }

    fn state(&self, state: &str) -> Value {
        self.wait_for(state, |v| v["state"] == state)
    }

    fn reply(&self, cmd: &str, id: u64) -> Value {
        self.wait_for(cmd, |v| v["reply"] == cmd && v["id"] == id)
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.engine.shutdown();
        // SAFETY: our end of the pair, closed once.
        unsafe { libc::close(self.vpn_end) };
        let _ = std::fs::remove_dir_all(&self._dir);
    }
}

#[test]
fn first_line_is_the_state_snapshot_with_the_protocol_version() {
    let _one = serial();
    let f = Fixture::new();
    let first = f.lines.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(first["state"], "disconnected");
    assert_eq!(first["ipcVersion"], engine_ipc_version());
}

#[test]
fn list_servers_answers_from_the_bundled_list() {
    let _one = serial();
    let f = Fixture::new();
    f.engine.send(json!({"cmd": "listServers", "id": 1}).to_string());
    let reply = f.reply("listServers", 1);
    assert_eq!(reply["ok"], true, "{reply}");
    assert!(reply["result"]["servers"].as_array().is_some_and(|s| !s.is_empty()));
    assert_eq!(reply["result"]["source"], "Built-in");
}

#[test]
fn validate_account_and_unknown_commands_follow_the_ipc_rules() {
    let _one = serial();
    let f = Fixture::new();
    f.engine.send(json!({"cmd": "validateAccount", "id": 7}).to_string());
    let reply = f.reply("validateAccount", 7);
    assert_eq!(reply["ok"], false);

    f.engine.send(json!({"cmd": "status"}).to_string());
    f.state("disconnected");
}

#[test]
fn a_connect_builds_the_tunnel_from_the_lease_and_carries_packets() {
    let _one = serial();
    let f = Fixture::new();
    f.relay.network.configure(|c| c.dns = vec![0x0808_0808]);
    f.engine.send(json!({"cmd": "connect", "host": "198.51.100.1", "port": 443, "autoReconnect": false}).to_string());
    let connected = f.state("connected");
    assert!(connected["virtualIP"].is_string(), "{connected}");

    let plans = lock(&f.host.plans).clone();
    assert_eq!(plans.len(), 1);
    let cfg = f.relay.network.config();
    assert_eq!(plans[0].address, std::net::Ipv4Addr::from(cfg.offered_ip).to_string());
    assert_eq!(plans[0].routes, ["0.0.0.0/0"]);
    assert_eq!(plans[0].dns_servers, ["8.8.8.8"]);
    assert!(plans[0].block_ipv6);

    // A packet the phone's apps write reaches the relay as an Ethernet frame.
    let packet = vpngate_core::packets::ipv4_packet(17, cfg.offered_ip, 0x0808_0808, &[0u8; 12]);
    // SAFETY: `vpn_end` is an open datagram socket and `packet` is valid for its length.
    unsafe { libc::write(f.vpn_end, packet.as_ptr().cast(), packet.len()) };
    let deadline = Instant::now() + Duration::from_secs(5);
    while !lock(&f.relay.ipv4_dst).contains(&0x0808_0808) {
        assert!(Instant::now() < deadline, "the relay never saw the packet");
        std::thread::sleep(Duration::from_millis(20));
    }

    f.engine.send(json!({"cmd": "disconnect"}).to_string());
    f.state("disconnected");
    assert_eq!(*lock(&f.host.closed), 1);
}

#[test]
fn a_host_that_cannot_establish_fails_the_connect_with_its_reason() {
    let _one = serial();
    struct Refusing;
    impl VpnHostCallbacks for Refusing {
        fn establish(&self, _plan: TunnelPlanRecord) -> EstablishResult {
            EstablishResult { fd: -1, error: Some("VPN permission was revoked".into()) }
        }
        fn protect(&self, _fd: i32) -> bool {
            true
        }
        fn tunnel_closed(&self) {}
    }
    let (tx, lines) = channel();
    let relay =
        Arc::new(Relay { network: FakeNetworkServer::new(), on_frame: Mutex::default(), ipv4_dst: Mutex::default() });
    let dir = std::env::temp_dir().join(format!("vpngate-uniffi-refuse-{}", std::process::id()));
    let engine = AndroidEngine::build(
        dir.to_string_lossy().into_owned(),
        None,
        Arc::new(Refusing),
        Arc::new(Lines(Mutex::new(tx))),
        move |deps| deps.make_transport = Arc::new(move |_, _| relay.clone() as Arc<dyn VpnTransport>),
    )
    .unwrap();
    engine.send(json!({"cmd": "connect", "host": "198.51.100.1", "autoReconnect": false}).to_string());
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let v = lines.recv_timeout(deadline.saturating_duration_since(Instant::now())).expect("no error line");
        if v["error"].as_str().is_some_and(|e| e.contains("permission was revoked")) {
            break;
        }
    }
    engine.shutdown();
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn the_host_protects_sockets_the_engine_opens() {
    let _one = serial();
    let f = Fixture::new();
    protect::protect(42).unwrap();
    assert_eq!(*lock(&f.host.protected), [42]);
    f.engine.shutdown();
    // After shutdown the protector is gone: no host call, no error.
    protect::protect(43).unwrap();
    assert_eq!(*lock(&f.host.protected), [42]);
}
