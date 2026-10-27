//! The real macOS tun, routes and net config driven by the real `Session`, against a fake relay in this process.
//! Needs root, so it is `#[ignore]`d:
//!   sudo -E cargo test -p vpngate-daemon --test tunnel_hermetic -- --ignored --nocapture
//!
//! Only the documentation prefix 192.0.2.0/24 is routed through the tunnel (default action `direct`, one `proxy` CIDR
//! rule) and the fake DHCP offers no DNS server, so the default route and the resolvers are never touched: it is safe
//! next to another VPN. IPv6 is the exception: `::/1` and `8000::/1` point at the tun while it is up (a few seconds).
#![cfg(target_os = "macos")]

use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use vpngate_core::ipc::{ConnectConfig, ConnectionState, HelperEvent};
use vpngate_core::packets::{checksum, ethernet_frame, ipv4_packet, ipv4_parse};
use vpngate_core::routing_rule::{RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType};
use vpngate_daemon::backend::platform_dependencies;
use vpngate_daemon::stale::StaleState;
use vpngate_net::connection_pool::{CloseFn, FrameFn};
use vpngate_net::session::{Session, SessionTiming, VpnTransport};
use vpngate_net::softether_client::Welcome;
use vpngate_net::stream::StreamError;
use vpngate_net::testing::fake_network::FakeNetworkServer;

/// A relay that answers DHCP/ARP like the testkit hub and echoes ICMP pings sent to 192.0.2.0/24.
struct EchoRelay {
    network: FakeNetworkServer,
    on_frame: Mutex<Option<FrameFn>>,
    echo_requests: Mutex<usize>,
    /// One line per frame the client sent: ethertype, and for IPv4 the protocol and destination.
    seen: Mutex<Vec<String>>,
    delivered: Mutex<usize>,
}

impl EchoRelay {
    fn echo_reply(&self, frame: &[u8]) -> Option<Vec<u8>> {
        let ip = ipv4_parse(frame.get(14..)?).filter(|ip| ip.proto == 1 && ip.dst >> 8 == 0x00C0_0002)?;
        if ip.payload.first() != Some(&8) {
            return None;
        }
        let mut icmp = ip.payload.clone();
        icmp[0] = 0;
        icmp[2..4].fill(0);
        let sum = checksum(&icmp).to_be_bytes();
        icmp[2..4].copy_from_slice(&sum);
        let packet = ipv4_packet(1, ip.dst, ip.src, &icmp);
        let (client, gateway) = (frame[6..12].try_into().ok()?, self.network.config().gateway_mac);
        Some(ethernet_frame(client, gateway, 0x0800, &packet))
    }
}

#[async_trait]
impl VpnTransport for EchoRelay {
    fn set_on_frame(&self, f: Option<FrameFn>) {
        *self.on_frame.lock().unwrap() = f;
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
            session_name: "SID-HERMETIC".into(),
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
        let summary = match frame.get(12..14) {
            Some([0x08, 0x00]) => ipv4_parse(&frame[14..])
                .map_or("ipv4 unparsable".into(), |ip| format!("ipv4 proto {} dst {:08x}", ip.proto, ip.dst)),
            Some(t) => format!("ethertype {:02x}{:02x}", t[0], t[1]),
            None => "runt".into(),
        };
        self.seen.lock().unwrap().push(summary);
        let replies = self.network.handle(&frame);
        let echo = self.echo_reply(&frame);
        *self.delivered.lock().unwrap() += replies.len() + usize::from(echo.is_some());
        let on_frame = self.on_frame.lock().unwrap().clone();
        let Some(f) = on_frame else { return };
        replies.into_iter().for_each(|r| f(r));
        if let Some(r) = echo {
            // A real relay answers from its own thread, never from inside the bridge's send path.
            *self.echo_requests.lock().unwrap() += 1;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                f(r);
            });
        }
    }
    fn close(&self, _error: Option<StreamError>) {}
}

fn sh(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// Routing table and resolver config without the volatile parts (same filter as `scripts/e2e-tunnel.sh`).
fn snapshot() -> Vec<String> {
    let all = format!(
        "{}{}{}",
        sh("netstat", &["-rn", "-f", "inet"]),
        sh("netstat", &["-rn", "-f", "inet6"]),
        sh("scutil", &["--dns"])
    );
    let mut lines: Vec<String> = all
        .lines()
        .filter(|l| {
            !["utun", "Expire", "Refs", "Use "].iter().any(|k| l.contains(k))
                && !is_neighbour_entry(l)
                && !is_cloned_host_entry(l)
        })
        .map(|l| l.split_whitespace().collect::<Vec<_>>().join(" "))
        .collect();
    lines.sort();
    lines
}

/// The kernel adds `x.x.x.x/32 link#N UCS` entries for on-link hosts it talked to (e.g. the gateway) on its own.
fn is_cloned_host_entry(l: &str) -> bool {
    l.contains("/32") && l.contains("link#")
}

/// A neighbour-cache entry (a line with a MAC address): changes on its own and is not ours.
fn is_neighbour_entry(l: &str) -> bool {
    l.split_whitespace().any(|w| w.split(':').count() == 6 && w.split(':').all(|p| (1..=2).contains(&p.len())))
}

fn route_interface(dest: &str) -> String {
    sh("route", &["-n", "get", dest])
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:"))
        .unwrap_or("?")
        .trim()
        .to_string()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs root: modifies routes and creates a utun"]
async fn only_the_documentation_prefix_goes_through_the_tunnel() {
    assert!(sh("id", &["-u"]).trim() == "0", "run with sudo");
    let before = snapshot();
    let default_before = route_interface("1.1.1.1");

    let relay = Arc::new(EchoRelay {
        network: FakeNetworkServer::new(),
        on_frame: Mutex::new(None),
        echo_requests: Mutex::new(0),
        seen: Mutex::default(),
        delivered: Mutex::new(0),
    });
    relay.network.configure(|c| c.dns.clear()); // no resolver change
    let transport = relay.clone();
    let stale =
        Arc::new(StaleState::new(std::env::temp_dir().join(format!("vg-hermetic-{}.state", std::process::id()))));
    let deps = platform_dependencies(Arc::new(move |_, _| transport.clone() as Arc<dyn VpnTransport>), stale);
    let session = Session::new(deps, SessionTiming::default());

    let states: Arc<Mutex<Vec<HelperEvent>>> = Arc::default();
    let sink = states.clone();
    session.set_emit(Some(Arc::new(move |e| sink.lock().unwrap().push(e))));
    let mut cfg = ConnectConfig::new("198.51.100.1"); // TEST-NET-2: the (fake) relay's bypass route
    cfg.auto_reconnect = false;
    cfg.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::Cidr, "192.0.2.0/24", RoutingAction::Proxy)],
        default_action: RoutingAction::Direct,
        bypass_private_networks: false,
    });
    session.connect(cfg);

    let deadline = Instant::now() + Duration::from_secs(20);
    let tun = loop {
        let last = states.lock().unwrap().last().cloned();
        match last {
            Some(e) if e.state == ConnectionState::Connected => break e.log.unwrap_or_default(),
            Some(e) if e.error.is_some() => panic!("session failed: {:?}", e.error),
            _ => {}
        }
        assert!(Instant::now() < deadline, "never connected: {:?}", states.lock().unwrap().last());
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    println!("connected: {tun}");

    let iface = route_interface("192.0.2.7");
    assert!(iface.starts_with("utun"), "192.0.2.7 should route into the tunnel, got {iface}");
    assert_eq!(route_interface("1.1.1.1"), default_before, "the default route must not change");

    let ping = sh("ping", &["-c", "3", "-t", "6", "192.0.2.7"]);
    println!("{ping}");
    println!("frames the relay saw: {:?}", relay.seen.lock().unwrap());
    println!("frames the relay answered with: {}", relay.delivered.lock().unwrap());
    println!("{}", sh("netstat", &["-I", &iface, "-b"]));
    println!("{}", sh("ifconfig", &[&iface]));
    assert!(
        ping.contains("3 packets received")
            || ping.contains("2 packets received")
            || ping.contains(" 0.0% packet loss"),
        "no echo replies:\n{ping}"
    );
    assert!(*relay.echo_requests.lock().unwrap() >= 1, "the relay never saw an echo request");

    session.disconnect();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(snapshot(), before, "routes and DNS must be restored exactly");
    assert_eq!(route_interface("1.1.1.1"), default_before);
}
