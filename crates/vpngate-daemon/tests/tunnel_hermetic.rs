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

mod common;

use common::EchoRelay;
use vpngate_core::ipc::{ConnectConfig, ConnectionState, HelperEvent};
use vpngate_core::routing_rule::{RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType};
use vpngate_daemon::backend::platform_dependencies;
use vpngate_daemon::stale::StaleState;
use vpngate_net::session::{Session, SessionTiming, VpnTransport};

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
        .map(|l| {
            let mut words: Vec<&str> = l.split_whitespace().collect();
            // The Expire column counts down on its own.
            if words.len() > 4 && words.last().is_some_and(|w| w.bytes().all(|b| b.is_ascii_digit())) {
                words.pop();
            }
            words.join(" ")
        })
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

    let relay = Arc::new(EchoRelay::new());
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
