//! The real Wintun adapter, IP Helper routes and DNS driven by the real `Session`, against a fake relay in this process.
//! Needs Administrator rights and `wintun.dll` next to the test executable, so everything is `#[ignore]`d (CI runs it on a
//! disposable runner, see `scripts/get-wintun.ps1`):
//!   cargo test -p vpngate-daemon --test tunnel_windows -- --ignored --nocapture --test-threads=1
//!
//! Like the macOS test, only the documentation prefix 192.0.2.0/24 goes through the tunnel (default action `direct`), so the
//! machine's own default route is never replaced. Tests share the adapter name, hence `--test-threads=1`.
#![cfg(windows)]

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use common::EchoRelay;
use vpngate_core::ipc::{ConnectConfig, ConnectionState, HelperEvent, TunnelMode};
use vpngate_core::routing_rule::{RoutingAction, RoutingConfig, RoutingRule, RoutingRuleType};
use vpngate_daemon::backend::{cleanup_stale, platform_dependencies};
use vpngate_daemon::stale::StaleState;
use vpngate_net::session::{Session, SessionTiming, VpnTransport};

const ADAPTER: &str = "VPNGate";
/// TEST-NET-2: the (fake) relay's bypass route.
const RELAY_HOST: &str = "198.51.100.1";

fn ps(script: &str) -> String {
    let out = Command::new("powershell").args(["-NoProfile", "-NonInteractive", "-Command", script]).output().unwrap();
    String::from_utf8_lossy(&out.stdout).trim().to_string() + &String::from_utf8_lossy(&out.stderr)
}

fn command(program: &str, args: &[&str]) -> String {
    let out = Command::new(program).args(args).output().unwrap();
    String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
}

/// The interface alias Windows would use to reach `dest`.
fn route_alias(dest: &str) -> String {
    ps(&format!("(Find-NetRoute -RemoteIPAddress {dest} | Select-Object -First 1).InterfaceAlias")).trim().to_string()
}

/// Routes of the given prefix, one `prefix next-hop alias metric` line each (empty when none).
fn routes(prefix: &str) -> Vec<String> {
    lines(&ps(&format!(
        "Get-NetRoute -DestinationPrefix '{prefix}' -ErrorAction SilentlyContinue | ForEach-Object {{ \"$($_.DestinationPrefix) $($_.NextHop) $($_.InterfaceAlias) $($_.RouteMetric)\" }}"
    )))
}

fn lines(s: &str) -> Vec<String> {
    s.lines().map(str::trim).filter(|l| !l.is_empty()).map(String::from).collect()
}

/// Every route not on the tunnel adapter, without multicast, broadcast and link-local noise.
fn snapshot() -> Vec<String> {
    let mut v = lines(&ps(
        "Get-NetRoute | Where-Object { $_.InterfaceAlias -ne 'VPNGate' -and $_.DestinationPrefix -notlike '224.*' \
         -and $_.DestinationPrefix -notlike 'ff*' -and $_.DestinationPrefix -notlike 'fe80*' \
         -and $_.DestinationPrefix -ne '255.255.255.255/32' } | ForEach-Object { \"$($_.DestinationPrefix) $($_.NextHop) $($_.InterfaceAlias) $($_.RouteMetric)\" }",
    ));
    v.sort();
    v
}

fn adapter_present() -> bool {
    !ps(&format!("(Get-NetAdapter -Name '{ADAPTER}' -ErrorAction SilentlyContinue).Name")).trim().is_empty()
}

fn adapter_dns() -> Vec<String> {
    lines(&ps(&format!(
        "(Get-DnsClientServerAddress -InterfaceAlias '{ADAPTER}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses"
    )))
}

struct Run {
    session: Arc<Session>,
    relay: Arc<EchoRelay>,
}

fn temp_state(name: &str) -> PathBuf {
    std::env::temp_dir().join(format!("vg-{name}-{}.state", std::process::id()))
}

/// Starts a session against the fake relay and waits until it is connected.
async fn connect(state: &Path, tweak: impl FnOnce(&mut ConnectConfig)) -> Run {
    let relay = Arc::new(EchoRelay::new());
    let transport = relay.clone();
    let stale = Arc::new(StaleState::new(state));
    let deps = platform_dependencies(Arc::new(move |_, _| transport.clone() as Arc<dyn VpnTransport>), stale);
    let session = Session::new(deps, SessionTiming::default());

    let states: Arc<Mutex<Vec<HelperEvent>>> = Arc::default();
    let sink = states.clone();
    session.set_emit(Some(Arc::new(move |e| sink.lock().unwrap().push(e))));
    let mut cfg = ConnectConfig::new(RELAY_HOST);
    cfg.auto_reconnect = false;
    cfg.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::Cidr, "192.0.2.0/24", RoutingAction::Proxy)],
        default_action: RoutingAction::Direct,
        bypass_private_networks: false,
    });
    tweak(&mut cfg);
    session.connect(cfg);

    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let last = states.lock().unwrap().last().cloned();
        match last {
            Some(e) if e.state == ConnectionState::Connected => break,
            Some(e) if e.error.is_some() => panic!("session failed: {:?}", e.error),
            _ => {}
        }
        assert!(Instant::now() < deadline, "never connected: {:?}", states.lock().unwrap().last());
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    Run { session, relay }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Administrator and wintun.dll: creates an adapter and modifies routes"]
async fn only_the_documentation_prefix_goes_through_the_tunnel() {
    let before = snapshot();
    let default_before = route_alias("1.1.1.1");
    assert!(!adapter_present(), "a {ADAPTER} adapter is left over from an earlier run");

    let state = temp_state("hermetic");
    let run = connect(&state, |_| {}).await;

    assert!(adapter_present(), "the {ADAPTER} adapter should exist while connected");
    assert_eq!(route_alias("192.0.2.7"), ADAPTER, "192.0.2.7 should route into the tunnel");
    assert_eq!(route_alias("1.1.1.1"), default_before, "the default route must not change");
    assert!(!routes(&format!("{RELAY_HOST}/32")).is_empty(), "the relay bypass route is missing");
    // IPv6 is blocked by default: two /1 routes that lead nowhere.
    assert!(!routes("::/1").is_empty() && !routes("8000::/1").is_empty(), "IPv6 block routes are missing");
    let dns = adapter_dns();
    println!("adapter DNS: {dns:?}");
    assert!(!dns.is_empty(), "the tunnel's resolvers should be on the adapter");

    let ping = command("ping", &["-n", "3", "-w", "3000", "192.0.2.7"]);
    println!("{ping}");
    println!("frames the relay saw: {:?}", run.relay.seen.lock().unwrap());
    assert!(ping.contains("Reply from 192.0.2.7: bytes="), "no echo replies:\n{ping}");
    assert!(*run.relay.echo_requests.lock().unwrap() >= 1, "the relay never saw an echo request");

    run.session.disconnect();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(!adapter_present(), "the adapter should be gone after disconnect");
    assert_eq!(snapshot(), before, "routes must be restored exactly");
    assert_eq!(route_alias("1.1.1.1"), default_before);
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Administrator and wintun.dll: creates an adapter and modifies routes"]
async fn socks_mode_serves_a_proxy_and_leaves_the_machine_routing_alone() {
    const PORT: u16 = 10808;
    let before = snapshot();
    let default_before = route_alias("1.1.1.1");

    let state = temp_state("socks");
    let run = connect(&state, |c| {
        c.tunnel_mode = TunnelMode::SocksProxy;
        c.socks_port = i64::from(PORT);
        c.routing = None;
    })
    .await;

    assert_eq!(route_alias("1.1.1.1"), default_before, "SOCKS mode must not change the system default route");
    assert!(
        routes("0.0.0.0/1").is_empty() && routes("128.0.0.0/1").is_empty(),
        "no split default routes in SOCKS mode"
    );
    let scoped = routes("0.0.0.0/0").into_iter().filter(|r| r.contains(ADAPTER)).collect::<Vec<_>>();
    println!("scoped default: {scoped:?}");
    assert!(scoped.iter().any(|r| r.ends_with(" 9000")), "the metric-9000 scoped default is missing: {scoped:?}");

    // A SOCKS5 greeting (no authentication) must be answered with "version 5, no auth".
    let mut s = TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, PORT)), Duration::from_secs(5))
        .expect("the SOCKS5 proxy should listen on 127.0.0.1");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&[5, 1, 0]).unwrap();
    let mut reply = [0u8; 2];
    s.read_exact(&mut reply).unwrap();
    assert_eq!(reply, [5, 0], "SOCKS5 greeting reply");
    drop(s);

    run.session.disconnect();
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(TcpStream::connect_timeout(&SocketAddr::from((Ipv4Addr::LOCALHOST, PORT)), Duration::from_secs(2)).is_err());
    assert!(!adapter_present());
    assert_eq!(snapshot(), before, "routes must be restored exactly");
}

/// Run by `a_crashed_daemon_leaves_routes_that_the_next_start_removes` in a child process: connects and waits to be killed.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "child process of the crash test"]
async fn crash_child() {
    let Ok(state) = std::env::var("VG_CRASH_STATE") else { return };
    let _run = connect(Path::new(&state), |_| {}).await;
    println!("CHILD-CONNECTED");
    tokio::time::sleep(Duration::from_secs(600)).await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs Administrator and wintun.dll: creates an adapter and modifies routes"]
async fn a_crashed_daemon_leaves_routes_that_the_next_start_removes() {
    let before = snapshot();
    let state = temp_state("crash");
    let _ = std::fs::remove_file(&state);

    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--ignored", "--exact", "crash_child", "--nocapture", "--test-threads=1"])
        .env("VG_CRASH_STATE", &state)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let out = child.stdout.take().unwrap();
    std::thread::spawn(move || {
        for line in BufReader::new(out).lines().map_while(Result::ok) {
            println!("[child] {line}");
            if line.contains("CHILD-CONNECTED") {
                let _ = tx.send(());
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(60)).expect("the child never connected");
    assert!(!routes(&format!("{RELAY_HOST}/32")).is_empty(), "the child should have routed the relay");

    // A crash: no teardown runs.
    child.kill().unwrap();
    child.wait().unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let leftover = routes(&format!("{RELAY_HOST}/32"));
    println!("routes left by the crash: {leftover:?}, IPv6 block: {:?}", routes("::/1"));
    assert!(!leftover.is_empty(), "the killed child should have left its bypass route (else this test proves nothing)");

    // The next start undoes them from the undo list.
    cleanup_stale(&StaleState::new(&state));
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(!adapter_present(), "the adapter should be gone once the process died");
    assert_eq!(snapshot(), before, "stale cleanup must restore the routes exactly");
}
