//! Network tests against real VPN Gate relays (port of `Tests/Live/LiveTests.swift`). All `#[ignore]`d: run with
//!   cargo test -p vpngate-daemon --test live -- --ignored --nocapture
//! They work from the signed list shipped with the app (`Tests/Fixtures/VPNGate.dat`), not from the CSV API, which is
//! blocked in some countries. Relays come and go, so a single dead relay is not a failure: a test passes when at
//! least one relay completes it. To use specific relays:
//!   VPNGATE_LIVE_RELAYS=150.40.105.12:443,219.100.37.59:443 cargo test ... -- --ignored

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use vpngate_core::cert_pin::ServerCertPolicy;
use vpngate_core::ipc::{ConnectConfig, ProxySettings};
use vpngate_core::{validation, vgdat};
use vpngate_net::dat_fetcher::{DatFetcher, DatFetcherConfig};
use vpngate_net::session::tls_stream_factory;
use vpngate_net::stream::ByteStream;
use vpngate_net::tls::TlsStream;

/// Relays to try: the override from the environment, else the bundled list (port 443 first, best score first).
fn live_relays(limit: usize) -> Vec<(String, u16)> {
    if let Some(raw) = std::env::var("VPNGATE_LIVE_RELAYS").ok().filter(|r| !r.is_empty()) {
        return raw
            .split(',')
            .filter_map(|item| {
                let mut parts = item.split(':');
                let ip = parts.next().filter(|ip| validation::is_valid_host(ip))?;
                let port = parts.next().map_or(Some(443), |p| p.parse().ok())?;
                Some((ip.to_string(), port))
            })
            .collect();
    }
    let dat = std::fs::read(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/Fixtures/VPNGate.dat")).unwrap();
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_millis() as u64;
    let file = vgdat::parse(&dat, now).expect("bundled list must verify");
    let mut usable: Vec<_> =
        vgdat::parse_inner_servers(&file.inner).into_iter().filter(|s| !s.ssl_ports.is_empty()).collect();
    usable.sort_by(|a, b| {
        let (a443, b443) = (a.ssl_ports.contains(&443), b.ssl_ports.contains(&443));
        b443.cmp(&a443).then(b.score.cmp(&a.score))
    });
    usable
        .into_iter()
        .take(limit)
        .map(|s| (s.ip.clone(), if s.ssl_ports.contains(&443) { 443 } else { s.ssl_ports[0] }))
        .collect()
}

#[tokio::test]
#[ignore = "needs the network"]
async fn csv_api_reachable_when_the_network_allows() {
    // Informational: the legacy CSV list is the fallback source and is unreachable in some countries.
    let dir = std::env::temp_dir().join(format!("vg-live-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let streams = tls_stream_factory(&ConnectConfig::new(""));
    let fetcher = DatFetcher::new(streams, DatFetcherConfig::new(dir.join("VPNGate.dat")));
    match fetcher.fetch_csv(None).await {
        Ok(list) => {
            assert!(list.len() >= 10, "only {} servers", list.len());
            let ids: std::collections::HashSet<_> = list.iter().map(|s| s.id().to_string()).collect();
            assert_eq!(ids.len(), list.len(), "ids must be unique");
            assert!(list.iter().all(|s| validation::is_valid_host(&s.ip)), "invalid ip in list");
        }
        Err(e) => println!("    SKIPPED: CSV API unreachable from this network ({e}); relay tests do not need it"),
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
#[ignore = "needs the network"]
fn relay_handshake_and_dhcp() {
    let relays = live_relays(10);
    assert!(!relays.is_empty(), "no relays to try");
    let bin = env!("CARGO_BIN_EXE_vpngate-daemon");
    let (mut ok, mut report) = (0, Vec::new());
    for (ip, port) in relays {
        // One relay must not stall the run: kill the probe if it takes longer than 20 s.
        let mut child = Command::new(bin)
            .args(["--probe", &ip, "--port", &port.to_string()])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let start = std::time::Instant::now();
        let status = loop {
            if let Some(s) = child.try_wait().unwrap() {
                break Some(s);
            }
            if start.elapsed() > Duration::from_secs(20) {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        match status {
            Some(s) if s.success() => {
                ok += 1;
                report.push(format!("{ip}:{port} ok"));
            }
            Some(s) => report.push(format!("{ip}:{port} FAILED ({s})")),
            None => report.push(format!("{ip}:{port} FAILED (timeout)")),
        }
        if ok >= 3 {
            break;
        }
    }
    println!("    live report:");
    report.iter().for_each(|l| println!("      {l}"));
    assert!(
        ok >= 1,
        "no relay completed handshake + DHCP (network blocking VPN Gate, or all tried relays down): {report:?}"
    );
}

/// The accept half of the system-trust policy (`rustls-platform-verifier`): the hermetic suite only proves that a
/// self-signed certificate is refused, so this checks that a certificate chaining to a public CA is accepted.
#[tokio::test]
#[ignore = "needs the network"]
async fn system_trust_accepts_a_public_ca_certificate() {
    let mut tls = TlsStream::new("example.com", 443, &ProxySettings::default(), ServerCertPolicy::new(true, None));
    tls.start_with_timeout(Duration::from_secs(20)).await.expect("TLS handshake with a CA-signed host");
    tls.send(b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n").await.unwrap();
    let reply = tls.read_chunk().await.unwrap();
    let head = String::from_utf8_lossy(&reply[..reply.len().min(40)]).into_owned();
    assert!(reply.starts_with(b"HTTP/1."), "unexpected reply: {head:?}");
}

/// Runs `--probe` (full handshake + DHCP, a separate process) on one relay; `true` when it completed within 20 s.
fn full_handshake(ip: &str, port: u16) -> bool {
    let mut child = Command::new(env!("CARGO_BIN_EXE_vpngate-daemon"))
        .args(["--probe", ip, "--port", &port.to_string()])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let start = std::time::Instant::now();
    loop {
        if let Some(s) = child.try_wait().unwrap() {
            return s.success();
        }
        if start.elapsed() > Duration::from_secs(20) {
            let _ = child.kill();
            let _ = child.wait();
            return false;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// "Test Connection" (the `probe` request behind the "Test from this computer" column) against real relays, the way the
/// apps send it: Windows, GTK and Android 8 relays per request with the daemon's default timeout, macOS one request
/// with a 5 s timeout. Each relay's answer is then checked against a full handshake (`--probe`): a relay that the
/// full handshake reaches but Test Connection reports as failed is a false negative, which is what a broken test
/// looks like to a user. Relays come and go, so the test fails only when Test Connection is clearly wrong: no relay ok
/// while full handshakes work, most working relays missed, or measurements that are not plausible.
///   VPNGATE_LIVE_PROBE_COUNT (default 24): how many relays of the list to test.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs the network"]
async fn test_connection_like_the_apps() {
    use vpngate_core::ipc::ProbeTarget;
    use vpngate_daemon::engine::{Engine, DEFAULT_PROBE_TIMEOUT_SECONDS, PROBE_CONCURRENCY};

    let count: usize = std::env::var("VPNGATE_LIVE_PROBE_COUNT").ok().and_then(|c| c.parse().ok()).unwrap_or(24);
    let dir = std::env::temp_dir().join(format!("vg-live-probe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let bundle = PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Tests/Fixtures/VPNGate.dat"));
    let engine = Engine::production(dir.join("VPNGate.dat"), vec![bundle]);

    // The apps refresh the list first; the shipped list is the fallback when the sync gets nothing newer.
    let started = std::time::Instant::now();
    let list =
        match tokio::time::timeout(Duration::from_secs(150), engine.refresh_servers(&ProxySettings::default(), None))
            .await
        {
            Ok(Ok(l)) => l,
            other => {
                println!("    refresh failed ({other:?}); using the shipped list");
                engine.list_servers().expect("shipped list")
            }
        };
    println!(
        "    list: {} servers, source {:?}, fresh {}, outcome {:?} ({:.1} s)",
        list.servers.len(),
        list.source,
        list.is_fresh,
        list.outcome,
        started.elapsed().as_secs_f64()
    );
    let mut servers: Vec<_> = list.servers.into_iter().filter(|s| !s.ssl_ports.is_empty()).collect();
    servers.sort_by_key(|s| std::cmp::Reverse(s.score));
    servers.truncate(count);
    assert!(!servers.is_empty(), "no relay with an SSL port in the list");
    // What GTK, Windows and Android send: the relay's ports in the Windows client's order (the daemon keeps 3).
    let targets: Vec<ProbeTarget> = servers
        .iter()
        .map(|s| ProbeTarget {
            host: s.ip.clone(),
            ports: Some(s.prioritized_ssl_ports().into_iter().map(i64::from).collect()),
        })
        .collect();

    // Mode A: Windows / GTK / Android.
    let t = std::time::Instant::now();
    let mut batched = Vec::new();
    for batch in targets.chunks(PROBE_CONCURRENCY) {
        let bt = std::time::Instant::now();
        let r = engine.probe(batch.to_vec(), &ProxySettings::default(), DEFAULT_PROBE_TIMEOUT_SECONDS).await.unwrap();
        assert_eq!(r.results.len(), batch.len(), "one result per target");
        // A batch runs in parallel: at most 3 ports x timeout, plus slack; serial testing would take up to 8x longer.
        let limit = 3.0 * DEFAULT_PROBE_TIMEOUT_SECONDS + 10.0;
        assert!(bt.elapsed().as_secs_f64() < limit, "batch took {:.1} s (> {limit} s)", bt.elapsed().as_secs_f64());
        batched.extend(r.results);
    }
    let batched_secs = t.elapsed().as_secs_f64();

    // Mode B: the macOS app (one request with every relay, 5 s per port).
    let t = std::time::Instant::now();
    let mac = engine.probe(targets.clone(), &ProxySettings::default(), 5.0).await.unwrap().results;
    let mac_secs = t.elapsed().as_secs_f64();
    assert_eq!(mac.len(), targets.len(), "one result per target");

    let mut report = vec![format!(
        "{:<16} {:<20} {:>14} {:>14} {:>6}  full handshake",
        "relay", "ports", "apps (8/req)", "macOS (5 s)", "build"
    )];
    let (mut ok_apps, mut ok_mac, mut full_ok, mut missed_apps, mut missed_mac) = (0, 0, 0, 0, 0);
    let mut implausible = Vec::new();
    for ((s, a), m) in servers.iter().zip(&batched).zip(&mac) {
        for e in [a, m] {
            assert_eq!(e.host, s.ip, "results must keep the order of the request");
            if e.ok {
                let (c, h) = (e.connect_ms.unwrap_or(0), e.hello_ms.unwrap_or(0));
                if !(1..=60_000).contains(&c) || h < c || e.port.is_none() {
                    implausible.push(format!("{}: connect {c} ms, hello {h} ms, port {:?}", s.ip, e.port));
                }
            } else if e.error.as_deref().unwrap_or("").is_empty() {
                implausible.push(format!("{}: failed without a reason", s.ip));
            }
        }
        let port = a.port.or(m.port).unwrap_or_else(|| s.prioritized_ssl_ports()[0]);
        let full = full_handshake(&s.ip, port);
        ok_apps += a.ok as usize;
        ok_mac += m.ok as usize;
        full_ok += full as usize;
        missed_apps += (full && !a.ok) as usize;
        missed_mac += (full && !m.ok) as usize;
        let cell = |e: &vpngate_core::ipc::ProbeEntry| match (e.ok, e.connect_ms) {
            (true, Some(c)) => format!("{c} ms :{}", e.port.unwrap_or(0)),
            _ => e.error.clone().unwrap_or_default().chars().take(14).collect(),
        };
        let ports = format!("{:?}", s.prioritized_ssl_ports());
        report.push(format!(
            "{:<16} {:<20} {:>14} {:>14} {:>6}  {}{}",
            s.ip,
            ports,
            cell(a),
            cell(m),
            a.build.or(m.build).map_or("-".into(), |b| b.to_string()),
            if full { "ok" } else { "fail" },
            if full && !(a.ok && m.ok) { "   <-- MISSED by Test Connection" } else { "" }
        ));
    }
    println!("    Test Connection on {} ({} relays)", std::env::consts::OS, servers.len());
    report.iter().for_each(|l| println!("      {l}"));
    println!(
        "    apps: {ok_apps} ok in {batched_secs:.1} s; macOS mode: {ok_mac} ok in {mac_secs:.1} s; full handshake: {full_ok} ok"
    );
    println!("    missed (full handshake ok, Test Connection failed): apps {missed_apps}, macOS mode {missed_mac}");
    let _ = std::fs::remove_dir_all(dir);

    assert!(implausible.is_empty(), "implausible results: {implausible:?}");
    assert!(full_ok >= 1, "no relay completed a full handshake (network blocking VPN Gate, or all relays down)");
    assert!(ok_apps >= 1 && ok_mac >= 1, "Test Connection found no relay although {full_ok} full handshakes worked");
    // A relay can drop between the two checks, so a few misses are expected; most of them is a broken test.
    for (mode, missed) in [("apps", missed_apps), ("macOS", missed_mac)] {
        assert!(missed * 2 <= full_ok, "{mode}: Test Connection missed {missed} of {full_ok} working relays");
    }
}
