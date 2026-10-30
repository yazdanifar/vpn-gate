//! Network tests against real VPN Gate relays (port of `Tests/Live/LiveTests.swift`). All `#[ignore]`d: run with
//!   cargo test -p vpngate-daemon --test live -- --ignored --nocapture
//! They work from the signed list shipped with the app (`Tests/Fixtures/VPNGate.dat`), not from the CSV API, which is
//! blocked in some countries. Relays come and go, so a single dead relay is not a failure: a test passes when at
//! least one relay completes it. To use specific relays:
//!   VPNGATE_LIVE_RELAYS=150.40.105.12:443,219.100.37.59:443 cargo test ... -- --ignored

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
