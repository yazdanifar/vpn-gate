//! `--probe`: handshake and DHCP only, no tun and no routes, so it runs without root (`main.swift`).

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use vpngate_core::ipc::{ConnectConfig, ProxySettings};
use vpngate_core::packets::ip_string;
use vpngate_net::connection::{ConnectOptions, ConnectionEvents, SoftEtherConnection};
use vpngate_net::entropy::{Entropy, SystemEntropy};
use vpngate_net::ethernet_bridge::{BridgeTiming, EthernetBridge};
use vpngate_net::host_unique_id::HostUniqueId;
use vpngate_net::session::tls_stream_factory;
use vpngate_net::softether_client::{ClientConfig, SoftEtherClient};

use crate::backend::client_environment;

/// Returns the process exit code: 0 on success, 1 on any failure.
pub async fn run_probe(host: &str, port: i64, watch_udp: Option<u64>) -> i32 {
    match probe(host, port, watch_udp).await {
        Ok(()) => 0,
        Err(m) => {
            println!("FAIL {m}");
            1
        }
    }
}

async fn probe(host: &str, port: i64, watch_udp: Option<u64>) -> Result<(), String> {
    let mut key = [0u8; 32];
    key.copy_from_slice(&SystemEntropy.bytes(32));
    let client = SoftEtherClient::new(
        ClientConfig::new(host, port as u16, ProxySettings::default()),
        HostUniqueId::new(key),
        tls_stream_factory(&ConnectConfig::new(host)),
        Box::new(SystemEntropy),
        client_environment(),
    );
    let bridge = EthernetBridge::new(BridgeTiming::default());
    let slot: Arc<OnceLock<Arc<SoftEtherConnection>>> = Arc::default();
    {
        let slot = slot.clone();
        bridge.set_send_frame(move |f| {
            if let Some(c) = slot.get() {
                c.send_frame(f);
            }
        });
    }
    let hub = bridge.clone();
    let events = ConnectionEvents { on_frame: Arc::new(move |f| hub.from_hub(&f)), on_close: Arc::new(|_| {}) };
    let conn = client
        .connect(&mut |m: &str| println!("  {m}"), events, ConnectOptions::default())
        .await
        .map_err(|e| e.to_string())?;
    let conn = Arc::new(conn);
    let _ = slot.set(conn.clone());
    let w = conn.welcome();
    println!("OK session {} timeout {}ms", w.session_name, w.timeout_ms);
    let l = bridge.acquire_lease().await.map_err(|e| e.to_string())?;
    let dns: Vec<String> = l.dns.iter().map(|d| ip_string(*d)).collect();
    println!(
        "OK lease ip {} mask {} gw {} dns {dns:?} {}s",
        ip_string(l.ip),
        ip_string(l.mask),
        ip_string(l.router),
        l.seconds
    );
    if let Some(seconds) = watch_udp {
        watch(&conn, seconds).await;
    }
    conn.close(None);
    Ok(())
}

/// Polls whether UDP acceleration became usable; it needs about 10 s of stable receive before data may use it.
async fn watch(conn: &SoftEtherConnection, seconds: u64) {
    println!(
        "  UDP negotiated: {} - watching for {seconds}s (needs ~10s stable receive before it carries data)",
        conn.udp_accel_negotiated()
    );
    let mut usable_at = None;
    for elapsed in 1..=seconds {
        tokio::time::sleep(Duration::from_secs(1)).await;
        if conn.udp_accel_usable() && usable_at.is_none() {
            usable_at = Some(elapsed);
            println!("  UDP became usable after {elapsed}s");
        }
    }
    match usable_at {
        Some(t) => println!("OK udp usable after {t}s (still usable: {})", conn.udp_accel_usable()),
        None if conn.udp_accel_negotiated() => println!(
            "FAIL udp negotiated by the server but never became usable in {seconds}s (likely blocked/dropped on this \
network; TCP fallback is what carries traffic instead)"
        ),
        None => println!("OK udp not negotiated by this server; nothing to watch (TCP only)"),
    }
}
