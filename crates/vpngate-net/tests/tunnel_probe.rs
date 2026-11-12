//! The tunnel liveness probe against a loopback TLS server: a completed handshake is alive; a closed port, or a port
//! that accepts TCP but never speaks TLS (a relay that carries nothing), is not.

use std::net::SocketAddrV4;
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use vpngate_net::session::TunnelProbe;
use vpngate_net::tunnel_probe::TlsTunnelProbe;
use vpngate_platform::UnboundSocketBinder;

async fn tls_server() -> SocketAddrV4 {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.signing_key.serialize_der())),
        )
        .unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _tls = acceptor.accept(tcp).await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    addr
}

/// Accepts TCP and then says nothing.
async fn mute_server() -> SocketAddrV4 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = match listener.local_addr().unwrap() {
        std::net::SocketAddr::V4(a) => a,
        _ => unreachable!(),
    };
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((tcp, _)) = listener.accept().await {
            held.push(tcp);
        }
    });
    addr
}

fn probe(targets: Vec<SocketAddrV4>) -> TlsTunnelProbe {
    TlsTunnelProbe::with_targets(Arc::new(UnboundSocketBinder), targets, Duration::from_millis(800))
}

#[tokio::test]
async fn a_completed_handshake_is_alive() {
    assert!(probe(vec![tls_server().await]).alive().await);
}

#[tokio::test]
async fn a_port_that_accepts_tcp_but_never_speaks_tls_is_not_alive() {
    assert!(!probe(vec![mute_server().await]).alive().await);
}

#[tokio::test]
async fn a_closed_port_is_not_alive() {
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        match l.local_addr().unwrap() {
            std::net::SocketAddr::V4(a) => a,
            _ => unreachable!(),
        }
    };
    assert!(!probe(vec![closed]).alive().await);
}

#[tokio::test]
async fn one_reachable_target_among_dead_ones_is_enough() {
    let mute = mute_server().await;
    assert!(probe(vec![mute, tls_server().await]).alive().await);
}
