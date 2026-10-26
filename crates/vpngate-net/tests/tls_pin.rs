//! Server certificate pinning, proxies and the probe through real TLS handshakes against a loopback (127.0.0.1)
//! server presenting a throwaway rcgen certificate.

use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::ServerConfig;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;
use vpngate_core::cert_pin::ServerCertPolicy;
use vpngate_core::ipc::{ProxyKind, ProxySettings};
use vpngate_core::pack::Pack;
use vpngate_net::probe::{self, ProbeOutcome};
use vpngate_net::stream::{ByteStream, StreamError, StreamFactory};
use vpngate_net::tls::TlsStream;

struct Loopback {
    port: u16,
    leaf_der: Vec<u8>,
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A TLS server that sends `greeting` after the handshake; when `softether` it instead answers the probe's hello.
async fn loopback(greeting: &'static [u8], softether: bool) -> Loopback {
    let key = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let leaf_der = key.cert.der().to_vec();
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
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else { return };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(tcp).await else { return };
                if softether {
                    let mut buf = vec![0u8; 4096];
                    let mut got = Vec::new();
                    while !got.windows(10).any(|w| w == b"VPNCONNECT") {
                        match tls.read(&mut buf).await {
                            Ok(n) if n > 0 => got.extend_from_slice(&buf[..n]),
                            _ => return,
                        }
                    }
                    let mut p = Pack::new();
                    p.add_str("hello", "SoftEther VPN Server");
                    p.add_int("build", 9729);
                    p.add_data("random", &[7u8; 20]);
                    let body = p.serialize();
                    let head = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len());
                    let _ = tls.write_all(head.as_bytes()).await;
                    let _ = tls.write_all(&body).await;
                } else {
                    let _ = tls.write_all(greeting).await;
                }
                let _ = tls.flush().await;
                tokio::time::sleep(Duration::from_secs(5)).await;
            });
        }
    });
    Loopback { port, leaf_der }
}

async fn attempt(srv: &Loopback, policy: ServerCertPolicy) -> Result<TlsStream, String> {
    let mut s = TlsStream::new("127.0.0.1", srv.port, &ProxySettings::default(), policy);
    s.start_with_timeout(Duration::from_secs(10)).await.map_err(|e| e.to_string())?;
    s.recv(5).await.map_err(|e| e.to_string())?;
    Ok(s)
}

fn pin(fp: &str) -> ServerCertPolicy {
    ServerCertPolicy::new(false, Some(fp))
}

#[tokio::test]
async fn correct_sha1_and_sha256_fingerprints_succeed() {
    let srv = loopback(b"hello", false).await;
    let sha1 = hex(&Sha1::digest(&srv.leaf_der));
    let colons: String = sha1
        .to_uppercase()
        .as_bytes()
        .chunks(2)
        .map(|c| std::str::from_utf8(c).unwrap().to_string())
        .collect::<Vec<_>>()
        .join(":");
    let sha256 = hex(&Sha256::digest(&srv.leaf_der));
    for (label, fp) in [("sha1", &sha1), ("SHA-1 with colons", &colons), ("sha256", &sha256)] {
        let s = attempt(&srv, pin(fp)).await.unwrap_or_else(|e| panic!("{label}: {e}"));
        if label == "sha1" {
            assert_eq!(s.remote_ipv4().as_deref(), Some("127.0.0.1"), "the connected peer is exposed");
        }
    }
}

#[tokio::test]
async fn wrong_fingerprint_fails_with_the_pin_mismatch_error() {
    let srv = loopback(b"hello", false).await;
    let mut wrong1 = hex(&Sha1::digest(&srv.leaf_der));
    wrong1.pop();
    wrong1.push(if hex(&Sha1::digest(&srv.leaf_der)).ends_with('0') { '1' } else { '0' });
    for fp in [wrong1, hex(&Sha256::digest(b"other"))] {
        let e = attempt(&srv, pin(&fp)).await.err().expect("a mismatching pin must not connect");
        assert!(e.contains("does not match the pinned fingerprint"), "error was: {e}");
    }
    let e = attempt(&srv, pin("xyz")).await.err().expect("an unparseable pin fails closed");
    assert!(e.contains("not a valid"), "error was: {e}");
}

#[tokio::test]
async fn no_pin_accepts_any_certificate_and_system_trust_refuses_self_signed() {
    let srv = loopback(b"hello", false).await;
    attempt(&srv, ServerCertPolicy::AcceptAny).await.unwrap();
    let strict = attempt(&srv, ServerCertPolicy::new(true, None)).await.err();
    assert!(strict.is_some(), "system trust must reject a self-signed certificate");
}

#[tokio::test]
async fn refused_port_fails_without_hanging() {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let mut s = TlsStream::new("127.0.0.1", port, &ProxySettings::default(), ServerCertPolicy::AcceptAny);
    assert!(matches!(s.start_with_timeout(Duration::from_secs(5)).await, Err(StreamError::Io(_))));
    assert_eq!(s.send(b"x").await, Err(StreamError::Closed));
}

/// Relays bytes between two TCP streams until either side closes.
async fn pipe(mut a: TcpStream, mut b: TcpStream) {
    let _ = tokio::io::copy_bidirectional(&mut a, &mut b).await;
}

/// A proxy that speaks HTTP CONNECT (when `socks` is false) or SOCKS5 with optional username/password `auth`.
async fn proxy_server(socks: bool, auth: Option<(&'static str, &'static str)>) -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let target =
                    if socks { socks_handshake(&mut c, auth).await } else { connect_handshake(&mut c, auth).await };
                if let Some(t) = target {
                    if let Ok(up) = TcpStream::connect(t).await {
                        pipe(c, up).await;
                    }
                }
            });
        }
    });
    port
}

async fn connect_handshake(c: &mut TcpStream, auth: Option<(&str, &str)>) -> Option<String> {
    let mut raw = Vec::new();
    let mut b = [0u8; 512];
    while !raw.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = c.read(&mut b).await.ok().filter(|n| *n > 0)?;
        raw.extend_from_slice(&b[..n]);
    }
    let text = String::from_utf8_lossy(&raw).to_string();
    if let Some((u, p)) = auth {
        use base64::Engine;
        let want = format!(
            "Proxy-Authorization: Basic {}",
            base64::engine::general_purpose::STANDARD.encode(format!("{u}:{p}"))
        );
        if !text.contains(&want) {
            c.write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n").await.ok()?;
            return None;
        }
    }
    let target = text.split(' ').nth(1)?.to_string();
    c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await.ok()?;
    Some(target)
}

async fn socks_handshake(c: &mut TcpStream, auth: Option<(&str, &str)>) -> Option<String> {
    let mut h = [0u8; 2];
    c.read_exact(&mut h).await.ok()?;
    let mut methods = vec![0u8; h[1] as usize];
    c.read_exact(&mut methods).await.ok()?;
    if let Some((u, p)) = auth {
        if !methods.contains(&2) {
            c.write_all(&[5, 0xff]).await.ok()?;
            return None;
        }
        c.write_all(&[5, 2]).await.ok()?;
        let mut v = [0u8; 2];
        c.read_exact(&mut v).await.ok()?;
        let mut user = vec![0u8; v[1] as usize];
        c.read_exact(&mut user).await.ok()?;
        let mut pl = [0u8; 1];
        c.read_exact(&mut pl).await.ok()?;
        let mut pass = vec![0u8; pl[0] as usize];
        c.read_exact(&mut pass).await.ok()?;
        let ok = user == u.as_bytes() && pass == p.as_bytes();
        c.write_all(&[1, if ok { 0 } else { 1 }]).await.ok()?;
        if !ok {
            return None;
        }
    } else {
        c.write_all(&[5, 0]).await.ok()?;
    }
    let mut r = [0u8; 4];
    c.read_exact(&mut r).await.ok()?;
    let host = match r[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await.ok()?;
            std::net::Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut l = [0u8; 1];
            c.read_exact(&mut l).await.ok()?;
            let mut n = vec![0u8; l[0] as usize];
            c.read_exact(&mut n).await.ok()?;
            String::from_utf8(n).ok()?
        }
        _ => return None,
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await.ok()?;
    c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await.ok()?;
    Some(format!("{host}:{}", u16::from_be_bytes(p)))
}

fn proxy_settings(kind: ProxyKind, port: u16, creds: Option<(&str, &str)>) -> ProxySettings {
    ProxySettings {
        kind,
        host: "127.0.0.1".into(),
        port: i64::from(port),
        username: creds.map(|c| c.0.to_string()),
        password: creds.map(|c| c.1.to_string()),
    }
}

#[tokio::test]
async fn tls_goes_through_http_connect_and_socks5_proxies() {
    let srv = loopback(b"hello", false).await;
    let cases = [
        (ProxyKind::Http, proxy_server(false, None).await, None),
        (ProxyKind::Http, proxy_server(false, Some(("bob", "pw"))).await, Some(("bob", "pw"))),
        (ProxyKind::Socks5, proxy_server(true, None).await, None),
        (ProxyKind::Socks5, proxy_server(true, Some(("bob", "pw"))).await, Some(("bob", "pw"))),
    ];
    for (kind, port, creds) in cases {
        let proxy = proxy_settings(kind, port, creds);
        let mut s = TlsStream::new("127.0.0.1", srv.port, &proxy, ServerCertPolicy::AcceptAny);
        s.start_with_timeout(Duration::from_secs(10)).await.unwrap_or_else(|e| panic!("{kind:?} {creds:?}: {e}"));
        assert_eq!(s.recv(5).await.unwrap(), b"hello");
    }
}

#[tokio::test]
async fn wrong_proxy_credentials_are_reported() {
    let srv = loopback(b"hello", false).await;
    let http = proxy_server(false, Some(("bob", "pw"))).await;
    let mut s = TlsStream::new(
        "127.0.0.1",
        srv.port,
        &proxy_settings(ProxyKind::Http, http, Some(("bob", "no"))),
        ServerCertPolicy::AcceptAny,
    );
    let e = s.start_with_timeout(Duration::from_secs(5)).await.unwrap_err();
    assert!(e.to_string().contains("authentication"), "{e}");
    let socks = proxy_server(true, Some(("bob", "pw"))).await;
    let mut s = TlsStream::new(
        "127.0.0.1",
        srv.port,
        &proxy_settings(ProxyKind::Socks5, socks, Some(("bob", "no"))),
        ServerCertPolicy::AcceptAny,
    );
    let e = s.start_with_timeout(Duration::from_secs(5)).await.unwrap_err();
    assert!(e.to_string().contains("authentication failed"), "{e}");
}

#[tokio::test]
async fn probe_over_real_tls_finds_the_softether_hello() {
    let srv = loopback(b"", true).await;
    let factory: StreamFactory = Arc::new(|h, p, px| Box::new(TlsStream::new(h, p, px, ServerCertPolicy::AcceptAny)));
    let r = probe::run("127.0.0.1", &[srv.port], &ProxySettings::default(), Duration::from_secs(5), &factory).await;
    let ProbeOutcome::Ok { port, connect_ms, hello_ms, build } = r else { panic!("{r:?}") };
    assert_eq!((port, build), (srv.port, Some(9729)));
    assert!(connect_ms >= 1 && hello_ms >= connect_ms);
    // a plain TLS server that sends no hello is not a VPN server
    let plain = loopback(b"hello", false).await;
    let r =
        probe::run("127.0.0.1", &[plain.port], &ProxySettings::default(), Duration::from_millis(500), &factory).await;
    assert!(!r.is_ok(), "{r:?}");
}
