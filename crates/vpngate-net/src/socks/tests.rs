use std::sync::Mutex;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use vpngate_platform::UnboundSocketBinder;

use super::*;

/// Connects straight to loopback and records what was asked for.
#[derive(Default)]
struct LoopbackConnector {
    requests: Mutex<Vec<(String, u16)>>,
    remap: Vec<(&'static str, &'static str)>,
}

#[async_trait]
impl SocksConnector for LoopbackConnector {
    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, SocksFailure> {
        self.requests.lock().unwrap().push((host.to_string(), port));
        let target = self.remap.iter().find(|(h, _)| *h == host).map_or(host, |(_, t)| *t);
        let ip: Ipv4Addr = target.parse().map_err(|_| SocksFailure::HostUnreachable)?;
        tokio::time::timeout(Duration::from_secs(2), TcpStream::connect((ip, port)))
            .await
            .map_err(|_| SocksFailure::HostUnreachable)?
            .map_err(|e| failure_for(&e))
    }
}

/// Accepts connections and echoes everything back until each closes.
async fn echo_server() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = l.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut c, _)) = l.accept().await {
            tokio::spawn(async move {
                let (mut r, mut w) = c.split();
                let _ = tokio::io::copy(&mut r, &mut w).await;
            });
        }
    });
    port
}

fn unused_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    l.local_addr().unwrap().port()
}

fn started(connector: Arc<dyn SocksConnector>) -> SocksServer {
    let s = SocksServer::new(0, connector);
    s.start().unwrap();
    s
}

async fn dial(port: u16) -> TcpStream {
    TcpStream::connect(("127.0.0.1", port)).await.unwrap()
}

/// Greeting (no auth) + a CONNECT request; returns the reply's status byte (`None` if the server hung up).
async fn socks_connect(c: &mut TcpStream, atyp: u8, dest: &[u8], port: u16, cmd: u8) -> Option<u8> {
    c.write_all(&[5, 1, 0]).await.ok()?;
    let mut greeting = [0u8; 2];
    c.read_exact(&mut greeting).await.ok()?;
    if greeting != [5, 0] {
        return None;
    }
    let mut req = vec![5, cmd, 0, atyp];
    req.extend_from_slice(dest);
    req.extend_from_slice(&port.to_be_bytes());
    c.write_all(&req).await.ok()?;
    let mut reply = [0u8; 10];
    c.read_exact(&mut reply).await.ok()?;
    Some(reply[1])
}

async fn connect_v4(c: &mut TcpStream, port: u16) -> Option<u8> {
    socks_connect(c, 1, &[127, 0, 0, 1], port, 1).await
}

#[tokio::test]
async fn relays_both_directions_for_an_ipv4_destination() {
    let echo = echo_server().await;
    let server = started(Arc::new(LoopbackConnector::default()));
    let mut c = dial(server.bound_port()).await;
    assert_eq!(connect_v4(&mut c, echo).await, Some(0));
    c.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    c.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"hello");
}

#[tokio::test]
async fn passes_a_domain_name_to_the_connector_unresolved() {
    let echo = echo_server().await;
    let conn = Arc::new(LoopbackConnector { remap: vec![("example.test", "127.0.0.1")], ..Default::default() });
    let server = started(conn.clone());
    let mut c = dial(server.bound_port()).await;
    let name = b"example.test";
    let mut dest = vec![name.len() as u8];
    dest.extend_from_slice(name);
    assert_eq!(socks_connect(&mut c, 3, &dest, echo, 1).await, Some(0));
    assert_eq!(conn.requests.lock().unwrap()[0], ("example.test".to_string(), echo));
}

#[tokio::test]
async fn rejects_unsupported_commands_address_types_and_methods() {
    let server = started(Arc::new(LoopbackConnector::default()));
    let port = server.bound_port();
    let mut c = dial(port).await;
    assert_eq!(socks_connect(&mut c, 1, &[1, 2, 3, 4], 80, 2).await, Some(SocksFailure::CommandUnsupported as u8));
    let mut c = dial(port).await;
    assert_eq!(socks_connect(&mut c, 4, &[1u8; 16], 80, 1).await, Some(SocksFailure::AddressTypeUnsupported as u8));
    let mut c = dial(port).await;
    c.write_all(&[5, 1, 2]).await.unwrap(); // only username/password offered
    let mut r = [0u8; 2];
    c.read_exact(&mut r).await.unwrap();
    assert_eq!(r, [5, 0xFF]);
    let mut c = dial(port).await;
    let bad = b"a b;rm";
    let mut dest = vec![bad.len() as u8];
    dest.extend_from_slice(bad);
    assert_eq!(socks_connect(&mut c, 3, &dest, 80, 1).await, Some(SocksFailure::HostUnreachable as u8));
}

#[tokio::test]
async fn reports_a_refused_connection() {
    let server = started(Arc::new(LoopbackConnector::default()));
    let mut c = dial(server.bound_port()).await;
    let code = connect_v4(&mut c, unused_port()).await;
    assert!(matches!(code, Some(n) if n != 0), "expected a failure code, got {code:?}");
}

#[tokio::test]
async fn stop_closes_the_listener_and_live_sessions() {
    let echo = echo_server().await;
    let server = started(Arc::new(LoopbackConnector::default()));
    let mut c = dial(server.bound_port()).await;
    assert_eq!(connect_v4(&mut c, echo).await, Some(0));
    server.stop();
    assert!(!server.is_listening());
    let mut b = [0u8; 1];
    let r = tokio::time::timeout(Duration::from_secs(3), c.read(&mut b)).await.expect("session must end");
    assert!(matches!(r, Ok(0) | Err(_)), "an established session must end when the proxy stops");
}

#[tokio::test]
async fn port_can_be_rebound_right_after_stop() {
    let first = started(Arc::new(LoopbackConnector::default()));
    let port = first.bound_port();
    first.stop();
    let second = SocksServer::new(port, Arc::new(LoopbackConnector::default()));
    second.start().unwrap();
    assert_eq!(second.bound_port(), port);
}

#[tokio::test]
async fn a_second_start_while_listening_keeps_the_same_port() {
    let s = started(Arc::new(LoopbackConnector::default()));
    let port = s.bound_port();
    s.start().unwrap();
    assert_eq!(s.bound_port(), port);
}

#[tokio::test]
async fn busy_port_is_a_readable_error() {
    let first = started(Arc::new(LoopbackConnector::default()));
    let second = SocksServer::new(first.bound_port(), Arc::new(LoopbackConnector::default()));
    let e = second.start().unwrap_err();
    assert!(e.to_string().contains("SOCKS proxy cannot listen on 127.0.0.1:"), "{e}");
    assert!(!second.is_listening());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_simultaneous_transfers_do_not_deadlock() {
    let echo = echo_server().await;
    let server = started(Arc::new(LoopbackConnector::default()));
    let mut c = dial(server.bound_port()).await;
    assert_eq!(connect_v4(&mut c, echo).await, Some(0));
    let total = 4 * 1024 * 1024;
    let (mut r, mut w) = c.into_split();
    let writer = tokio::spawn(async move {
        w.write_all(&vec![7u8; total]).await.unwrap();
        w.shutdown().await.unwrap();
    });
    let mut got = 0;
    let mut buf = vec![0u8; 65536];
    while got < total {
        let n = r.read(&mut buf).await.unwrap();
        if n == 0 {
            break;
        }
        got += n;
    }
    writer.await.unwrap();
    assert_eq!(got, total);
}

#[tokio::test]
async fn a_half_close_from_the_client_still_lets_the_reply_through() {
    let echo = echo_server().await;
    let server = started(Arc::new(LoopbackConnector::default()));
    let mut c = dial(server.bound_port()).await;
    assert_eq!(connect_v4(&mut c, echo).await, Some(0));
    c.write_all(b"ping").await.unwrap();
    c.shutdown().await.unwrap();
    let mut all = Vec::new();
    c.read_to_end(&mut all).await.unwrap();
    assert_eq!(all, b"ping");
}

#[tokio::test]
async fn admits_at_most_max_clients() {
    let server = started(Arc::new(LoopbackConnector::default()));
    let mut held = Vec::new();
    for _ in 0..MAX_CLIENTS {
        let mut c = dial(server.bound_port()).await;
        c.write_all(&[5, 1, 0]).await.unwrap();
        let mut g = [0u8; 2];
        c.read_exact(&mut g).await.unwrap();
        held.push(c);
    }
    let mut extra = dial(server.bound_port()).await;
    let _ = extra.write_all(&[5, 1, 0]).await;
    let mut g = [0u8; 2];
    let r = tokio::time::timeout(Duration::from_secs(2), extra.read_exact(&mut g)).await.expect("closed, not hung");
    assert!(r.is_err(), "client {} must be refused", MAX_CLIENTS + 1);
}

// MARK: - TunnelConnector

/// Answers every A query with one fixed address, or not at all.
struct StubDns(Option<[u8; 4]>);

#[async_trait]
impl DnsUpstream for StubDns {
    async fn query(&self, message: &[u8], _server: &str, _timeout_ms: u32) -> Option<Vec<u8>> {
        self.0.map(|ip| dns_answer(message, ip))
    }
}

fn dns_answer(query: &[u8], ip: [u8; 4]) -> Vec<u8> {
    let mut r = query.to_vec();
    r[2] |= 0x80;
    r[7] = 1;
    r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
    r.extend_from_slice(&ip);
    r
}

fn tunnel(dns: Option<[u8; 4]>) -> TunnelConnector {
    TunnelConnector::new(Arc::new(UnboundSocketBinder), vec!["10.233.254.254".into()], Arc::new(StubDns(dns)))
}

#[tokio::test]
async fn tunnel_connector_resolves_through_the_vpn_dns_and_connects() {
    let echo = echo_server().await;
    let mut s = tunnel(Some([127, 0, 0, 1])).connect("example.test", echo).await.expect("connect");
    s.write_all(b"x").await.unwrap();
    let mut b = [0u8; 1];
    s.read_exact(&mut b).await.unwrap();
    assert_eq!(&b, b"x");
    let r = tunnel(None).connect("example.test", echo).await;
    assert_eq!(r.err(), Some(SocksFailure::HostUnreachable), "an unresolvable name must not connect");
}

#[tokio::test]
async fn tunnel_connector_connects_to_a_literal_without_asking_dns() {
    let echo = echo_server().await;
    assert!(tunnel(None).connect("127.0.0.1", echo).await.is_ok());
}

#[tokio::test]
async fn tunnel_connector_maps_a_refused_connection() {
    let r = tunnel(None).connect("127.0.0.1", unused_port()).await;
    assert_eq!(r.err(), Some(SocksFailure::ConnectionRefused));
}

#[test]
fn a_query_is_a_well_formed_recursive_a_question() {
    let q = dns_message::a_query("www.example.com", 0x1234);
    assert_eq!(q[..4], [0x12, 0x34, 0x01, 0x00]);
    assert_eq!(dns_message::query_name(&q).as_deref(), Some("www.example.com"));
    assert_eq!(q[q.len() - 4..], [0, 1, 0, 1]);
    assert_eq!(dns_message::resolved_ipv4_addresses(&dns_answer(&q, [9, 8, 7, 6])), ["9.8.7.6"]);
}
