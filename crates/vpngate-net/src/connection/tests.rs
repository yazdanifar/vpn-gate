use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::data_phase;
use vpngate_core::ipc::ProxySettings;

use super::*;
use crate::entropy::ClientEnvironment;
use crate::host_unique_id::HostUniqueId;
use crate::softether_client::ClientConfig;
use crate::stream::{ByteStream, StreamFactory};
use crate::testing::fake_softether::FakeSoftEtherServer;

fn env() -> ClientEnvironment {
    ClientEnvironment { os_name: "macOS".into(), os_version: "14.5.0".into(), hostname: "golden-host".into() }
}

fn config(max_connections: usize) -> ClientConfig {
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.use_udp_accel = false;
    cfg.max_connections = max_connections;
    cfg
}

fn client_with(factory: StreamFactory, cfg: ClientConfig) -> SoftEtherClient {
    SoftEtherClient::new(cfg, HostUniqueId::new([7; 32]), factory, Box::new(SystemEntropy), env())
}

#[derive(Clone, Default)]
struct Sink {
    frames: Arc<Mutex<Vec<Vec<u8>>>>,
    closes: Arc<Mutex<Vec<Option<StreamError>>>>,
}

impl Sink {
    fn events(&self) -> ConnectionEvents {
        let (f, c) = (self.frames.clone(), self.closes.clone());
        ConnectionEvents {
            on_frame: Arc::new(move |fr| f.lock().unwrap().push(fr)),
            on_close: Arc::new(move |e| c.lock().unwrap().push(e)),
        }
    }
}

fn fast() -> ConnectOptions {
    ConnectOptions { replenish_interval: Duration::from_millis(50) }
}

async fn connect_with(
    factory: StreamFactory,
    cfg: ClientConfig,
    sink: &Sink,
) -> Result<SoftEtherConnection, StreamError> {
    client_with(factory, cfg).connect(&mut |_| {}, sink.events(), fast()).await
}

async fn connect(s: &FakeSoftEtherServer, max: usize, sink: &Sink) -> SoftEtherConnection {
    connect_with(s.factory(), config(max), sink).await.expect("connect")
}

async fn eventually(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    let end = tokio::time::Instant::now() + Duration::from_secs(secs);
    while tokio::time::Instant::now() < end {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    f()
}

/// Server that redirects the first attempt (once a stream exists), then accepts.
fn redirecting(s: &FakeSoftEtherServer) -> StreamFactory {
    let (s2, inner) = (s.clone(), s.factory());
    Arc::new(move |h: &str, p: u16, pr: &ProxySettings| {
        if s2.streams_created() >= 1 {
            s2.configure(|c| c.redirect = false);
        }
        inner(h, p, pr)
    })
}

// MARK: - redirects

#[tokio::test]
async fn redirect_limit_is_an_error() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.redirect = true);
    let e = connect_with(s.factory(), config(1), &Sink::default()).await.err().expect("fails");
    assert!(e.to_string().to_lowercase().contains("redirect"), "{e}");
    assert_eq!(s.streams_created(), 5);
}

#[tokio::test]
async fn redirect_succeeds_with_ticket_and_routes_follow_the_target() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.redirect = true);
    let conn = connect_with(redirecting(&s), config(1), &Sink::default()).await.unwrap();
    assert_eq!(conn.welcome().session_name, "SID-VPN-TEST-1");
    let logins = s.logins();
    assert_eq!(logins.len(), 2);
    assert_eq!(logins[1].int("authtype"), Some(99));
    assert_eq!(logins[1].data("ticket"), Some(&[0x42u8; 20][..]));
    assert_eq!(conn.bypass_hosts(), vec!["5.6.7.8".to_string()], "routes must follow the redirect target");
    conn.close(None);
}

#[tokio::test]
async fn redirect_port_list_prefers_the_current_port_else_the_first() {
    for (offered, want) in [(vec![80u32, 443, 992], 443u32), (vec![992, 5555], 992)] {
        let s = FakeSoftEtherServer::new();
        s.configure(|c| {
            c.redirect = true;
            c.redirect_ports = Some(offered.clone());
        });
        let ports = Arc::new(Mutex::new(Vec::new()));
        let (inner, p2, s2) = (s.factory(), ports.clone(), s.clone());
        let factory: StreamFactory = Arc::new(move |h: &str, p: u16, pr: &ProxySettings| {
            p2.lock().unwrap().push(p);
            if s2.streams_created() >= 1 {
                s2.configure(|c| c.redirect = false);
            }
            inner(h, p, pr)
        });
        let conn = connect_with(factory, config(1), &Sink::default()).await.unwrap();
        assert_eq!(ports.lock().unwrap().last().copied(), Some(want as u16));
        conn.close(None);
    }
}

#[tokio::test]
async fn redirect_ip_integer_goes_to_the_right_host() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.redirect = true;
        c.redirect_ip_int = Some(0x0807_0605);
    });
    let conn = connect_with(redirecting(&s), config(1), &Sink::default()).await.unwrap();
    assert_eq!(conn.bypass_hosts(), vec!["5.6.7.8".to_string()]);
    conn.close(None);
}

// MARK: - additional connections

#[tokio::test]
async fn additional_connect_matches_the_stock_client() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.max_connections = 2);
    let conn = connect(&s, 2, &Sink::default()).await;
    assert!(eventually(5, || s.additional_connects().len() == 1).await);
    let signatures: Vec<_> = s.requests().into_iter().filter(|r| r.path == "/vpnsvc/connect.cgi").collect();
    assert_eq!(signatures.len(), 2);
    for r in &signatures {
        assert_eq!(&r.body[..6], b"GIF89a", "watermark upload, not VPNCONNECT");
    }
    let p = &s.additional_connects()[0];
    assert_eq!(p.str("method"), Some("additional_connect"));
    assert_eq!(p.data("session_key").map(<[u8]>::len), Some(20));
    assert_eq!((p.int("client_ver"), p.int("client_build")), (Some(444), Some(9807)));
    assert!(p.data("pencore").is_some(), "pencore on every pack");
    assert!(p.int("direction").is_none(), "the client never sends a direction");
    conn.close(None);
}

#[tokio::test]
async fn additional_connect_uses_the_plain_signature_only_if_the_first_connection_had_to() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.max_connections = 2;
        c.reject_watermark = true;
    });
    let conn = connect(&s, 2, &Sink::default()).await;
    assert!(eventually(5, || s.additional_connects().len() == 1).await);
    let bodies: Vec<_> = s.requests().into_iter().filter(|r| r.path == "/vpnsvc/connect.cgi").map(|r| r.body).collect();
    assert!(bodies.len() >= 3 && bodies.last().unwrap() == b"VPNCONNECT");
    conn.close(None);
}

#[tokio::test]
async fn qos_bump_is_honoured_by_the_pool() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.max_connections = 1;
        let mut w = vpngate_core::pack::Pack::new();
        w.add_str("session_name", "SID-1");
        w.add_str("connection_name", "CID-1");
        w.add_data("session_key", &[0x11; 20]);
        w.add_int("max_connection", 1);
        w.add_bool("qos", true);
        c.welcome_override = Some(w);
    });
    let conn = connect(&s, 2, &Sink::default()).await;
    assert_eq!(conn.welcome().max_connection, 2);
    assert!(eventually(5, || s.additional_connects().len() == 1).await);
    conn.close(None);
}

#[tokio::test]
async fn multi_tcp_fills_the_pool_and_spreads_frames() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.max_connections = 4);
    let conn = connect(&s, 4, &Sink::default()).await;
    assert!(eventually(5, || conn.active_connection_count() == 4).await);
    assert_eq!(s.additional_connects()[0].data("session_key"), Some(&[0x11u8; 20][..]));
    for i in 0..40u8 {
        conn.send_frame(vec![i; 64]);
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(eventually(5, || s.frames_received().len() == 40).await);
    let used = (0..4).filter(|i| s.stream(*i).bytes_received_from_client() > 0).count();
    assert!(used > 1, "frames should be balanced over several sockets, used {used}");
    conn.close(None);
}

#[tokio::test]
async fn pool_replaces_a_socket_that_died() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.max_connections = 3);
    let conn = connect(&s, 3, &Sink::default()).await;
    assert!(eventually(5, || conn.active_connection_count() == 3).await);
    assert_eq!(s.additional_connects().len(), 2);
    s.stream(2).fail_from_server(StreamError::Closed);
    assert!(
        eventually(5, || s.additional_connects().len() == 3 && conn.active_connection_count() == 3).await,
        "attempts {}, active {}",
        s.additional_connects().len(),
        conn.active_connection_count()
    );
    conn.close(None);
}

#[tokio::test]
async fn failed_additional_connects_are_retried_and_stop_after_close() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.max_connections = 2;
        c.fail_additional_connects = 2;
    });
    let conn = connect(&s, 2, &Sink::default()).await;
    assert!(eventually(5, || conn.active_connection_count() == 2).await);
    assert_eq!(s.additional_connects().len(), 3, "two refusals then success");
    conn.close(None);
    assert!(eventually(3, || conn.active_connection_count() == 0).await);
    let seen = s.additional_connects().len();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(s.additional_connects().len(), seen, "no connection attempts after close()");
}

// MARK: - half connection

fn half_config(max: usize) -> ClientConfig {
    let mut cfg = config(max);
    cfg.half_connection = true;
    cfg
}

#[tokio::test]
async fn half_connection_directions_are_applied_end_to_end() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.max_connections = 4;
        c.additional_connect_directions = vec![2, 1, 0];
    });
    let sink = Sink::default();
    let conn = connect_with(s.factory(), half_config(4), &sink).await.unwrap();
    assert!(eventually(5, || conn.active_connection_count() == 4).await);
    let handles: Vec<_> = (0..4).map(|i| s.stream(i)).collect();
    let stc = handles.iter().find(|h| h.assigned_direction() == Some(1)).expect("a server-to-client stream");
    let send_capable: Vec<_> = handles.iter().filter(|h| h.assigned_direction() != Some(1)).collect();
    assert_eq!(send_capable.len(), 3);

    for i in 0..40u8 {
        conn.send_frame(vec![i; 64]);
    }
    assert!(eventually(3, || send_capable.iter().map(|h| h.bytes_received_from_client()).sum::<usize>() > 0).await);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(stc.bytes_received_from_client(), 0, "nothing must be sent on the server-to-client-only socket");

    stc.deliver(&data_phase::encode(&[vec![0xAB; 10]]));
    assert!(eventually(3, || sink.frames.lock().unwrap().contains(&vec![0xAB; 10])).await);
    conn.close(None);
}

#[tokio::test]
async fn client_to_server_only_socket_is_not_torn_down_for_never_receiving() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.max_connections = 2;
        c.welcome_timeout_ms = 500;
        c.additional_connect_directions = vec![2];
    });
    let conn = connect_with(s.factory(), half_config(2), &Sink::default()).await.unwrap();
    assert!(eventually(5, || conn.active_connection_count() == 2).await);
    tokio::time::sleep(Duration::from_millis(900)).await; // well past the 500 ms idle-read timeout
    assert_eq!(conn.active_connection_count(), 2, "the send-only socket must survive");
    conn.close(None);
}

// MARK: - data phase

#[tokio::test]
async fn compressed_session_transfers_frames_both_ways() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.use_compress = true);
    let mut cfg = config(1);
    cfg.use_compress = true;
    let sink = Sink::default();
    let conn = connect_with(s.factory(), cfg, &sink).await.unwrap();
    assert!(conn.welcome().use_compress);
    let frame = b"test compression data frame payload".to_vec();
    conn.send_frame(frame.clone());
    assert!(eventually(5, || s.frames_received().len() == 1).await);
    assert_eq!(s.frames_received()[0], frame);
    assert_eq!(conn.bytes_out(), frame.len() as u64);

    s.stream(0).deliver(&data_phase::encode_compressed(std::slice::from_ref(&frame), true).unwrap());
    assert!(eventually(5, || sink.frames.lock().unwrap().len() == 1).await);
    assert_eq!(conn.bytes_in(), frame.len() as u64);
    conn.close(None);
}

#[tokio::test]
async fn bytes_after_the_welcome_are_decoded() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.trailing_after_welcome = data_phase::encode(&[vec![1, 2, 3]]));
    let sink = Sink::default();
    let conn = connect(&s, 1, &sink).await;
    assert!(eventually(5, || sink.frames.lock().unwrap().len() == 1).await);
    assert_eq!(sink.frames.lock().unwrap()[0], vec![1, 2, 3]);
    conn.close(None);
}

#[tokio::test]
async fn oversized_frames_are_ignored() {
    let s = FakeSoftEtherServer::new();
    let conn = connect(&s, 1, &Sink::default()).await;
    conn.send_frame(vec![0; MAX_BLOCK + 1]);
    conn.send_frame(vec![9; 10]);
    assert!(eventually(5, || s.frames_received().len() == 1).await);
    assert_eq!(s.frames_received()[0], vec![9; 10]);
    conn.close(None);
}

// MARK: - close

#[tokio::test]
async fn closing_reports_once_and_cancels_every_stream() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.max_connections = 2);
    let sink = Sink::default();
    let conn = connect(&s, 2, &sink).await;
    assert!(eventually(5, || conn.active_connection_count() == 2).await);
    conn.close(None);
    conn.close(Some(StreamError::Closed));
    assert_eq!(sink.closes.lock().unwrap().len(), 1);
    assert!(eventually(3, || (0..2).all(|i| s.stream(i).is_cancelled())).await);
    conn.send_frame(vec![1]);
    assert_eq!(conn.pending_frame_count(), 0, "a closed session takes no frames");
}

#[tokio::test]
async fn losing_the_only_socket_ends_the_session_with_the_error() {
    let s = FakeSoftEtherServer::new();
    let sink = Sink::default();
    let _conn = connect(&s, 1, &sink).await;
    s.stream(0).fail_from_server(StreamError::Io("reset".into()));
    assert!(eventually(5, || !sink.closes.lock().unwrap().is_empty()).await);
    assert_eq!(sink.closes.lock().unwrap()[0], Some(StreamError::Io("reset".into())));
}

#[tokio::test]
async fn idle_socket_times_out() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.welcome_timeout_ms = 500);
    let sink = Sink::default();
    let _conn = connect(&s, 1, &sink).await;
    assert!(eventually(3, || !sink.closes.lock().unwrap().is_empty()).await);
    let e = sink.closes.lock().unwrap()[0].clone().unwrap();
    assert!(e.to_string().contains("Read idle timeout"), "{e}");
}

#[tokio::test]
async fn dropping_the_handle_closes_the_session() {
    let s = FakeSoftEtherServer::new();
    let sink = Sink::default();
    drop(connect(&s, 1, &sink).await);
    assert_eq!(sink.closes.lock().unwrap().len(), 1);
    assert!(eventually(3, || s.stream(0).is_cancelled()).await);
}

// MARK: - pending queue

/// Wraps a fake stream; while held, `send` never completes.
struct HoldStream {
    inner: Box<dyn ByteStream>,
    hold: Arc<AtomicUsize>,
}

#[async_trait]
impl ByteStream for HoldStream {
    fn buffer(&mut self) -> &mut ByteBuffer {
        self.inner.buffer()
    }
    async fn start(&mut self) -> Result<(), StreamError> {
        self.inner.start().await
    }
    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
        while self.hold.load(Ordering::SeqCst) == 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        self.inner.send(data).await
    }
    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        self.inner.read_chunk().await
    }
    fn cancel(&mut self) {
        self.inner.cancel();
    }
}

#[tokio::test]
async fn pending_send_queue_is_capped() {
    let s = FakeSoftEtherServer::new();
    let hold = Arc::new(AtomicUsize::new(0));
    let (inner, h2) = (s.factory(), hold.clone());
    let factory: StreamFactory = Arc::new(move |h: &str, p: u16, pr: &ProxySettings| {
        Box::new(HoldStream { inner: inner(h, p, pr), hold: h2.clone() }) as Box<dyn ByteStream>
    });
    let conn = connect_with(factory, config(1), &Sink::default()).await.unwrap();
    hold.store(1, Ordering::SeqCst);
    for i in 0..6000usize {
        conn.send_frame(vec![(i & 0xff) as u8, 1, 2, 3]);
    }
    assert!(conn.pending_frame_count() <= MAX_PENDING_FRAMES, "pending {}", conn.pending_frame_count());
    assert!(
        conn.dropped_frames() as usize >= 6000 - MAX_PENDING_FRAMES - FLUSH_BATCH,
        "dropped {}",
        conn.dropped_frames()
    );
    conn.close(None);
}

#[tokio::test]
async fn proxy_hides_the_remote_address() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.remote_ipv4 = Some("1.2.3.4".into()));
    let conn = connect(&s, 1, &Sink::default()).await;
    assert_eq!(conn.remote_ipv4().as_deref(), Some("1.2.3.4"));
    assert_eq!(conn.bypass_hosts(), vec!["1.2.3.4".to_string()]);
    conn.close(None);

    let mut cfg = config(1);
    cfg.proxy.kind = vpngate_core::ipc::ProxyKind::Http;
    cfg.proxy.host = "9.9.9.9".into();
    cfg.proxy.port = 8080;
    let conn = connect_with(s.factory(), cfg, &Sink::default()).await.unwrap();
    assert_eq!(conn.remote_ipv4(), None);
    assert!(conn.bypass_hosts().is_empty());
    conn.close(None);
}

// MARK: - UDP acceleration

const UDP_SERVER_KEY: [u8; 32] = [0x5a; 32];

struct UdpWelcome {
    ip: Option<&'static str>,
    ip_int: Option<u32>,
    port: u32,
    version: u32,
    server_cookie: u32,
    client_cookie: u32,
    key: Vec<u8>,
    encryption: Option<bool>,
}

impl UdpWelcome {
    fn new(port: u32) -> Self {
        UdpWelcome {
            ip: Some("127.0.0.1"),
            ip_int: None,
            port,
            version: 2,
            server_cookie: 0x1111,
            client_cookie: 0x2222,
            key: UDP_SERVER_KEY.to_vec(),
            encryption: None,
        }
    }

    fn pack(&self) -> Pack {
        let mut p = Pack::new();
        p.add_str("session_name", "SID-UDP");
        p.add_str("connection_name", "CID-1");
        p.add_data("session_key", &[3u8; 20]);
        p.add_int("max_connection", 1);
        p.add_bool("use_udp_acceleration", true);
        p.add_int("udp_acceleration_version", self.version);
        if let Some(e) = self.encryption {
            p.add_bool("udp_acceleration_use_encryption", e);
        }
        if let Some(ip) = self.ip {
            p.add_str("udp_acceleration_server_ip", ip);
        }
        if let Some(n) = self.ip_int {
            p.add_int("udp_acceleration_server_ip", n);
        }
        p.add_int("udp_acceleration_server_port", self.port);
        p.add_int("udp_acceleration_server_cookie", self.server_cookie);
        p.add_int("udp_acceleration_client_cookie", self.client_cookie);
        p.add_data("udp_acceleration_server_key_v2", &self.key);
        p
    }
}

fn udp_config() -> ClientConfig {
    let mut cfg = ClientConfig::new("127.0.0.1", 443, ProxySettings::default());
    cfg.use_udp_accel = true;
    cfg
}

async fn connect_udp(s: &FakeSoftEtherServer, w: &UdpWelcome, sink: &Sink) -> SoftEtherConnection {
    s.configure(|c| c.welcome_override = Some(w.pack()));
    connect_with(s.factory(), udp_config(), sink).await.expect("connect")
}

#[tokio::test]
async fn hostile_udp_fields_disable_udp_but_keep_tcp() {
    for port in [0u32, 65536, 70000, u32::MAX] {
        let s = FakeSoftEtherServer::new();
        let conn = connect_udp(&s, &UdpWelcome::new(port), &Sink::default()).await;
        assert_eq!(conn.welcome().session_name, "SID-UDP");
        assert_eq!(conn.welcome().udp_server_port, None, "port {port} must not become a u16");
        assert!(!conn.udp_accel_negotiated(), "port {port}");
        assert_eq!(conn.udp_local_port(), 0);
        conn.close(None);
    }
    let s = FakeSoftEtherServer::new();
    let w = UdpWelcome { ip: None, ip_int: Some(0xFFFF_FFFF), ..UdpWelcome::new(70000) };
    let conn = connect_udp(&s, &w, &Sink::default()).await;
    assert!(!conn.udp_accel_negotiated());
    conn.close(None);
}

#[tokio::test]
async fn advertised_udp_port_is_the_port_that_stays_bound() {
    let s = FakeSoftEtherServer::new();
    let w = UdpWelcome { ip: Some("10.0.0.1"), ..UdpWelcome::new(4433) }; // private: falls back to the TCP peer
    let conn = connect_udp(&s, &w, &Sink::default()).await;
    assert_eq!(conn.welcome().udp_server_ip.as_deref(), Some("127.0.0.1"));
    let advertised = s.logins()[0].int("udp_acceleration_client_port").unwrap_or(0);
    assert!(advertised > 0, "login must advertise a bound port");
    assert_eq!(u32::from(conn.udp_local_port()), advertised, "the advertised socket is the one in use");
    assert_eq!(conn.bypass_hosts(), vec!["127.0.0.1".to_string()]);
    conn.close(None);
    assert_eq!(conn.udp_local_port(), 0, "socket must be closed on close()");
}

#[tokio::test]
async fn udp_endpoint_gets_its_own_bypass_host() {
    let s = FakeSoftEtherServer::new();
    let w = UdpWelcome { ip: Some("9.9.9.9"), ..UdpWelcome::new(4433) };
    let conn = connect_udp(&s, &w, &Sink::default()).await;
    assert_eq!(conn.bypass_hosts(), vec!["127.0.0.1".to_string(), "9.9.9.9".to_string()]);
    conn.close(None);
}

#[tokio::test]
async fn welcome_gating_version_cookies_encryption() {
    let lb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = u32::from(lb.local_addr().unwrap().port());
    let cases: Vec<(UdpWelcome, bool, &str)> = vec![
        (UdpWelcome::new(port), true, "baseline: v2 with cookies uses UDP"),
        (UdpWelcome { encryption: Some(true), ..UdpWelcome::new(port) }, true, "explicit encryption"),
        (UdpWelcome { version: 1, ..UdpWelcome::new(port) }, false, "v1 key path is not implemented"),
        (UdpWelcome { version: 0, ..UdpWelcome::new(port) }, false, "version 0 means v1"),
        (UdpWelcome { server_cookie: 0, ..UdpWelcome::new(port) }, false, "zero server cookie"),
        (UdpWelcome { client_cookie: 0, ..UdpWelcome::new(port) }, false, "zero client cookie"),
        (UdpWelcome { key: vec![], encryption: Some(false), ..UdpWelcome::new(port) }, true, "plaintext needs no key"),
        (UdpWelcome { key: vec![], encryption: Some(true), ..UdpWelcome::new(port) }, false, "encrypted needs the key"),
        (UdpWelcome { key: vec![1, 2, 3], ..UdpWelcome::new(port) }, false, "short key"),
    ];
    for (w, want, why) in cases {
        let s = FakeSoftEtherServer::new();
        let conn = connect_udp(&s, &w, &Sink::default()).await;
        assert_eq!(conn.udp_local_port() != 0, want, "{why}");
        assert_eq!(conn.udp_accel_negotiated(), want, "{why}");
        conn.close(None);
    }
}

#[tokio::test]
async fn udp_off_in_config_advertises_no_socket() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.welcome_override = Some(UdpWelcome::new(4433).pack()));
    let conn = connect_with(s.factory(), config(1), &Sink::default()).await.unwrap();
    assert_eq!(s.logins()[0].int("udp_acceleration_client_port"), None);
    assert!(!conn.udp_accel_negotiated());
    conn.close(None);
}

#[tokio::test]
async fn frames_from_the_server_over_udp_reach_the_session_and_the_counters() {
    use vpngate_core::udp_accel::{self as packet, UdpAccelFields};
    let sink = Sink::default();
    let s = FakeSoftEtherServer::new();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let w = UdpWelcome::new(u32::from(server.local_addr().unwrap().port()));
    let conn = connect_udp(&s, &w, &sink).await;
    let fields = UdpAccelFields {
        cookie: 0x2222, // the client cookie the server assigned
        my_tick: 1000,
        your_tick: 1,
        compressed: false,
        payload: &[0xAB; 60],
        padding: 0,
    };
    let (wire, _) = packet::encode(&UDP_SERVER_KEY, &[1; 12], &fields, false).unwrap();
    server.send_to(&wire, ("127.0.0.1", conn.udp_local_port())).await.unwrap();
    assert!(eventually(3, || !sink.frames.lock().unwrap().is_empty()).await, "no frame from UDP");
    assert_eq!(sink.frames.lock().unwrap()[0], vec![0xAB; 60]);
    assert_eq!(conn.bytes_in(), 60);
    conn.close(None);
}

#[tokio::test]
async fn frames_go_over_tcp_until_udp_has_proven_stable() {
    let s = FakeSoftEtherServer::new();
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let conn =
        connect_udp(&s, &UdpWelcome::new(u32::from(server.local_addr().unwrap().port())), &Sink::default()).await;
    assert!(conn.udp_accel_negotiated() && !conn.udp_accel_usable());
    conn.send_frame(vec![7; 64]);
    assert!(eventually(3, || s.frames_received().contains(&vec![7; 64])).await, "frame must fall back to TCP");
    conn.close(None);
}
