//! The IPC v9 commands end to end: a real `IpcServer` with an `Engine` on fake networks, spoken to by the real Rust
//! `IpcClient`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::client_account::ClientAccount;
use vpngate_core::ipc::{
    ConnectConfig, ConnectionState, HelperEvent, ListSource, ProbeTarget, ProxyKind, ProxySettings, SyncOutcome,
};
use vpngate_core::pack::Pack;
use vpngate_core::vgdat;
use vpngate_ipc_client::{ClientError, IpcClient};
use vpngate_net::dat_fetcher::{DatFetcher, DatFetcherConfig, HttpGet};
use vpngate_net::session::{EmitFn, SessionControlling};
use vpngate_net::stream::{ByteStream, StreamError, StreamFactory};

use super::*;
use crate::ipc_server::{IpcServer, UidPeerAuth};

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn unique(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/vge-{}-{}-{name}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)))
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Tests/Fixtures/VPNGate.dat")
}

fn fixture_ms() -> u64 {
    vgdat::parse(&std::fs::read(fixture_path()).unwrap(), 0).unwrap().timestamp_ms
}

struct NoHttp;
#[async_trait]
impl HttpGet for NoHttp {
    async fn get(&self, _: &str, _: Duration, _: Duration, _: usize) -> Result<Vec<u8>, StreamError> {
        Err(StreamError::Closed)
    }
}

/// A relay that answers the SoftEther hello when `up`, and refuses the connection otherwise.
struct Relay {
    buffer: ByteBuffer,
    up: bool,
    reply: Option<Vec<u8>>,
}

#[async_trait]
impl ByteStream for Relay {
    fn buffer(&mut self) -> &mut ByteBuffer {
        &mut self.buffer
    }
    async fn start(&mut self) -> Result<(), StreamError> {
        if self.up {
            Ok(())
        } else {
            Err(StreamError::Io("refused".into()))
        }
    }
    async fn send(&mut self, _: &[u8]) -> Result<(), StreamError> {
        let mut hello = Pack::new();
        hello.add_str("hello", "SoftEther VPN Server");
        hello.add_int("build", 9729);
        hello.add_data("random", &[7u8; 20]);
        let body = hello.serialize();
        let mut r = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        r.extend_from_slice(&body);
        self.reply = Some(r);
        Ok(())
    }
    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        self.reply.take().ok_or(StreamError::Closed)
    }
    fn cancel(&mut self) {}
}

/// Hosts named `up-*` answer; everything else is refused.
fn relays() -> StreamFactory {
    Arc::new(|host, _, _| Box::new(Relay { buffer: ByteBuffer::new(), up: host.starts_with("up-"), reply: None }))
}

fn engine(dir: &Path, bundle: bool) -> Arc<Engine> {
    let mut cfg = DatFetcherConfig::new(dir.join("VPNGate.dat"));
    if bundle {
        cfg.bundle_paths = vec![fixture_path()];
    }
    cfg.timeout_scale = 0.005;
    let now = fixture_ms() + 3_600_000;
    let fetcher = DatFetcher::new(relays(), cfg).with_http(Arc::new(NoHttp)).with_clock(move || now);
    Arc::new(Engine::new(fetcher, relays()))
}

#[derive(Default)]
struct IdleSession;
impl SessionControlling for IdleSession {
    fn set_emit(&self, _: Option<EmitFn>) {}
    fn snapshot(&self) -> HelperEvent {
        HelperEvent::new(ConnectionState::Disconnected)
    }
    fn connect(&self, _: ConnectConfig) {}
    fn disconnect(&self) {}
}

async fn my_uid() -> u32 {
    let (a, _b) = tokio::net::UnixStream::pair().unwrap();
    a.peer_cred().unwrap().uid()
}

struct Fixture {
    _server: IpcServer,
    client: IpcClient,
    _events: tokio::sync::mpsc::UnboundedReceiver<vpngate_ipc_client::ClientEvent>,
    dir: PathBuf,
}

async fn start(engine: Option<Arc<Engine>>, dir: PathBuf) -> Fixture {
    let path = unique("s.sock");
    let uid = my_uid().await;
    let server =
        IpcServer::new(&path, Some(uid), Arc::new(UidPeerAuth::new(Some(uid), || None)), Arc::new(IdleSession));
    if let Some(e) = engine {
        server.set_engine(e);
    }
    server.start().unwrap();
    let (client, events) = IpcClient::new(&path);
    Fixture { _server: server, client, _events: events, dir }
}

async fn with_engine(bundle: bool) -> Fixture {
    let dir = unique("dir");
    std::fs::create_dir_all(&dir).unwrap();
    start(Some(engine(&dir, bundle)), dir).await
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[tokio::test]
async fn list_servers_serves_the_stored_list_without_the_network() {
    let f = with_engine(true).await;
    let r = f.client.list_servers().await.unwrap();
    assert_eq!(r.servers.len(), 200);
    assert_eq!((r.source, r.is_fresh, r.timestamp_ms), (ListSource::Bundle, true, Some(fixture_ms())));
    assert_eq!(r.next_poll_seconds, None);
    assert_eq!(r.servers[0].ssl_ports, vec![465, 995, 1195, 1897, 9008]);
}

#[tokio::test]
async fn list_servers_without_any_list_says_so() {
    let f = with_engine(false).await;
    let e = f.client.list_servers().await.unwrap_err();
    assert!(matches!(e, ClientError::Rejected(m) if m.contains("refreshServers")));
}

#[tokio::test]
async fn refresh_runs_the_pipeline_and_schedules_the_next_poll() {
    let f = with_engine(true).await;
    let r = f.client.refresh_servers(None, None).await.unwrap();
    // no relay answers the download (the fake relays are hello-only), so the shipped list serves
    assert_eq!((r.servers.len(), r.source), (200, ListSource::Bundle));
    assert_eq!(r.outcome, SyncOutcome::RelaysFailed, "the bundled servers were asked and none delivered");
    let next = r.next_poll_seconds.unwrap();
    assert!((0.0..600.0).contains(&next), "{next}");

    let s = f.client.sync_dat(None, None).await.unwrap();
    assert_eq!((s.server_count, s.source, s.is_fresh), (200, ListSource::Bundle, true));
}

#[tokio::test]
async fn sync_with_nothing_available_returns_an_empty_stale_list() {
    let f = with_engine(false).await;
    let s = f.client.sync_dat(None, None).await.unwrap();
    assert_eq!((s.server_count, s.is_fresh, s.outcome, s.timestamp_ms), (0, false, SyncOutcome::NoRelays, None));
}

#[tokio::test]
async fn probe_keeps_the_request_order_and_reports_each_relay() {
    let f = with_engine(false).await;
    let targets = ["up-1", "down-1", "up-2"].map(|h| ProbeTarget { host: h.into(), ports: Some(vec![443]) }).to_vec();
    let r = f.client.probe(targets, None, Some(2.0)).await.unwrap();
    let got: Vec<_> = r.results.iter().map(|e| (e.host.as_str(), e.ok)).collect();
    assert_eq!(got, vec![("up-1", true), ("down-1", false), ("up-2", true)]);
    assert_eq!((r.results[0].port, r.results[0].build), (Some(443), Some(9729)));
    assert!(r.results[0].connect_ms.unwrap() >= 1);
    assert_eq!(r.results[1].error.as_deref(), Some("Cannot connect"));
}

#[tokio::test]
async fn probe_uses_the_ports_of_a_known_relay() {
    let f = with_engine(true).await;
    f.client.list_servers().await.unwrap(); // makes the bundled servers known
    let known = f.client.list_servers().await.unwrap().servers.remove(0);
    let r = f.client.probe(vec![ProbeTarget { host: known.ip.clone(), ports: None }], None, None).await.unwrap();
    // The fake relays refuse everything but `up-*`; the failure names the last port tried. The list has 465 995 1195 1897
    // 9008, which the client's priority puts as 995 465 1195 ..., and three are tried.
    let why = r.results[0].error.clone().unwrap();
    assert_eq!(why, "Cannot connect (port 1195)");
}

#[tokio::test]
async fn bad_requests_are_refused_before_any_work() {
    let f = with_engine(false).await;
    let t = |h: &str| ProbeTarget { host: h.into(), ports: None };
    let rejected = |e: ClientError| match e {
        ClientError::Rejected(m) => m,
        other => panic!("{other:?}"),
    };
    assert!(rejected(f.client.probe(vec![], None, None).await.unwrap_err()).contains("at least one"));
    assert!(rejected(f.client.probe(vec![t("-x")], None, None).await.unwrap_err()).contains("invalid host"));
    let many = (0..MAX_PROBE_TARGETS + 1).map(|_| t("h")).collect();
    assert!(rejected(f.client.probe(many, None, None).await.unwrap_err()).contains("too many"));
    let bad_port = ProbeTarget { host: "h".into(), ports: Some(vec![70000]) };
    assert!(rejected(f.client.probe(vec![bad_port], None, None).await.unwrap_err()).contains("invalid port"));
    let bad_proxy = ProxySettings { kind: ProxyKind::Socks5, host: "-p".into(), port: 1, ..Default::default() };
    assert_eq!(rejected(f.client.refresh_servers(Some(bad_proxy), None).await.unwrap_err()), "invalid proxy host");
}

#[tokio::test]
async fn validate_account_reports_what_connect_would_reject() {
    let f = with_engine(false).await;
    let ok = f.client.validate_account(ClientAccount::new("Home", "vpn.example.net")).await.unwrap();
    assert!(ok.valid && ok.error.is_none());
    let bad = f.client.validate_account(ClientAccount::new("Bad", "-evil")).await.unwrap();
    assert_eq!((bad.valid, bad.error.as_deref()), (false, Some("invalid host")));
    let mut hub = ClientAccount::new("Hub", "h");
    hub.hub = "a\0b".into();
    assert_eq!(f.client.validate_account(hub).await.unwrap().error.as_deref(), Some("invalid hub name"));
}

#[tokio::test]
async fn a_daemon_without_an_engine_still_validates_but_refuses_network_commands() {
    let f = start(None, unique("none")).await;
    assert!(f.client.validate_account(ClientAccount::new("n", "h")).await.unwrap().valid);
    let e = f.client.list_servers().await.unwrap_err();
    assert!(matches!(e, ClientError::Rejected(m) if m.contains("no server engine")));
}

#[tokio::test]
async fn the_snapshot_event_still_arrives_next_to_replies() {
    let mut f = with_engine(true).await;
    assert!(f.client.connect().await);
    let first = tokio::time::timeout(Duration::from_secs(5), f._events.recv()).await.unwrap().unwrap();
    assert!(matches!(first, vpngate_ipc_client::ClientEvent::Event(e) if e.state == ConnectionState::Disconnected));
    f.client.list_servers().await.unwrap();
}
