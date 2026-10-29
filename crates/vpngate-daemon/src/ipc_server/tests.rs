//! Ports of `IPCTests.swift` (the server half; the client-side reconnect tests belong to the Rust IPC client).

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::UnixStream;
use vpngate_core::ipc::{ConnectConfig, ConnectionState};

use super::*;

#[derive(Default)]
struct FakeSession {
    snapshot: Mutex<Option<HelperEvent>>,
    emit: Mutex<Option<EmitFn>>,
    connects: Mutex<Vec<ConnectConfig>>,
    disconnects: AtomicUsize,
}

impl FakeSession {
    fn emit(&self, e: HelperEvent) {
        let f = lock(&self.emit).clone();
        if let Some(f) = f {
            f(e);
        }
    }
    fn connects(&self) -> Vec<ConnectConfig> {
        lock(&self.connects).clone()
    }
}

impl SessionControlling for FakeSession {
    fn set_emit(&self, emit: Option<EmitFn>) {
        *lock(&self.emit) = emit;
    }
    fn snapshot(&self) -> HelperEvent {
        lock(&self.snapshot).clone().unwrap_or_else(|| {
            let mut e = HelperEvent::new(ConnectionState::Disconnected);
            e.helper_version = Some(vpngate_core::ipc::HELPER_VERSION);
            e
        })
    }
    fn connect(&self, config: ConnectConfig) {
        lock(&self.connects).push(config);
    }
    fn disconnect(&self) {
        self.disconnects.fetch_add(1, Ordering::SeqCst);
    }
}

async fn my_uid() -> u32 {
    let (a, _b) = UnixStream::pair().unwrap();
    a.peer_cred().unwrap().uid()
}

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn temp_path(name: &str) -> PathBuf {
    let n = SEQ.fetch_add(1, Ordering::SeqCst);
    // sockaddr_un paths are short (104 bytes on macOS), so stay out of long temp directories.
    PathBuf::from(format!("/tmp/vg-{}-{n}-{name}.sock", std::process::id()))
}

struct Fixture {
    server: IpcServer,
    session: Arc<FakeSession>,
    path: PathBuf,
}

async fn start(uid: Option<u32>, console: impl Fn() -> Option<u32> + Send + Sync + 'static) -> Fixture {
    start_as(uid, uid, console).await
}

/// `socket_uid` owns the socket file (chown needs root for anyone else); `auth_uid` is who `PeerAuth` lets in.
async fn start_as(
    socket_uid: Option<u32>,
    auth_uid: Option<u32>,
    console: impl Fn() -> Option<u32> + Send + Sync + 'static,
) -> Fixture {
    let path = temp_path("s");
    let session = Arc::new(FakeSession::default());
    let auth = Arc::new(UidPeerAuth::new(auth_uid, console));
    let server = IpcServer::new(&path, socket_uid, auth, session.clone());
    server.start().unwrap();
    Fixture { server, session, path }
}

async fn start_for_me() -> Fixture {
    start(Some(my_uid().await), || None).await
}

/// Raw client socket for protocol-level tests.
struct Raw(UnixStream);

impl Raw {
    async fn open(path: &std::path::Path) -> Raw {
        Raw(UnixStream::connect(path).await.unwrap())
    }
    async fn write(&mut self, s: &str) {
        let _ = self.0.write_all(s.as_bytes()).await;
    }
    /// Bytes read, `Some("")` on EOF, `None` on timeout.
    async fn read(&mut self, timeout_ms: u64) -> Option<String> {
        let mut buf = vec![0u8; 65536];
        match tokio::time::timeout(Duration::from_millis(timeout_ms), self.0.read(&mut buf)).await {
            Err(_) => None,
            Ok(Ok(n)) => Some(String::from_utf8_lossy(&buf[..n]).into_owned()),
            Ok(Err(_)) => Some(String::new()),
        }
    }
    /// Reads until `needle` shows up.
    async fn read_until(&mut self, needle: &str, timeout_ms: u64) -> String {
        let mut got = String::new();
        let deadline = tokio::time::Instant::now() + Duration::from_millis(timeout_ms);
        loop {
            let left = deadline.saturating_duration_since(tokio::time::Instant::now()).as_millis() as u64;
            match self.read(left.max(1)).await {
                Some(s) if !s.is_empty() => {
                    // Only the new chunk plus the bytes a needle could straddle: rescanning everything read so far
                    // is quadratic, which a test pushing megabytes through cannot afford on a slow runner.
                    let from = got.len().saturating_sub(needle.len());
                    let from = (0..=from).rev().find(|&i| got.is_char_boundary(i)).unwrap_or(0);
                    got.push_str(&s);
                    if got[from..].contains(needle) {
                        break;
                    }
                }
                _ => break,
            }
        }
        got
    }
}

async fn eventually(mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..200 {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    f()
}

#[tokio::test]
async fn sends_snapshot_on_connect() {
    let f = start_for_me().await;
    let mut e = HelperEvent::new(ConnectionState::Connected);
    e.server = Some("1.2.3.4".into());
    e.virtual_ip = Some("10.0.0.2".into());
    *lock(&f.session.snapshot) = Some(e);
    let mut c = Raw::open(&f.path).await;
    let got = c.read_until("\n", 2000).await;
    assert!(got.contains("\"connected\"") && got.contains("10.0.0.2"), "{got}");
}

#[tokio::test]
async fn connect_and_disconnect_requests_reach_the_session() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.write("{\"cmd\":\"connect\",\"host\":\"1.2.3.4\",\"port\":443}\n").await;
    assert!(eventually(|| f.session.connects().len() == 1).await);
    let cfg = &f.session.connects()[0];
    assert_eq!(cfg.host, "1.2.3.4");
    assert_eq!(cfg.ports[0], 443);
    c.write("{\"cmd\":\"disconnect\"}\n").await;
    assert!(eventually(|| f.session.disconnects.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test]
async fn config_requests_pass_through_untouched() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.write("{\"cmd\":\"connect\",\"config\":{\"host\":\"h.example\",\"hubName\":\"HUB\",\"maxConnection\":4}}\n")
        .await;
    assert!(eventually(|| f.session.connects().len() == 1).await);
    let cfg = &f.session.connects()[0];
    assert_eq!((cfg.host.as_str(), cfg.hub_name.as_str(), cfg.max_connection), ("h.example", "HUB", 4));
}

#[tokio::test]
async fn events_are_broadcast_to_every_client() {
    let f = start_for_me().await;
    let (mut a, mut b) = (Raw::open(&f.path).await, Raw::open(&f.path).await);
    a.read_until("\n", 2000).await;
    b.read_until("\n", 2000).await;
    let mut ev = HelperEvent::new(ConnectionState::Dhcp);
    ev.log = Some("hello".into());
    f.session.emit(ev);
    assert!(a.read_until("hello", 2000).await.contains("hello"));
    assert!(b.read_until("hello", 2000).await.contains("hello"));
}

#[tokio::test]
async fn tolerates_garbage_and_split_lines() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    c.write("garbage\n\n{not json}\n").await;
    c.write("{\"cmd\":\"disc").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    c.write("onnect\"}\n").await;
    assert!(eventually(|| f.session.disconnects.load(Ordering::SeqCst) == 1).await, "split line not reassembled");
    c.write("{\"cmd\":\"status\"}\n").await;
    assert!(c.read_until("state", 2000).await.contains("state"));
}

#[tokio::test]
async fn rejects_other_users() {
    let f = start_as(None, Some(my_uid().await + 1), || None).await;
    let mut c = Raw::open(&f.path).await;
    assert_eq!(c.read(1500).await.as_deref(), Some(""), "must be closed without data");
    c.write("{\"cmd\":\"disconnect\"}\n").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.session.disconnects.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn flags_are_forwarded_with_safe_defaults() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    c.write("{\"cmd\":\"connect\",\"host\":\"1.2.3.4\"}\n").await;
    c.write("{\"cmd\":\"connect\",\"host\":\"1.2.3.4\",\"blockIPv6\":false}\n").await;
    assert!(eventually(|| f.session.connects().len() == 2).await);
    let flags: Vec<bool> = f.session.connects().iter().map(|c| c.block_ipv6).collect();
    assert_eq!(flags, [true, false], "IPv6 must be blocked unless the app explicitly says otherwise");
    assert!(f.session.connects()[0].auto_reconnect);
}

#[tokio::test]
async fn console_user_is_accepted_without_a_configured_uid() {
    let me = my_uid().await;
    let f = start(None, move || Some(me)).await;
    let mut c = Raw::open(&f.path).await;
    assert!(c.read_until("state", 2000).await.contains("state"), "console user must get the snapshot");
    c.write("{\"cmd\":\"disconnect\"}\n").await;
    assert!(eventually(|| f.session.disconnects.load(Ordering::SeqCst) == 1).await);
}

#[tokio::test]
async fn non_console_users_are_rejected_in_console_mode() {
    let me = my_uid().await;
    let f = start(None, move || Some(me + 1)).await;
    let mut c = Raw::open(&f.path).await;
    assert_eq!(c.read(1500).await.as_deref(), Some(""));
    c.write("{\"cmd\":\"disconnect\"}\n").await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(f.session.disconnects.load(Ordering::SeqCst), 0);
    // nobody logged in: only root may talk to the daemon
    if me != 0 {
        let g = start(None, || None).await;
        assert_eq!(Raw::open(&g.path).await.read(1500).await.as_deref(), Some(""));
    }
}

#[tokio::test]
async fn console_uid_is_resolved_per_connection() {
    let me = my_uid().await;
    let who = Arc::new(Mutex::new(Some(me + 1)));
    let w = who.clone();
    let f = start(None, move || *lock(&w)).await;
    assert_eq!(Raw::open(&f.path).await.read(1500).await.as_deref(), Some(""), "before the user logs in");
    *lock(&who) = Some(me); // fast user switching / login
    assert!(Raw::open(&f.path).await.read_until("state", 2000).await.contains("state"));
}

#[test]
fn console_uid_matches_the_console_device() {
    use std::os::unix::fs::MetadataExt;
    let want = std::fs::metadata("/dev/console").ok().map(|m| m.uid()).filter(|&u| u != 0);
    assert_eq!(current_console_uid(), want);
}

#[test]
fn root_is_always_allowed_and_nobody_else_by_default() {
    let a = UidPeerAuth::new(None, || None);
    assert!(a.is_allowed(&Peer { uid: 0, gid: 0 }));
    assert!(!a.is_allowed(&Peer { uid: 501, gid: 501 }));
    // a console owner of root never grants anything extra
    let b = UidPeerAuth::new(None, || Some(0));
    assert!(!b.is_allowed(&Peer { uid: 501, gid: 501 }));
}

#[tokio::test]
async fn socket_mode_follows_the_configured_user() {
    let f = start_for_me().await;
    assert_eq!(std::fs::metadata(&f.path).unwrap().permissions().mode() & 0o777, 0o600);
    let g = start(None, || None).await;
    assert_eq!(std::fs::metadata(&g.path).unwrap().permissions().mode() & 0o777, 0o666);
}

#[tokio::test]
async fn invalid_connect_requests_are_rejected_before_reaching_the_session() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    for host in ["-interface", "1.2.3.4; reboot", "", "a b"] {
        let h = serde_json::to_string(host).unwrap();
        c.write(&format!("{{\"cmd\":\"connect\",\"host\":{h},\"port\":443}}\n")).await;
    }
    for port in [0, 70000, -1] {
        c.write(&format!("{{\"cmd\":\"connect\",\"host\":\"1.2.3.4\",\"port\":{port}}}\n")).await;
    }
    c.write("{\"cmd\":\"connect\",\"host\":\"1.2.3.4\",\"proxy\":{\"kind\":\"http\",\"host\":\"-x\",\"port\":80}}\n")
        .await;
    c.write("{\"cmd\":\"connect\",\"host\":\"1.2.3.4\",\"proxy\":{\"kind\":\"http\",\"host\":\"p\",\"port\":99999}}\n")
        .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(f.session.connects().is_empty(), "session received: {:?}", f.session.connects());
    c.write("{\"cmd\":\"connect\",\"host\":\"vpn1.example.net\",\"port\":443}\n").await;
    assert!(eventually(|| f.session.connects().len() == 1).await);
}

#[tokio::test]
async fn rejected_request_reports_an_error_event() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    c.write("{\"cmd\":\"connect\",\"host\":\"-interface\"}\n").await;
    let r = c.read_until("error", 2000).await;
    assert!(r.contains("Rejected connect request: invalid host"), "client not told why: {r}");
}

#[tokio::test]
async fn slow_client_cannot_stall_the_session() {
    let f = start_for_me().await;
    let slow = Raw::open(&f.path).await; // connects, never reads
    let mut good = Raw::open(&f.path).await;
    good.read_until("\n", 2000).await;
    let mut ev = HelperEvent::new(ConnectionState::Connected);
    ev.log = Some("x".repeat(60_000));
    let started = std::time::Instant::now();
    for _ in 0..300 {
        f.session.emit(ev.clone());
    }
    assert!(started.elapsed() < Duration::from_secs(3), "emit blocked on a client that is not reading");
    // The slow client is dropped after the stall timeout, the good one keeps working.
    let mut ping = HelperEvent::new(ConnectionState::Dhcp);
    ping.log = Some("ping".into());
    f.session.emit(ping);
    assert!(good.read_until("ping", 5000).await.contains("ping"));
    assert!(eventually(|| f.server.client_count() <= 1).await || f.server.client_count() == 2);
    drop(slow);
}

#[tokio::test]
async fn client_gone_mid_broadcast_is_survivable() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    drop(c);
    for _ in 0..50 {
        f.session.emit(HelperEvent::new(ConnectionState::Connected));
    }
    let mut c2 = Raw::open(&f.path).await;
    assert!(c2.read(2000).await.is_some(), "server still serves new clients");
}

#[tokio::test]
async fn runaway_line_drops_the_client() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    let junk = vec![b'a'; MAX_LINE_BYTES + 8192];
    let _ = c.0.write_all(&junk).await;
    let mut eof = false;
    for _ in 0..40 {
        if c.read(100).await.as_deref() == Some("") {
            eof = true;
            break;
        }
    }
    assert!(eof, "client was not dropped");
    assert!(eventually(|| f.server.client_count() == 0).await);
}

#[tokio::test]
async fn stop_closes_clients_and_removes_the_socket() {
    let f = start_for_me().await;
    let mut c = Raw::open(&f.path).await;
    c.read(2000).await;
    f.server.stop();
    assert!(!f.path.exists());
    assert_eq!(c.read(2000).await.as_deref(), Some(""));
    // the same path can be bound again right away
    let again = IpcServer::new(&f.path, f.server.allowed_uid, f.server.auth.clone(), f.session.clone());
    again.start().unwrap();
    assert!(f.path.exists());
}

#[test]
fn outbox_drops_the_oldest_event_when_full() {
    let c = Client::new();
    for i in 0..(MAX_QUEUED_EVENTS + 10) {
        c.send(vec![(i % 251) as u8, (i / 251) as u8]);
    }
    assert_eq!(lock(&c.outbox).queue.len(), MAX_QUEUED_EVENTS);
    assert_eq!(c.next().unwrap(), vec![10, 0], "the 10 oldest were dropped");
    c.close();
    c.send(vec![1]);
    assert!(c.next().is_none(), "a closed client takes nothing");
}
