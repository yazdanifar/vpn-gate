//! Ports of the fetcher tests of `VGDatTests.swift`, plus the sync pipeline, relay choice and the HTTP client.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::*;

static SEQ: AtomicUsize = AtomicUsize::new(0);

fn temp_dir() -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("vg-fetch-{}-{}", std::process::id(), SEQ.fetch_add(1, Ordering::SeqCst)));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn fixture_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Tests/Fixtures/VPNGate.dat")
}

fn fixture() -> Vec<u8> {
    std::fs::read(fixture_path()).unwrap()
}

fn fixture_ms() -> u64 {
    vgdat::parse(&fixture(), 0).unwrap().timestamp_ms
}

const HOUR_MS: u64 = 3_600_000;

/// A relay that serves `payload` after the 4-byte length, then the 1-byte reply.
struct RelayStream {
    buffer: ByteBuffer,
    payload: Vec<u8>,
    hang: bool,
    served: bool,
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    cancelled: Arc<AtomicUsize>,
}

#[async_trait]
impl ByteStream for RelayStream {
    fn buffer(&mut self) -> &mut ByteBuffer {
        &mut self.buffer
    }
    async fn start(&mut self) -> Result<(), StreamError> {
        Ok(())
    }
    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
        lock(&self.sent).push(data.to_vec());
        Ok(())
    }
    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        if self.hang {
            std::future::pending::<()>().await;
        }
        if self.served {
            return Ok(vec![1]);
        }
        self.served = true;
        let mut r = (self.payload.len() as u32).to_be_bytes().to_vec();
        r.extend_from_slice(&self.payload);
        Ok(r)
    }
    fn cancel(&mut self) {
        self.cancelled.fetch_add(1, Ordering::SeqCst);
    }
}

#[derive(Default, Clone)]
struct Relay {
    sent: Arc<Mutex<Vec<Vec<u8>>>>,
    cancelled: Arc<AtomicUsize>,
    asked: Arc<Mutex<Vec<(String, u16)>>>,
}

fn relay_factory(relay: &Relay, payload: Vec<u8>, hang: bool, fail_hosts: Vec<String>) -> StreamFactory {
    let relay = relay.clone();
    Arc::new(move |host, port, _| {
        lock(&relay.asked).push((host.to_string(), port));
        let fail = fail_hosts.iter().any(|h| h == host);
        Box::new(RelayStream {
            buffer: ByteBuffer::new(),
            payload: if fail { Vec::new() } else { payload.clone() },
            hang: hang || fail,
            served: false,
            sent: relay.sent.clone(),
            cancelled: relay.cancelled.clone(),
        })
    })
}

struct NoHttp;
#[async_trait]
impl HttpGet for NoHttp {
    async fn get(&self, _: &str, _: Duration, _: Duration, _: usize) -> Result<Vec<u8>, StreamError> {
        Err(StreamError::Closed)
    }
}

/// Serves a canned answer per URL substring and records the URLs asked.
struct CannedHttp {
    answers: Vec<(&'static str, Vec<u8>)>,
    asked: Mutex<Vec<String>>,
}
#[async_trait]
impl HttpGet for CannedHttp {
    async fn get(&self, url: &str, _: Duration, _: Duration, _: usize) -> Result<Vec<u8>, StreamError> {
        lock(&self.asked).push(url.to_string());
        self.answers.iter().find(|(k, _)| url.contains(k)).map(|(_, v)| v.clone()).ok_or(StreamError::Closed)
    }
}

fn fetcher(dir: &Path, factory: StreamFactory, now_ms: u64) -> DatFetcher {
    let mut cfg = DatFetcherConfig::new(dir.join("VPNGate.dat"));
    cfg.api_digits = Some(('a', 'b'));
    cfg.timeout_scale = 0.005;
    DatFetcher::new(factory, cfg).with_http(Arc::new(NoHttp)).with_clock(move || now_ms).with_shuffle(|s| s)
}

fn unused_factory() -> StreamFactory {
    Arc::new(|_, _, _| panic!("no relay expected"))
}

#[tokio::test]
async fn bootstrap_picks_the_newest_stored_list() {
    let dir = temp_dir();
    let mut f = fetcher(&dir, unused_factory(), fixture_ms() + HOUR_MS);
    f.config.bundle_paths = vec![fixture_path()];
    assert!(f.load_cached().is_none(), "empty temp cache");
    assert_eq!(vgdat::parse_inner_servers(&f.load_bundle().unwrap().inner).len(), 200);

    let r = f.sync(Vec::new(), &ProxySettings::default(), None).await;
    assert_eq!(r.servers.len(), 200);
    assert_eq!(r.source, ListSource::Bundle);
    assert!(r.is_fresh, "an hour old is fresh");
    assert_eq!(r.outcome, SyncOutcome::NoRelays);

    // Past 36 h the list is still used (it is signed) but is flagged stale.
    let mut stale = fetcher(&dir, unused_factory(), fixture_ms() + 40 * HOUR_MS);
    stale.config.bundle_paths = vec![fixture_path()];
    let r = stale.sync(Vec::new(), &ProxySettings::default(), None).await;
    assert_eq!(r.servers.len(), 200);
    assert!(!r.is_fresh, "40 h old must be flagged stale");
}

#[tokio::test]
async fn relay_download_with_ack_handshake() {
    let dir = temp_dir();
    let relay = Relay::default();
    let now = fixture_ms() + 60_000;
    let f = fetcher(&dir, relay_factory(&relay, fixture(), false, vec![]), now);

    let dat = f.download_from_host("1.2.3.4", 443, &ProxySettings::default()).await.unwrap();
    assert_eq!(vgdat::parse_inner_servers(&dat.inner).len(), 200);
    assert_eq!(relay.cancelled.load(Ordering::SeqCst), 1, "socket must be closed afterwards");
    assert_eq!(std::fs::read(dir.join("VPNGate.dat")).unwrap(), fixture(), "verified list is cached");

    // 1) GET request + 16-byte probe, 2) 17-byte ack, 3) 512 bytes of junk
    let sent = lock(&relay.sent).clone();
    assert_eq!(sent.len(), 3);
    let head = b"GET /vgc_download_dat/ HTTP/1.1\r\nHOST: vpngate\r\n\r\n";
    assert_eq!(&sent[0][..head.len()], head);
    assert_eq!(sent[0].len(), head.len() + 16);
    assert!(vgdat::verify_probe(&sent[0][head.len()..], vgdat::ALLOW_TIME_DIFF_MS, now));
    assert_eq!(sent[1].len(), 17);
    assert_eq!(sent[1][0], 1);
    assert_eq!(sent[2].len(), 512);
}

#[tokio::test]
async fn rejects_a_stale_list_from_a_relay() {
    let dir = temp_dir();
    let relay = Relay::default();
    let f = fetcher(&dir, relay_factory(&relay, fixture(), false, vec![]), fixture_ms() + 40 * HOUR_MS);
    assert!(f.download_from_host("1.2.3.4", 443, &ProxySettings::default()).await.is_err());
    assert!(!dir.join("VPNGate.dat").exists(), "a stale list must not be cached");
    assert_eq!(relay.cancelled.load(Ordering::SeqCst), 1);
}

#[tokio::test(start_paused = true)]
async fn gives_up_on_a_relay_that_stops_answering() {
    let dir = temp_dir();
    let relay = Relay::default();
    let f = fetcher(&dir, relay_factory(&relay, Vec::new(), true, vec![]), fixture_ms());
    let e = f.download_from_host("1.2.3.4", 443, &ProxySettings::default()).await.unwrap_err();
    assert_eq!(e, StreamError::Timeout);
    assert_eq!(relay.cancelled.load(Ordering::SeqCst), 1, "socket released after timeout");
}

#[tokio::test]
async fn a_tampered_list_is_refused() {
    let dir = temp_dir();
    let mut bad = fixture();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    let relay = Relay::default();
    let f = fetcher(&dir, relay_factory(&relay, bad, false, vec![]), fixture_ms());
    assert!(f.download_from_host("1.2.3.4", 443, &ProxySettings::default()).await.is_err());
    assert!(!dir.join("VPNGate.dat").exists());
}

fn server(ip: &str, ssl: &[u16]) -> VpnServer {
    let mut s = VpnServer::new(&format!("h-{ip}"), ip);
    s.ssl_ports = ssl.to_vec();
    s
}

#[test]
fn relay_choice_follows_the_original() {
    let servers = vec![
        server("1.1.1.1", &[995, 443]),
        server("2.2.2.2", &[995, 465]),
        server("3.3.3.3", &[]),
        server("4.4.4.4", &[1195]),
    ];
    let t = DatFetcher::select_targets(servers.clone(), 12, &|s| s);
    assert_eq!(
        t,
        vec![
            RelayTarget { ip: "1.1.1.1".into(), port: 443 },
            RelayTarget { ip: "2.2.2.2".into(), port: 995 },
            RelayTarget { ip: "4.4.4.4".into(), port: 1195 },
        ]
    );
    // each pass admits limit + 1 hosts
    let many: Vec<_> = (0..40).map(|i| server(&format!("10.0.0.{i}"), &[443])).collect();
    assert_eq!(DatFetcher::select_targets(many, 12, &|s| s).len(), 13);
    // a list without SSL ports (the CSV mirror) falls back to the listed port
    let mut csv = server("5.5.5.5", &[]);
    csv.listed_port = 1194;
    let t = DatFetcher::select_targets(vec![csv, server("6.6.6.6", &[])], 1, &|s| s);
    assert_eq!(t, vec![RelayTarget { ip: "5.5.5.5".into(), port: 1194 }]);
}

#[tokio::test]
async fn relays_are_tried_in_order_and_the_last_good_goes_first() {
    let dir = temp_dir();
    let relay = Relay::default();
    let f = fetcher(&dir, relay_factory(&relay, fixture(), false, vec!["1.1.1.1".into()]), fixture_ms());
    let candidates = vec![server("1.1.1.1", &[443]), server("2.2.2.2", &[443]), server("3.3.3.3", &[443])];

    let dat = f.fetch_from_relays(candidates.clone(), &ProxySettings::default()).await.unwrap();
    assert!(dat.is_fresh);
    assert_eq!(*lock(&relay.asked), vec![("1.1.1.1".into(), 443), ("2.2.2.2".into(), 443)]);
    assert_eq!(f.last_good_relay(), Some(RelayTarget { ip: "2.2.2.2".into(), port: 443 }));

    lock(&relay.asked).clear();
    f.fetch_from_relays(candidates, &ProxySettings::default()).await.unwrap();
    assert_eq!(lock(&relay.asked)[0], ("2.2.2.2".to_string(), 443), "last good relay first");
}

#[tokio::test]
async fn a_failing_last_good_relay_is_forgotten() {
    let dir = temp_dir();
    let relay = Relay::default();
    let f = fetcher(&dir, relay_factory(&relay, fixture(), false, vec!["2.2.2.2".into()]), fixture_ms());
    f.set_last_good_relay(Some(&RelayTarget { ip: "2.2.2.2".into(), port: 443 }));
    let r = f.fetch_from_relays(vec![server("2.2.2.2", &[443])], &ProxySettings::default()).await;
    assert!(r.is_err());
    assert_eq!(f.last_good_relay(), None);
}

#[tokio::test]
async fn the_http_api_comes_first_and_is_skipped_behind_a_proxy() {
    let dir = temp_dir();
    let http = Arc::new(CannedHttp { answers: vec![("client.api.vpngate2.jp", fixture())], asked: Mutex::default() });
    let f = fetcher(&dir, unused_factory(), fixture_ms() + 60_000).with_http(http.clone());
    let r = f.sync(Vec::new(), &ProxySettings::default(), None).await;
    assert_eq!((r.source, r.outcome, r.servers.len()), (ListSource::HttpApi, SyncOutcome::Synced, 200));
    let asked = lock(&http.asked).clone();
    assert_eq!(asked.len(), 1);
    assert!(asked[0].starts_with("http://xa.xb.client.api.vpngate2.jp/api/?session_id="), "{}", asked[0]);
    assert!(dir.join("VPNGate.dat").exists());

    // behind a proxy the API is not asked; the cache written above serves the list
    let proxy = ProxySettings { kind: ProxyKind::Socks5, host: "p".into(), port: 1080, ..Default::default() };
    let before = lock(&http.asked).len();
    let r = f.sync(Vec::new(), &proxy, None).await;
    assert_eq!(lock(&http.asked).len(), before);
    assert_eq!(r.source, ListSource::Cache);
}

#[tokio::test]
async fn alternative_mode_adds_an_https_attempt() {
    let dir = temp_dir();
    let http = Arc::new(CannedHttp { answers: vec![("https://", fixture())], asked: Mutex::default() });
    let mut f = fetcher(&dir, unused_factory(), fixture_ms()).with_http(http.clone());
    f.config.alternative_mode = true;
    f.fetch_from_http_api().await.unwrap();
    let asked = lock(&http.asked).clone();
    assert_eq!(asked.len(), 2);
    assert!(asked[0].starts_with("http://") && asked[1].starts_with("https://"));
}

#[tokio::test]
async fn csv_is_the_last_resort_and_failed_relays_set_the_outcome() {
    let dir = temp_dir();
    let line = "vpn1,1.2.3.4,100,5,1000,Japan,JP,1,1000,1,1000,2weeks,op,msg,Y29uZmln";
    let http =
        Arc::new(CannedHttp { answers: vec![("vpngate.net", line.as_bytes().to_vec())], asked: Mutex::default() });
    let relay = Relay::default();
    let f = fetcher(&dir, relay_factory(&relay, Vec::new(), true, vec![]), fixture_ms()).with_http(http);
    let r = f.sync(vec![server("9.9.9.9", &[443])], &ProxySettings::default(), None).await;
    assert_eq!(r.source, ListSource::Csv);
    assert_eq!(r.servers.len(), 1);
    assert_eq!(r.outcome, SyncOutcome::RelaysFailed);
    assert_eq!(r.timestamp_ms, None);

    let nothing =
        fetcher(&temp_dir(), unused_factory(), fixture_ms()).sync(Vec::new(), &ProxySettings::default(), None).await;
    assert!(nothing.servers.is_empty() && !nothing.is_fresh);
}

#[test]
fn poll_delays_use_the_outcome_interval_and_the_dyn_list() {
    let f = fetcher(&temp_dir(), unused_factory(), 0);
    assert_eq!(f.next_poll_delay(SyncOutcome::Synced, 5_000_000), Duration::from_millis(5_000_000 % HTTP_POLL_OK_MS));
    assert_eq!(f.next_poll_delay(SyncOutcome::RelaysFailed, 700_000), Duration::from_millis(100_000));
    assert_eq!(f.next_poll_delay(SyncOutcome::NoRelays, 599_999), Duration::from_millis(599_999));
    assert!(f.next_poll_delay(SyncOutcome::Synced, u64::MAX) < Duration::from_millis(HTTP_POLL_OK_MS));
}

#[test]
fn urls_split_into_scheme_host_port_path() {
    assert_eq!(split_url("http://a.b/api/?x=1"), Some((false, "a.b", 80, "/api/?x=1")));
    assert_eq!(split_url("https://a.b:8443"), Some((true, "a.b", 8443, "/")));
    assert_eq!(split_url("ftp://a.b/"), None);
    assert_eq!(split_url("http:///x"), None);
}

/// One-shot HTTP server on loopback answering with `response`.
async fn serve_once(response: Vec<u8>) -> u16 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut s, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 1024];
        let _ = s.read(&mut buf).await;
        let _ = s.write_all(&response).await;
        let _ = s.shutdown().await;
    });
    port
}

#[tokio::test]
async fn direct_http_get_reads_the_body() {
    let secs = Duration::from_secs(5);
    let port = serve_once(b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA".to_vec()).await;
    let body = DirectHttpGet.get(&format!("http://127.0.0.1:{port}/x"), secs, secs, 100).await.unwrap();
    assert_eq!(body, b"hello");

    // no Content-Length: the body runs to the end of the connection
    let port = serve_once(b"HTTP/1.0 200 OK\r\n\r\nabc".to_vec()).await;
    assert_eq!(DirectHttpGet.get(&format!("http://127.0.0.1:{port}/"), secs, secs, 100).await.unwrap(), b"abc");

    let port = serve_once(b"HTTP/1.0 404 Not Found\r\n\r\n".to_vec()).await;
    assert!(DirectHttpGet.get(&format!("http://127.0.0.1:{port}/"), secs, secs, 100).await.is_err());

    let port = serve_once(b"HTTP/1.0 200 OK\r\nContent-Length: 500\r\n\r\n".to_vec()).await;
    let e = DirectHttpGet.get(&format!("http://127.0.0.1:{port}/"), secs, secs, 100).await.unwrap_err();
    assert_eq!(e, StreamError::Protocol("HTTP body too large".into()));

    let mut long = b"HTTP/1.0 200 OK\r\n\r\n".to_vec();
    long.extend(vec![b'x'; 300]);
    let port = serve_once(long).await;
    assert!(DirectHttpGet.get(&format!("http://127.0.0.1:{port}/"), secs, secs, 100).await.is_err());
}
