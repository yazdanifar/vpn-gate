//! Fetches and syncs VPNGate.dat: the project's HTTP API, then peer-to-peer from relays, then the cached or bundled copy,
//! and the CSV mirror only when no verified list exists (`VGDatFetcher.swift`).
//! Reference: SoftEther Windows Client / VPN Gate Plugin FUN_00411140 (scheduler), FUN_00414230 (HTTP API),
//! FUN_00411a00 / FUN_00411f20 / FUN_00412960 (relay download), FUN_00413140.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::cert_pin::ServerCertPolicy;
pub use vpngate_core::ipc::{ListSource, SyncOutcome};
use vpngate_core::ipc::{ProxyKind, ProxySettings};
use vpngate_core::server_list::{self, VpnServer};
use vpngate_core::vgdat::{self, VgDatFile, VgTunables};

use crate::entropy::{Entropy, SystemEntropy};
use crate::stream::{ByteStream, StreamError, StreamFactory};
use crate::tls::TlsStream;

// Defaults of the client's tunables in milliseconds (client_exe.c 7366-7480, 8205-8300); a verified list's DynList can
// override each of them within [default/5, default*50].
const HTTP_POLL_OK_MS: u64 = 3_600_000; // VGC_HTTP_POLL_INTERVAL_OK
const HTTP_POLL_ERROR_MS: u64 = 600_000; // VGC_HTTP_POLL_INTERVAL_ERROR
const UDP_POLL_ERROR_MS: u64 = 600_000; // VGC_UDP_POLL_INTERVAL_ERROR (all relays failed)
const TCP_TARGET_HOSTS: u64 = 12; // VGC_NUM_TCP_TARGET_HOSTS
const TCP_CONNECT_MS: u64 = 1_000; // VGC_TCP_POLL_CONNECT_TIMEOUT
const TCP_SSL_MS: u64 = 5_000; // VGC_TCP_POLL_SSL_TIMEOUT
const DATA_MS: u64 = 60_000; // VGC_HTTP_DATA_TIMEOUT
const HTTP_CONNECT_MS: u64 = 7_000; // VGC_HTTP_CONNECT_TIMEOUT
/// Largest HTTP API body and relay payload (0x2000000, client_exe.c:9040).
pub const MAX_BODY_BYTES: usize = 32 * 1024 * 1024;
/// Timeout for the ack/junk/final-byte exchange (client_exe.c:8338, 10000 ms).
pub const TRAILER_TIMEOUT: Duration = Duration::from_secs(10);
const CSV_TIMEOUT: Duration = Duration::from_secs(60);
const LAST_GOOD_FILE: &str = "last-good-relay";

pub const DEFAULT_CSV_URLS: [&str; 2] = ["https://www.vpngate.net/api/iphone/", "http://www.vpngate.net/api/iphone/"];

#[derive(Debug, Clone)]
pub struct ServerFetchResult {
    pub servers: Vec<VpnServer>,
    pub source: ListSource,
    /// Unix milliseconds of the signed list; `None` for the CSV mirror and for nothing at all.
    pub timestamp_ms: Option<u64>,
    pub is_fresh: bool,
    pub outcome: SyncOutcome,
}

/// One relay to ask for the list: its address and the single port chosen for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayTarget {
    pub ip: String,
    pub port: u16,
}

/// Plain HTTP GET used for the project's list API and the CSV mirror. Must fail on a non-200 status or a body above
/// `max_bytes`.
#[async_trait]
pub trait HttpGet: Send + Sync {
    async fn get(
        &self,
        url: &str,
        connect_timeout: Duration,
        data_timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StreamError>;
}

fn protocol(m: impl Into<String>) -> StreamError {
    StreamError::Protocol(m.into())
}

/// Splits `scheme://host[:port]/path` (no userinfo, no IPv6 literals: the list hosts are DNS names).
fn split_url(url: &str) -> Option<(bool, &str, u16, &str)> {
    let (https, rest) = match url.split_once("://")? {
        ("https", r) => (true, r),
        ("http", r) => (false, r),
        _ => return None,
    };
    let (authority, path) = rest.find('/').map_or((rest, "/"), |i| (&rest[..i], &rest[i..]));
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (authority, if https { 443 } else { 80 }),
    };
    (!host.is_empty()).then_some((https, host, port, path))
}

/// A direct TCP connection without TLS, for `http://` URLs.
struct PlainStream {
    host: String,
    port: u16,
    buffer: ByteBuffer,
    io: Option<tokio::net::TcpStream>,
}

#[async_trait]
impl ByteStream for PlainStream {
    fn buffer(&mut self) -> &mut ByteBuffer {
        &mut self.buffer
    }
    async fn start(&mut self) -> Result<(), StreamError> {
        self.io = Some(tokio::net::TcpStream::connect((self.host.as_str(), self.port)).await?);
        Ok(())
    }
    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
        use tokio::io::AsyncWriteExt;
        Ok(self.io.as_mut().ok_or(StreamError::Closed)?.write_all(data).await?)
    }
    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        use tokio::io::AsyncReadExt;
        let io = self.io.as_mut().ok_or(StreamError::Closed)?;
        let mut buf = vec![0u8; 65536];
        let n = io.read(&mut buf).await?;
        if n == 0 {
            return Err(StreamError::Closed);
        }
        buf.truncate(n);
        Ok(buf)
    }
    fn cancel(&mut self) {
        self.io = None;
    }
}

/// Production HTTP client: HTTP/1.0 (so no chunked bodies), no cookies, no redirects, status 200 only, body capped.
/// `https://` URLs are verified against the system trust store.
pub struct DirectHttpGet;

#[async_trait]
impl HttpGet for DirectHttpGet {
    async fn get(
        &self,
        url: &str,
        connect_timeout: Duration,
        data_timeout: Duration,
        max_bytes: usize,
    ) -> Result<Vec<u8>, StreamError> {
        let (https, host, port, path) = split_url(url).ok_or_else(|| protocol(format!("Unsupported URL {url}")))?;
        let mut stream: Box<dyn ByteStream> = if https {
            Box::new(TlsStream::new(host, port, &ProxySettings::default(), ServerCertPolicy::SystemTrust))
        } else {
            Box::new(PlainStream { host: host.into(), port, buffer: ByteBuffer::new(), io: None })
        };
        let result = async {
            tokio::time::timeout(connect_timeout, stream.start()).await.map_err(|_| StreamError::Timeout)??;
            tokio::time::timeout(data_timeout, exchange(stream.as_mut(), host, path, max_bytes))
                .await
                .map_err(|_| StreamError::Timeout)?
        }
        .await;
        stream.cancel();
        result
    }
}

async fn exchange(
    stream: &mut dyn ByteStream,
    host: &str,
    path: &str,
    max_bytes: usize,
) -> Result<Vec<u8>, StreamError> {
    let request = format!("GET {path} HTTP/1.0\r\nHost: {host}\r\nUser-Agent: VPNGate/1.0\r\nAccept: */*\r\n\r\n");
    stream.send(request.as_bytes()).await?;
    let head = stream.recv_http_head().await?;
    if head.status_code() != Some(200) {
        return Err(protocol(format!("HTTP status {}", head.status_code().unwrap_or(0))));
    }
    let declared = head.headers.get("content-length").and_then(|v| v.parse::<usize>().ok());
    if declared.is_some_and(|n| n > max_bytes) {
        return Err(protocol("HTTP body too large"));
    }
    loop {
        if declared.is_none() && stream.buffer().len() > max_bytes {
            return Err(protocol("HTTP body too large"));
        }
        if declared.is_some_and(|n| stream.buffer().len() >= n) {
            break;
        }
        match stream.read_chunk().await {
            Ok(chunk) => stream.buffer().append(&chunk),
            Err(StreamError::Closed) if declared.is_none() => break,
            Err(e) => return Err(e),
        }
    }
    if declared.is_none() && stream.buffer().len() > max_bytes {
        return Err(protocol("HTTP body too large"));
    }
    let n = stream.buffer().len();
    let n = declared.map_or(n, |d| d.min(n));
    Ok(stream.buffer().take(n).expect("buffer holds n bytes"))
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

pub fn system_clock_ms() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

pub struct DatFetcherConfig {
    /// Where the newest verified list is kept (tests pass a temporary file, never the daemon's).
    pub cache_path: PathBuf,
    /// The lists shipped with the app, newest first wins on equal timestamps.
    pub bundle_paths: Vec<PathBuf>,
    /// Multiplies the original client's socket deadlines (tests use a tiny value).
    pub timeout_scale: f64,
    /// The original's "alt mode" (client_exe.c:283074), which adds an https attempt of the API.
    pub alternative_mode: bool,
    /// The two hex digits of the API host name (`x?.x?`). The original takes characters 2 and 3 of a hash of the
    /// machine; this app has no such id, so it uses random digits.
    pub api_digits: Option<(char, char)>,
}

impl DatFetcherConfig {
    pub fn new(cache_path: impl Into<PathBuf>) -> Self {
        DatFetcherConfig {
            cache_path: cache_path.into(),
            bundle_paths: Vec::new(),
            timeout_scale: 1.0,
            alternative_mode: false,
            api_digits: None,
        }
    }
}

type Clock = Arc<dyn Fn() -> u64 + Send + Sync>;
type Shuffle = Arc<dyn Fn(Vec<VpnServer>) -> Vec<VpnServer> + Send + Sync>;

pub struct DatFetcher {
    make_stream: StreamFactory,
    http: Arc<dyn HttpGet>,
    clock: Clock,
    shuffle: Shuffle,
    config: DatFetcherConfig,
    api_digits: (char, char),
    tunables: Mutex<VgTunables>,
}

fn default_shuffle(mut servers: Vec<VpnServer>) -> Vec<VpnServer> {
    let mut rng = SystemEntropy;
    for i in (1..servers.len()).rev() {
        servers.swap(i, rng.below(i + 1));
    }
    servers
}

impl DatFetcher {
    pub fn new(make_stream: StreamFactory, config: DatFetcherConfig) -> Self {
        let hex = b"0123456789abcdef";
        let mut rng = SystemEntropy;
        let api_digits = config.api_digits.unwrap_or_else(|| (hex[rng.below(16)] as char, hex[rng.below(16)] as char));
        DatFetcher {
            make_stream,
            http: Arc::new(DirectHttpGet),
            clock: Arc::new(system_clock_ms),
            shuffle: Arc::new(default_shuffle),
            config,
            api_digits,
            tunables: Mutex::new(VgTunables::default()),
        }
    }

    pub fn with_http(mut self, http: Arc<dyn HttpGet>) -> Self {
        self.http = http;
        self
    }

    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    pub fn with_shuffle(mut self, shuffle: impl Fn(Vec<VpnServer>) -> Vec<VpnServer> + Send + Sync + 'static) -> Self {
        self.shuffle = Arc::new(shuffle);
        self
    }

    pub fn cache_path(&self) -> &Path {
        &self.config.cache_path
    }

    // MARK: tunables (DynList)

    pub fn tunables(&self) -> VgTunables {
        lock(&self.tunables).clone()
    }

    /// Takes over the tunables of a verified list, like the original does for every list it parses, fresh or not.
    pub fn adopt(&self, file: &VgDatFile) {
        lock(&self.tunables).merge(&file.tunables);
    }

    fn ms(&self, name: &str, default_ms: u64) -> Duration {
        Duration::from_millis(lock(&self.tunables).value(name, default_ms))
    }

    fn scaled(&self, d: Duration) -> Duration {
        d.mul_f64(self.config.timeout_scale)
    }

    /// Next poll = Rand % interval, i.e. uniformly random in [0, interval) (client_exe.c:7366-7413), with the
    /// interval of the outcome. `random` is injectable for tests.
    pub fn next_poll_delay(&self, outcome: SyncOutcome, random: u64) -> Duration {
        let t = lock(&self.tunables);
        let interval = match outcome {
            SyncOutcome::Synced => t.value("VGC_HTTP_POLL_INTERVAL_OK", HTTP_POLL_OK_MS),
            SyncOutcome::RelaysFailed => t.value("VGC_UDP_POLL_INTERVAL_ERROR", UDP_POLL_ERROR_MS),
            SyncOutcome::NoRelays => t.value("VGC_HTTP_POLL_INTERVAL_ERROR", HTTP_POLL_ERROR_MS),
        };
        Duration::from_millis(random % interval)
    }

    // MARK: stored lists

    fn parse(&self, data: &[u8]) -> Result<VgDatFile, vgdat::VgDatError> {
        vgdat::parse(data, (self.clock)())
    }

    pub fn load_cached(&self) -> Option<VgDatFile> {
        self.parse(&std::fs::read(&self.config.cache_path).ok()?).ok()
    }

    pub fn load_bundle(&self) -> Option<VgDatFile> {
        self.config.bundle_paths.iter().find_map(|p| self.parse(&std::fs::read(p).ok()?).ok())
    }

    /// The newer of the cached and the bundled list, adopting its tunables.
    pub fn best_stored(&self) -> Option<(VgDatFile, ListSource)> {
        let best = [(self.load_cached(), ListSource::Cache), (self.load_bundle(), ListSource::Bundle)]
            .into_iter()
            .filter_map(|(f, s)| f.map(|f| (f, s)))
            .reduce(|a, b| if b.0.timestamp_ms > a.0.timestamp_ms { b } else { a })?;
        self.adopt(&best.0);
        Some(best)
    }

    /// Never lets an older (but validly signed) list overwrite a newer one.
    fn save_cached(&self, data: &[u8], new: &VgDatFile) {
        if self.load_cached().is_some_and(|existing| existing.timestamp_ms >= new.timestamp_ms) {
            return;
        }
        let path = &self.config.cache_path;
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = path.with_extension("tmp");
        if std::fs::write(&tmp, data).is_ok() && std::fs::rename(&tmp, path).is_err() {
            let _ = std::fs::remove_file(&tmp);
        }
    }

    /// Verifies a downloaded list, adopts its tunables, and keeps it when it is fresh.
    fn accept(&self, payload: &[u8]) -> Result<VgDatFile, StreamError> {
        let file = self.parse(payload).map_err(|e| protocol(format!("Invalid VPNGate.dat: {}", e.name())))?; // RSA signature
        self.adopt(&file); // the original applies DynList before the age check
        if !file.is_fresh {
            return Err(protocol(format!("Served a stale VPNGate.dat ({})", file.timestamp_ms)));
        }
        self.save_cached(payload, &file);
        Ok(file)
    }

    // MARK: HTTP API

    /// `http(s)://x<h2>.x<h3>.client.api.vpngate2.jp/api/?session_id=<random u64>` (client_exe.c:9438-9440, 9020). The
    /// X-Transaction header of the original (an RC4-obscured copy of the OS name and LAN address) is deliberately not
    /// sent; whether the server insists on it is unknown, in which case this step fails and the relays are used.
    pub fn api_url(&self, https: bool, session_id: u64) -> String {
        format!(
            "{}://x{}.x{}.client.api.vpngate2.jp/api/?session_id={session_id}",
            if https { "https" } else { "http" },
            self.api_digits.0,
            self.api_digits.1
        )
    }

    /// Asks the project's API for the list. The reply is the same signed VPNGate.dat; it is only used when it verifies
    /// and is fresh. Plain http first, then (alternative mode only) https, as the original does.
    pub async fn fetch_from_http_api(&self) -> Result<VgDatFile, StreamError> {
        let mut last = protocol("HTTP API unavailable");
        let session_id = u64::from_le_bytes(SystemEntropy.bytes(8).try_into().expect("8 bytes"));
        let schemes: &[bool] = if self.config.alternative_mode { &[false, true] } else { &[false] };
        for &https in schemes {
            let result = self
                .http
                .get(
                    &self.api_url(https, session_id),
                    self.scaled(self.ms("VGC_HTTP_CONNECT_TIMEOUT", HTTP_CONNECT_MS)),
                    self.scaled(self.ms("VGC_HTTP_DATA_TIMEOUT", DATA_MS)),
                    MAX_BODY_BYTES,
                )
                .await
                .and_then(|body| self.accept(&body));
            match result {
                Ok(f) => return Ok(f),
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    // MARK: peer-to-peer relay fetch

    /// Relay choice of FUN_00411a00 (client_exe.c:7641-7745): shuffle; pass 1 takes hosts offering 443 (port 443), pass
    /// 2 the remaining hosts that have SSL ports, each on the first port of its priority order; each pass admits at
    /// most `limit + 1` hosts (the original's post-increment `count <= N` test). Lists without SSL ports at all (the CSV
    /// mirror) fall back to the port from the OpenVPN config.
    pub fn select_targets(
        servers: Vec<VpnServer>,
        limit: usize,
        shuffle: &dyn Fn(Vec<VpnServer>) -> Vec<VpnServer>,
    ) -> Vec<RelayTarget> {
        let shuffled = shuffle(servers);
        let cap = limit + 1;
        let mut targets: Vec<RelayTarget> = shuffled
            .iter()
            .filter(|s| s.ssl_ports.contains(&443))
            .take(cap)
            .map(|s| RelayTarget { ip: s.ip.clone(), port: 443 })
            .collect();
        targets.extend(
            shuffled
                .iter()
                .filter(|s| !s.ssl_ports.contains(&443) && !s.ssl_ports.is_empty())
                .take(cap)
                .map(|s| RelayTarget { ip: s.ip.clone(), port: s.prioritized_ssl_ports()[0] }),
        );
        if targets.is_empty() {
            targets = shuffled
                .iter()
                .take(limit)
                .map(|s| RelayTarget {
                    ip: s.ip.clone(),
                    port: s.connect_port().and_then(|p| u16::try_from(p).ok()).unwrap_or(443),
                })
                .collect();
        }
        targets
    }

    fn last_good_path(&self) -> PathBuf {
        self.config.cache_path.with_file_name(LAST_GOOD_FILE)
    }

    /// The relay that delivered the last list, tried first next time (client_exe.c FUN_00411f20, 7848-7900).
    pub fn last_good_relay(&self) -> Option<RelayTarget> {
        let text = std::fs::read_to_string(self.last_good_path()).ok()?;
        let (ip, port) = text.trim().rsplit_once(':')?;
        Some(RelayTarget { ip: ip.to_string(), port: port.parse().ok()? })
    }

    fn set_last_good_relay(&self, relay: Option<&RelayTarget>) {
        let path = self.last_good_path();
        match relay {
            Some(r) => {
                if let Some(dir) = path.parent() {
                    let _ = std::fs::create_dir_all(dir);
                }
                let _ = std::fs::write(path, format!("{}:{}", r.ip, r.port));
            }
            None => {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    /// Asks the last-good relay, then up to 13 hosts with port 443 and 13 others, for the verified VPNGate.dat.
    pub async fn fetch_from_relays(
        &self,
        candidates: Vec<VpnServer>,
        proxy: &ProxySettings,
    ) -> Result<VgDatFile, StreamError> {
        let limit = usize::try_from(lock(&self.tunables).value("VGC_NUM_TCP_TARGET_HOSTS", TCP_TARGET_HOSTS))
            .unwrap_or(usize::MAX - 1);
        let mut targets = Self::select_targets(candidates, limit, &*self.shuffle);
        let last_good = self.last_good_relay();
        if let Some(l) = &last_good {
            targets.retain(|t| t != l);
            targets.insert(0, l.clone());
        }
        if targets.is_empty() {
            return Err(protocol("No target relay hosts available"));
        }
        let mut last_error = protocol("All relay hosts failed");
        for target in targets {
            match self.download_from_host(&target.ip, target.port, proxy).await {
                Ok(file) => {
                    self.set_last_good_relay(Some(&target));
                    return Ok(file);
                }
                Err(e) => {
                    last_error = e;
                    if last_good.as_ref() == Some(&target) {
                        self.set_last_good_relay(None); // the original forgets a cached relay that failed
                    }
                }
            }
        }
        Err(last_error)
    }

    /// Runs `op` under a deadline; dropping the future abandons whatever it was waiting on.
    async fn guarded<T>(
        &self,
        limit: Duration,
        op: impl Future<Output = Result<T, StreamError>>,
    ) -> Result<T, StreamError> {
        tokio::time::timeout(self.scaled(limit), op).await.map_err(|_| StreamError::Timeout)?
    }

    /// Single host download (GET /vgc_download_dat/ + probe + ack). Like the original, a list older than
    /// VG_ALLOW_TIME_DIFF is discarded so the next relay is tried.
    pub async fn download_from_host(
        &self,
        host: &str,
        port: u16,
        proxy: &ProxySettings,
    ) -> Result<VgDatFile, StreamError> {
        let mut stream = (self.make_stream)(host, port, proxy);
        let result = self.download(stream.as_mut()).await;
        stream.cancel();
        result
    }

    async fn download(&self, stream: &mut dyn ByteStream) -> Result<VgDatFile, StreamError> {
        self.guarded(
            self.ms("VGC_TCP_POLL_CONNECT_TIMEOUT", TCP_CONNECT_MS) + self.ms("VGC_TCP_POLL_SSL_TIMEOUT", TCP_SSL_MS),
            stream.start(),
        )
        .await?;

        let data_timeout = self.ms("VGC_HTTP_DATA_TIMEOUT", DATA_MS);
        let probe = vgdat::generate_probe((self.clock)());
        let payload = self
            .guarded(data_timeout, async {
                let mut request = b"GET /vgc_download_dat/ HTTP/1.1\r\nHOST: vpngate\r\n\r\n".to_vec();
                request.extend_from_slice(&probe);
                stream.send(&request).await?;
                // 4-byte big-endian payload length, then the payload
                let len = stream.recv_u32().await? as usize;
                if len == 0 || len > MAX_BODY_BYTES {
                    return Err(protocol(format!("Invalid download_dat payload length: {len}")));
                }
                stream.recv(len).await
            })
            .await?;

        // Ack (17 bytes, first = 1), 512 bytes of padding, then a best-effort 1-byte reply.
        self.guarded(TRAILER_TIMEOUT, async {
            let mut ack = [0u8; 17];
            ack[0] = 1;
            stream.send(&ack).await?;
            stream.send(&SystemEntropy.bytes(512)).await
        })
        .await?;
        let _ = self.guarded(TRAILER_TIMEOUT, stream.recv(1)).await;

        // Parse, verify the RSA signature, then require freshness before adopting it.
        self.accept(&payload)
    }

    // MARK: CSV mirror

    pub async fn fetch_csv(&self, mirror: Option<&str>) -> Result<Vec<VpnServer>, StreamError> {
        let mut last = protocol("Bad response");
        for url in mirror.into_iter().chain(DEFAULT_CSV_URLS) {
            match self.http.get(url, CSV_TIMEOUT, CSV_TIMEOUT, MAX_BODY_BYTES).await {
                Ok(body) => {
                    let servers = server_list::parse(&String::from_utf8_lossy(&body));
                    if !servers.is_empty() {
                        return Ok(servers);
                    }
                }
                Err(e) => last = e,
            }
        }
        Err(last)
    }

    // MARK: sync pipeline

    /// Executes the full fallback sync pipeline:
    /// 1. The project's HTTP API (skipped when an app proxy is set: it would not go through it)
    /// 2. P2P relay fetch (if candidate servers exist; only fresh, verified lists are accepted)
    /// 3. The newer of the cached and the bundled VPNGate.dat
    /// 4. CSV mirror fallback, only when no verified .dat exists at all
    ///
    /// A stored .dat older than 36 h is still returned (it is signed, and its SSL ports are worth more than the CSV
    /// list), but flagged `is_fresh == false` so the UI can say so.
    pub async fn sync(
        &self,
        current_servers: Vec<VpnServer>,
        proxy: &ProxySettings,
        mirror: Option<&str>,
    ) -> ServerFetchResult {
        let from_dat = |file: &VgDatFile, source, outcome| ServerFetchResult {
            servers: vgdat::parse_inner_servers(&file.inner),
            source,
            timestamp_ms: Some(file.timestamp_ms),
            is_fresh: file.is_fresh,
            outcome,
        };
        if proxy.kind == ProxyKind::None {
            if let Ok(dat) = self.fetch_from_http_api().await {
                return from_dat(&dat, ListSource::HttpApi, SyncOutcome::Synced);
            }
        }
        let mut outcome = SyncOutcome::NoRelays;
        if !current_servers.is_empty() {
            outcome = SyncOutcome::RelaysFailed;
            if let Ok(dat) = self.fetch_from_relays(current_servers.clone(), proxy).await {
                return from_dat(&dat, ListSource::RelaySync, SyncOutcome::Synced);
            }
        }
        if let Some((file, source)) = self.best_stored() {
            return from_dat(&file, source, outcome);
        }
        if let Ok(servers) = self.fetch_csv(mirror).await {
            return ServerFetchResult { servers, source: ListSource::Csv, timestamp_ms: None, is_fresh: true, outcome };
        }
        ServerFetchResult {
            servers: current_servers,
            source: ListSource::Cache,
            timestamp_ms: None,
            is_fresh: false,
            outcome,
        }
    }

    /// What the daemon already holds, without touching the network.
    pub fn stored(&self) -> Option<ServerFetchResult> {
        let (file, source) = self.best_stored()?;
        Some(ServerFetchResult {
            servers: vgdat::parse_inner_servers(&file.inner),
            source,
            timestamp_ms: Some(file.timestamp_ms),
            is_fresh: file.is_fresh,
            outcome: SyncOutcome::Synced,
        })
    }
}

#[cfg(test)]
mod tests;
