//! A logged-in SoftEther session: cluster redirects, the TCP pool with its additional connections, keep-alives and the
//! frame send queue (the data-services half of `SoftEtherClient.swift`). UDP acceleration is U10b.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::task::JoinHandle;
use vpngate_core::data_phase::{self, MAX_BLOCK};
use vpngate_core::pack::Pack;
use vpngate_core::softether_error;

use crate::connection_pool::{ByteCountFn, CloseFn, ConnectionPool, FrameFn, PoolCallbacks, SocketDirection};
use crate::entropy::{Entropy, SystemEntropy};
use crate::softether_client::{
    http_post, read_pack, upload_signature, ClientAuth, ConnectOutcome, SoftEtherClient, Welcome, CLIENT_BUILD,
    CLIENT_STR, CLIENT_VER,
};
use crate::stream::StreamError;

const MAX_REDIRECTS: u32 = 5;
/// Frames waiting for the TCP pool; beyond this they are dropped like a full interface queue (~13 MB of frames).
pub const MAX_PENDING_FRAMES: usize = 4096;
const FLUSH_BATCH: usize = 64;

pub struct ConnectionEvents {
    pub on_frame: FrameFn,
    /// Called once when the session ends; `None` for a clean close.
    pub on_close: CloseFn,
}

pub struct ConnectOptions {
    /// Poll/backoff base for topping up the additional-connection pool (tests shorten it).
    pub replenish_interval: Duration,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        ConnectOptions { replenish_interval: Duration::from_secs(1) }
    }
}

#[derive(Default)]
struct Shared {
    closed: bool,
    pending: VecDeque<Vec<u8>>,
    flushing: bool,
    dropped_frames: u64,
    connected_ipv4: Option<String>,
    tasks: Vec<JoinHandle<()>>,
}

struct Inner {
    client: Mutex<SoftEtherClient>,
    pool: ConnectionPool,
    welcome: Welcome,
    shared: Mutex<Shared>,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    on_close: CloseFn,
    replenish_interval: Duration,
    direct: bool,
}

/// Handle to an established session. Dropping it closes the session.
pub struct SoftEtherConnection {
    inner: Arc<Inner>,
}

impl Drop for SoftEtherConnection {
    fn drop(&mut self) {
        self.inner.close(None);
    }
}

impl SoftEtherClient {
    /// Connects, following up to 5 cluster redirects, then starts the keep-alive and pool services.
    pub async fn connect(
        mut self,
        log: &mut (dyn FnMut(&str) + Send),
        events: ConnectionEvents,
        options: ConnectOptions,
    ) -> Result<SoftEtherConnection, StreamError> {
        let mut redirects = 0;
        while redirects < MAX_REDIRECTS {
            let (host, port, auth) = {
                let c = self.config();
                (c.host.clone(), c.port, c.auth.clone())
            };
            match self.connect_once(&host, port, &auth, log, None).await? {
                ConnectOutcome::Redirect(r) => {
                    redirects += 1;
                    log(&format!("Cluster redirect ({redirects}/{MAX_REDIRECTS}) to {}:{}", r.host, r.port));
                    self.retarget(r.host, r.port, ClientAuth::Ticket(r.ticket));
                }
                ConnectOutcome::Connected { welcome, stream } => {
                    let welcome = *welcome;
                    log(&format!(
                        "Session {} established (TCP max={}, compress={}, UDP={})",
                        welcome.session_name,
                        welcome.max_connection,
                        welcome.use_compress,
                        welcome.use_udp_acceleration
                    ));
                    let direct = self.config().proxy.kind == vpngate_core::ipc::ProxyKind::None;
                    let remote = stream.remote_ipv4();
                    return Ok(SoftEtherConnection::start(self, welcome, stream, remote, direct, events, options));
                }
            }
        }
        Err(StreamError::Protocol(format!("Too many cluster redirects ({redirects})")))
    }
}

impl SoftEtherConnection {
    fn start(
        client: SoftEtherClient,
        welcome: Welcome,
        stream: Box<dyn crate::stream::ByteStream>,
        remote_ipv4: Option<String>,
        direct: bool,
        events: ConnectionEvents,
        options: ConnectOptions,
    ) -> Self {
        let half = client.config().half_connection;
        let ConnectionEvents { on_frame, on_close } = events;

        // Two-step wiring: the pool's callbacks need the Inner that owns the pool.
        let slot: Arc<Mutex<Weak<Inner>>> = Arc::new(Mutex::new(Weak::new()));
        let close_slot = slot.clone();
        let on_pool_close: CloseFn = Arc::new(move |e| {
            if let Some(i) = close_slot.lock().expect("slot").upgrade() {
                i.close(e);
            }
        });
        let count_slot = slot.clone();
        let on_byte_count: ByteCountFn = Arc::new(move |b_in, b_out| {
            if let Some(i) = count_slot.lock().expect("slot").upgrade() {
                i.bytes_in.fetch_add(b_in as u64, Ordering::Relaxed);
                i.bytes_out.fetch_add(b_out as u64, Ordering::Relaxed);
            }
        });
        let callbacks = PoolCallbacks { on_frame, on_close: on_pool_close, on_byte_count };
        let pool = ConnectionPool::new(callbacks);

        let inner = Arc::new(Inner {
            client: Mutex::new(client),
            pool: pool.clone(),
            welcome: welcome.clone(),
            shared: Mutex::new(Shared { connected_ipv4: remote_ipv4, ..Shared::default() }),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            on_close,
            replenish_interval: options.replenish_interval,
            direct,
        });
        *slot.lock().expect("slot") = Arc::downgrade(&inner);

        // The primary connection is always client-to-server when half connection is on (Protocol.c:4172-4176);
        // the server-to-client direction is only ever assigned to an additional connection.
        let direction = if half { SocketDirection::ClientToServer } else { SocketDirection::Both };
        pool.add(stream, welcome.use_compress, welcome.timeout_ms as u64, direction);
        inner.start_services();
        SoftEtherConnection { inner }
    }

    pub fn welcome(&self) -> &Welcome {
        &self.inner.welcome
    }

    pub fn bytes_in(&self) -> u64 {
        self.inner.bytes_in.load(Ordering::Relaxed)
    }

    pub fn bytes_out(&self) -> u64 {
        self.inner.bytes_out.load(Ordering::Relaxed)
    }

    pub fn active_connection_count(&self) -> usize {
        self.inner.pool.active_count()
    }

    pub fn dropped_frames(&self) -> u64 {
        self.inner.shared().dropped_frames
    }

    pub fn pending_frame_count(&self) -> usize {
        self.inner.shared().pending.len()
    }

    /// The IPv4 address the established session's TLS connection went to (`None` behind a proxy or when unknown).
    pub fn remote_ipv4(&self) -> Option<String> {
        if !self.inner.direct {
            return None;
        }
        self.inner.shared().connected_ipv4.clone()
    }

    /// Hosts that must stay reachable outside a full tunnel: the host the session really ended up on (after cluster
    /// redirects; none when a proxy carries the TCP traffic). The UDP acceleration endpoint joins in U10b.
    pub fn bypass_hosts(&self) -> Vec<String> {
        if !self.inner.direct {
            return Vec::new();
        }
        let ip = self.inner.shared().connected_ipv4.clone();
        let host = ip.unwrap_or_else(|| self.inner.client.lock().expect("client").config().host.clone());
        vec![host]
    }

    /// Queues an Ethernet frame for the pool. Frames beyond [`MAX_PENDING_FRAMES`] are dropped.
    pub fn send_frame(&self, frame: Vec<u8>) {
        if frame.len() > MAX_BLOCK {
            return;
        }
        let spawn = {
            let mut sh = self.inner.shared();
            if sh.closed {
                return;
            }
            if sh.pending.len() >= MAX_PENDING_FRAMES {
                sh.dropped_frames += 1;
                return;
            }
            sh.pending.push_back(frame);
            if sh.flushing {
                false
            } else {
                sh.flushing = true;
                true
            }
        };
        if spawn {
            let weak = Arc::downgrade(&self.inner);
            tokio::spawn(flush(weak));
        }
    }

    pub fn close(&self, error: Option<StreamError>) {
        self.inner.close(error);
    }
}

impl Inner {
    fn shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock().expect("connection state")
    }

    fn is_closed(&self) -> bool {
        self.shared().closed
    }

    fn start_services(self: &Arc<Self>) {
        let timeout_ms = self.welcome.timeout_ms.max(0) as u64;
        let mut tasks = vec![tokio::spawn(keep_alive_loop(Arc::downgrade(self), timeout_ms))];
        if self.welcome.max_connection > 1 {
            if let Some(key) = self.welcome.session_key.clone() {
                tasks.push(tokio::spawn(replenish_loop(
                    Arc::downgrade(self),
                    self.welcome.max_connection,
                    key,
                    self.welcome.use_compress,
                    timeout_ms,
                )));
            }
        }
        let mut sh = self.shared();
        if sh.closed {
            tasks.iter().for_each(JoinHandle::abort);
        } else {
            sh.tasks = tasks;
        }
    }

    fn close(&self, error: Option<StreamError>) {
        let tasks = {
            let mut sh = self.shared();
            if sh.closed {
                return;
            }
            sh.closed = true;
            std::mem::take(&mut sh.tasks)
        };
        tasks.iter().for_each(JoinHandle::abort);
        self.pool.close(error.clone());
        (self.on_close)(error);
    }
}

async fn flush(weak: Weak<Inner>) {
    loop {
        let Some(inner) = weak.upgrade() else { return };
        let frames: Vec<Vec<u8>> = {
            let mut sh = inner.shared();
            let n = sh.pending.len().min(FLUSH_BATCH);
            let frames: Vec<_> = sh.pending.drain(..n).collect();
            if frames.is_empty() {
                sh.flushing = false;
                return;
            }
            frames
        };
        let total: usize = frames.iter().map(Vec::len).sum();
        let result = match data_phase::encode_compressed(&frames, inner.welcome.use_compress) {
            Ok(encoded) => inner.pool.send(encoded, total).await,
            Err(e) => Err(StreamError::Protocol(e.to_string())),
        };
        if let Err(e) = result {
            inner.close(Some(e));
            return;
        }
    }
}

/// Timer jitter and junk length are timing-driven, so they stay on the system generator and out of the injected
/// `Entropy` (whose draw order the golden transcripts pin).
async fn keep_alive_loop(weak: Weak<Inner>, timeout_ms: u64) {
    let mut rng = SystemEntropy;
    loop {
        let lo = (timeout_ms / 5).max(1000) as usize;
        let hi = ((timeout_ms / 2) as usize).max(lo + 1);
        let wait = lo + rng.below(hi - lo + 1);
        tokio::time::sleep(Duration::from_millis(wait as u64)).await;
        let Some(inner) = weak.upgrade() else { return };
        let n = rng.below(512);
        let junk = rng.bytes(n);
        inner.pool.broadcast_keep_alive(&data_phase::encode_keep_alive(&junk));
    }
}

/// Keeps the pool at the negotiated size: opens the additional TCP connections and replaces any that die.
async fn replenish_loop(weak: Weak<Inner>, target: usize, key: Vec<u8>, use_compress: bool, timeout_ms: u64) {
    let mut failures: u32 = 0;
    loop {
        let Some(inner) = weak.upgrade() else { return };
        if inner.is_closed() {
            return;
        }
        let interval = inner.replenish_interval;
        let delay = if inner.pool.active_count() >= target {
            interval
        } else {
            match open_additional(&inner, &key, use_compress, timeout_ms).await {
                Ok(()) => {
                    failures = 0;
                    Duration::ZERO
                }
                Err(_) => {
                    if inner.is_closed() {
                        return;
                    }
                    failures += 1;
                    interval.mul_f64(f64::from(1u32 << (failures - 1).min(5))).min(Duration::from_secs(30))
                }
            }
        };
        drop(inner);
        tokio::time::sleep(delay).await;
    }
}

async fn open_additional(
    inner: &Arc<Inner>,
    key: &[u8],
    use_compress: bool,
    timeout_ms: u64,
) -> Result<(), StreamError> {
    if inner.is_closed() {
        return Ok(());
    }
    let (host, port, proxy, factory) = {
        let c = inner.client.lock().expect("client");
        let cfg = c.config();
        (cfg.host.clone(), cfg.port, cfg.proxy.clone(), c.make_stream())
    };
    let mut stream = factory(&host, port, &proxy);
    let result = additional_handshake(inner, stream.as_mut(), &host, key).await;
    match result {
        Ok(direction) if !inner.is_closed() => {
            inner.pool.add(stream, use_compress, timeout_ms, direction);
            Ok(())
        }
        Ok(_) => {
            stream.cancel();
            Ok(())
        }
        Err(e) => {
            stream.cancel();
            Err(e)
        }
    }
}

async fn additional_handshake(
    inner: &Inner,
    s: &mut dyn crate::stream::ByteStream,
    host: &str,
    key: &[u8],
) -> Result<SocketDirection, StreamError> {
    s.start().await?;
    if inner.is_closed() {
        return Ok(SocketDirection::Both);
    }
    // Signature: same upload as the first connection (ClientUploadSignature), then the server hello is discarded.
    let body = inner.client.lock().expect("client").signature_body();
    upload_signature(s, &body, host).await?;

    // Additional connect pack (PackAddClientVersion + the pencore HttpClientSend appends to every pack).
    let mut p = Pack::new();
    p.add_str("method", "additional_connect");
    p.add_data("session_key", key);
    p.add_str("client_str", CLIENT_STR);
    p.add_int("client_ver", CLIENT_VER);
    p.add_int("client_build", CLIENT_BUILD);
    let bytes = inner.client.lock().expect("client").with_dummy(p).serialize();
    s.send(&http_post("/vpnsvc/vpn.cgi", "application/octet-stream", &bytes, host)).await?;
    let resp = read_pack(s).await?;
    if let Some(err) = resp.int("error") {
        if err != 0 {
            return Err(StreamError::Protocol(format!(
                "Additional connection refused: {}",
                softether_error::describe(i64::from(err))
            )));
        }
    }
    // The reply's `direction` is chosen by the server, only when half connection was requested.
    Ok(SocketDirection::from_wire(resp.int("direction")))
}

#[cfg(test)]
mod tests;
