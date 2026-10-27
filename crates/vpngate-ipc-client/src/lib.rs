//! Rust client for the daemon IPC (GTK app, integration tests). Newline-delimited JSON over a Unix socket; the Windows
//! named-pipe transport comes with U17. Mirrors `HelperClient.swift` (reconnect on demand, one event stream) and adds
//! the IPC v9 request/reply calls.

use std::collections::HashMap;
use std::fmt;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde::de::DeserializeOwned;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Mutex as AsyncMutex};
use vpngate_core::client_account::ClientAccount;
use vpngate_core::ipc::{
    ConnectConfig, HelperEvent, HelperReply, HelperRequest, ProbeResult, ProbeTarget, ProxySettings, ServerListResult,
    ServerMessage, SyncResult, ValidateResult,
};

/// A daemon line longer than this is dropped with the connection (the daemon never sends one).
const MAX_LINE_BYTES: usize = 16 << 20;
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(120);

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientError {
    /// The daemon cannot be reached, or the connection dropped before the reply.
    Disconnected,
    Timeout,
    /// The daemon answered `ok: false`.
    Rejected(String),
    /// The reply did not have the expected shape (an older daemon, most likely).
    BadReply(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Disconnected => f.write_str("Not connected to the daemon"),
            ClientError::Timeout => f.write_str("The daemon did not answer in time"),
            ClientError::Rejected(m) | ClientError::BadReply(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for ClientError {}

/// What the client's event stream delivers.
#[derive(Debug, Clone, PartialEq)]
pub enum ClientEvent {
    Event(HelperEvent),
    /// The connection ended (the daemon stopped, or the socket broke). The next send reconnects.
    Disconnected,
}

type Pending = Arc<Mutex<HashMap<i64, oneshot::Sender<HelperReply>>>>;

struct Connection {
    writer: tokio::net::unix::OwnedWriteHalf,
    generation: u64,
}

struct Shared {
    path: PathBuf,
    conn: AsyncMutex<Option<Connection>>,
    generation: Mutex<u64>,
    next_id: AtomicI64,
    pending: Pending,
    events: mpsc::UnboundedSender<ClientEvent>,
}

/// A connection to the daemon that is established on demand and survives daemon restarts.
#[derive(Clone)]
pub struct IpcClient {
    shared: Arc<Shared>,
}

impl IpcClient {
    /// Does not connect yet; the first `connect` or `send` does. Events and disconnect notices arrive on the receiver.
    pub fn new(path: impl Into<PathBuf>) -> (IpcClient, mpsc::UnboundedReceiver<ClientEvent>) {
        let (events, rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            path: path.into(),
            conn: AsyncMutex::new(None),
            generation: Mutex::new(0),
            next_id: AtomicI64::new(1),
            pending: Arc::default(),
            events,
        });
        (IpcClient { shared }, rx)
    }

    pub async fn is_connected(&self) -> bool {
        self.shared.conn.lock().await.is_some()
    }

    /// Connects unless already connected; `false` when the daemon cannot be reached.
    pub async fn connect(&self) -> bool {
        let mut conn = self.shared.conn.lock().await;
        self.ensure(&mut conn).await.is_ok()
    }

    async fn ensure(&self, conn: &mut Option<Connection>) -> io::Result<()> {
        if conn.is_some() {
            return Ok(());
        }
        let stream = tokio::net::UnixStream::connect(&self.shared.path).await?;
        let (reader, writer) = stream.into_split();
        let generation = {
            let mut g = lock(&self.shared.generation);
            *g += 1;
            *g
        };
        *conn = Some(Connection { writer, generation });
        tokio::spawn(read_loop(reader, self.shared.clone(), generation));
        Ok(())
    }

    /// Sends one request line, reconnecting first if needed. `false` when the daemon is unreachable or the write failed.
    pub async fn send(&self, request: &HelperRequest) -> bool {
        let Ok(mut line) = serde_json::to_vec(request) else { return false };
        line.push(b'\n');
        let mut conn = self.shared.conn.lock().await;
        if self.ensure(&mut conn).await.is_err() {
            return false;
        }
        let written = conn.as_mut().expect("connected").writer.write_all(&line).await;
        if written.is_err() {
            // The read loop notices the broken connection and reports it; drop the writer so the next send reconnects.
            *conn = None;
            return false;
        }
        true
    }

    /// Sends a request with a fresh `id` and waits for the reply that carries it.
    pub async fn request(&self, mut request: HelperRequest, timeout: Duration) -> Result<HelperReply, ClientError> {
        let id = self.shared.next_id.fetch_add(1, Ordering::SeqCst);
        request.id = Some(id);
        let (tx, rx) = oneshot::channel();
        lock(&self.shared.pending).insert(id, tx);
        if !self.send(&request).await {
            lock(&self.shared.pending).remove(&id);
            return Err(ClientError::Disconnected);
        }
        let outcome = tokio::time::timeout(timeout, rx).await;
        lock(&self.shared.pending).remove(&id);
        match outcome {
            Err(_) => Err(ClientError::Timeout),
            Ok(Err(_)) => Err(ClientError::Disconnected),
            Ok(Ok(reply)) if reply.ok => Ok(reply),
            Ok(Ok(reply)) => Err(ClientError::Rejected(reply.error.unwrap_or_else(|| "Request failed".into()))),
        }
    }

    async fn call<T: DeserializeOwned>(&self, request: HelperRequest) -> Result<T, ClientError> {
        let cmd = request.cmd.clone();
        let reply = self.request(request, DEFAULT_REQUEST_TIMEOUT).await?;
        reply.decode().ok_or_else(|| ClientError::BadReply(format!("Unexpected {cmd} reply")))
    }

    // MARK: session control (no reply: the answer is the next event)

    pub async fn connect_vpn(&self, config: ConnectConfig) -> bool {
        let mut r = HelperRequest::new("connect");
        r.config = Some(config);
        self.send(&r).await
    }

    pub async fn disconnect_vpn(&self) -> bool {
        self.send(&HelperRequest::new("disconnect")).await
    }

    /// Asks for a state snapshot, which arrives as an event.
    pub async fn status(&self) -> bool {
        self.send(&HelperRequest::new("status")).await
    }

    // MARK: IPC v9

    /// The list the daemon already holds (cache or shipped), no network.
    pub async fn list_servers(&self) -> Result<ServerListResult, ClientError> {
        self.call(HelperRequest::new("listServers")).await
    }

    /// Runs the daemon's sync pipeline (HTTP API, relays, cache, CSV mirror) and returns the servers.
    pub async fn refresh_servers(
        &self,
        proxy: Option<ProxySettings>,
        mirror: Option<String>,
    ) -> Result<ServerListResult, ClientError> {
        let mut r = HelperRequest::new("refreshServers");
        r.proxy = proxy;
        r.mirror = mirror;
        self.call(r).await
    }

    /// The same sync without the servers.
    pub async fn sync_dat(
        &self,
        proxy: Option<ProxySettings>,
        mirror: Option<String>,
    ) -> Result<SyncResult, ClientError> {
        let mut r = HelperRequest::new("syncDat");
        r.proxy = proxy;
        r.mirror = mirror;
        self.call(r).await
    }

    pub async fn probe(
        &self,
        targets: Vec<ProbeTarget>,
        proxy: Option<ProxySettings>,
        timeout_seconds: Option<f64>,
    ) -> Result<ProbeResult, ClientError> {
        let mut r = HelperRequest::new("probe");
        r.targets = Some(targets);
        r.proxy = proxy;
        r.timeout = timeout_seconds;
        self.call(r).await
    }

    pub async fn validate_account(&self, account: ClientAccount) -> Result<ValidateResult, ClientError> {
        let mut r = HelperRequest::new("validateAccount");
        r.account = Some(account);
        self.call(r).await
    }
}

/// Reads daemon lines until the connection ends, then reports it. `generation` keeps a stale loop from clearing a newer
/// connection.
async fn read_loop(mut reader: tokio::net::unix::OwnedReadHalf, shared: Arc<Shared>, generation: u64) {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    'read: loop {
        match reader.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            match ServerMessage::parse(&line[..nl]) {
                Some(ServerMessage::Event(e)) => {
                    let _ = shared.events.send(ClientEvent::Event(e));
                }
                Some(ServerMessage::Reply(r)) => {
                    if let Some(tx) = r.id.and_then(|id| lock(&shared.pending).remove(&id)) {
                        let _ = tx.send(r);
                    }
                }
                None => {}
            }
        }
        if buf.len() > MAX_LINE_BYTES {
            break 'read;
        }
    }
    let mut conn = shared.conn.lock().await;
    if conn.as_ref().is_some_and(|c| c.generation == generation) {
        *conn = None;
    }
    drop(conn);
    // Requests still waiting on this connection can no longer be answered.
    lock(&shared.pending).clear();
    let _ = shared.events.send(ClientEvent::Disconnected);
}

#[cfg(test)]
mod tests;
