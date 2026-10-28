//! Newline-delimited JSON over a local stream (`IPCServer.swift`): a Unix socket restricted by peer uid, or (Windows) a
//! named pipe whose listener lives in `pipe_server`. Both feed accepted streams to the same [`Inner`].
//!
//! Writes go through a bounded outbox per client, drained by that client's own task, so a client that stops reading can
//! never stall the VPN session or other clients: `broadcast` only pushes to queues and never waits.

use std::collections::VecDeque;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{watch, Notify};
#[cfg(unix)]
use tokio::task::JoinHandle;
use vpngate_core::ipc::{HelperEvent, HelperReply, HelperRequest, TunnelMode, DEFAULT_SOCKS_PORT};
use vpngate_net::session::{legacy_connect_config, EmitFn, SessionControlling};

use crate::engine::{check_probe, check_proxy, validate_account, Engine};
use crate::validate::validate;

/// Events are state snapshots, so a client that falls this far behind loses the oldest ones.
pub const MAX_QUEUED_EVENTS: usize = 256;
/// A client that accepts no bytes for this long is dropped.
pub const STALL_TIMEOUT: Duration = Duration::from_millis(2000);
/// A longer line (or an unterminated run of bytes) drops the client.
pub const MAX_LINE_BYTES: usize = 1 << 20;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Who is on the other end of a Unix socket connection.
#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Peer {
    pub uid: u32,
}

/// Decides whether a connecting peer may talk to the daemon.
#[cfg(unix)]
pub trait PeerAuth: Send + Sync {
    fn is_allowed(&self, peer: &Peer) -> bool;
}

/// root, the explicitly configured user, or whoever is logged in at the console.
#[cfg(unix)]
pub struct UidPeerAuth {
    allowed_uid: Option<u32>,
    /// Owner of the login session, looked up per connection so fast user switching works.
    console_uid: Box<dyn Fn() -> Option<u32> + Send + Sync>,
}

#[cfg(unix)]
impl UidPeerAuth {
    pub fn new(allowed_uid: Option<u32>, console_uid: impl Fn() -> Option<u32> + Send + Sync + 'static) -> Self {
        UidPeerAuth { allowed_uid, console_uid: Box::new(console_uid) }
    }
}

#[cfg(unix)]
impl PeerAuth for UidPeerAuth {
    fn is_allowed(&self, peer: &Peer) -> bool {
        peer.uid == 0
            || Some(peer.uid) == self.allowed_uid
            || (self.console_uid)().is_some_and(|c| c == peer.uid && c != 0)
    }
}

/// uid of the user logged in at the machine's console (owner of `/dev/console`); `None` when nobody is.
#[cfg(unix)]
pub fn current_console_uid() -> Option<u32> {
    use std::os::unix::fs::MetadataExt;
    let uid = std::fs::metadata("/dev/console").ok()?.uid();
    (uid != 0).then_some(uid)
}

/// Drop-oldest queue of encoded events.
struct Outbox {
    queue: VecDeque<Vec<u8>>,
    closed: bool,
}

struct Client {
    outbox: Mutex<Outbox>,
    wake: Notify,
    closed: watch::Sender<bool>,
    is_closed: AtomicBool,
}

impl Client {
    fn new() -> Arc<Client> {
        Arc::new(Client {
            outbox: Mutex::new(Outbox { queue: VecDeque::new(), closed: false }),
            wake: Notify::new(),
            closed: watch::channel(false).0,
            is_closed: AtomicBool::new(false),
        })
    }

    fn send(&self, line: Vec<u8>) {
        let mut o = lock(&self.outbox);
        if o.closed {
            return;
        }
        if o.queue.len() >= MAX_QUEUED_EVENTS {
            o.queue.pop_front(); // events are state snapshots: newest wins
        }
        o.queue.push_back(line);
        drop(o);
        self.wake.notify_one();
    }

    fn next(&self) -> Option<Vec<u8>> {
        lock(&self.outbox).queue.pop_front()
    }

    fn close(&self) {
        if self.is_closed.swap(true, Ordering::SeqCst) {
            return;
        }
        let mut o = lock(&self.outbox);
        o.closed = true;
        o.queue.clear();
        drop(o);
        self.closed.send_replace(true);
    }

    fn is_closed(&self) -> bool {
        self.is_closed.load(Ordering::SeqCst)
    }

    async fn wait_closed(&self) {
        let mut rx = self.closed.subscribe();
        let _ = rx.wait_for(|c| *c).await;
    }
}

struct Inner {
    session: Arc<dyn SessionControlling>,
    clients: Mutex<Vec<Arc<Client>>>,
    engine: Mutex<Option<Arc<Engine>>>,
}

fn encode_reply(r: &HelperReply) -> Option<Vec<u8>> {
    let mut d = serde_json::to_vec(r).ok()?;
    d.push(b'\n');
    Some(d)
}

impl Inner {
    /// IPC v9 request/reply commands. They never touch the session, so a slow sync or probe only delays its own reply.
    fn handle_v9(&self, cmd: &str, r: HelperRequest, client: &Arc<Client>) {
        let id = r.id;
        let reply = |c: &Arc<Client>, reply: HelperReply| {
            if let Some(line) = encode_reply(&reply) {
                c.send(line);
            }
        };
        if cmd == "validateAccount" {
            let out = validate_account(&r);
            reply(
                client,
                match out {
                    Ok(v) => HelperReply::success(cmd, id, &v),
                    Err(e) => HelperReply::failure(cmd, id, e),
                },
            );
            return;
        }
        let Some(engine) = lock(&self.engine).clone() else {
            reply(client, HelperReply::failure(cmd, id, "This daemon has no server engine"));
            return;
        };
        let cmd = cmd.to_string();
        let client = client.clone();
        // Checked here, before spawning, so a bad request is answered in order.
        let prepared = match cmd.as_str() {
            "probe" => check_probe(&r).map(|(t, p, to)| (Some(t), p, to)),
            "listServers" => Ok((None, Default::default(), 0.0)),
            _ => check_proxy(&r).map(|p| (None, p, 0.0)),
        };
        let (targets, proxy, timeout) = match prepared {
            Ok(p) => p,
            Err(e) => return reply(&client, HelperReply::failure(&cmd, id, e)),
        };
        let mirror = r.mirror;
        tokio::spawn(async move {
            let out = match cmd.as_str() {
                "listServers" => engine.list_servers().map(|v| HelperReply::success(&cmd, id, &v)),
                "refreshServers" => {
                    engine.refresh_servers(&proxy, mirror.as_deref()).await.map(|v| HelperReply::success(&cmd, id, &v))
                }
                "syncDat" => {
                    engine.sync_dat(&proxy, mirror.as_deref()).await.map(|v| HelperReply::success(&cmd, id, &v))
                }
                _ => engine
                    .probe(targets.unwrap_or_default(), &proxy, timeout)
                    .await
                    .map(|v| HelperReply::success(&cmd, id, &v)),
            };
            reply(&client, out.unwrap_or_else(|e| HelperReply::failure(&cmd, id, e)));
        });
    }

    fn broadcast(&self, event: &HelperEvent) {
        let Some(line) = encode(event) else { return };
        let clients: Vec<_> = lock(&self.clients).clone();
        for c in clients {
            c.send(line.clone());
        }
    }

    fn handle(&self, r: HelperRequest, client: &Arc<Client>) {
        match r.cmd.as_str() {
            "connect" => {
                if let Some(problem) = validate(&r) {
                    let mut e = self.session.snapshot();
                    e.log = None;
                    e.error = Some(format!("Rejected connect request: {problem}"));
                    if let Some(line) = encode(&e) {
                        client.send(line);
                    }
                    return;
                }
                let config = match r.config {
                    Some(c) => c,
                    None => legacy_connect_config(
                        r.host.as_deref().unwrap_or_default(),
                        r.port,
                        r.ports,
                        r.proxy.unwrap_or_default(),
                        r.auto_reconnect.unwrap_or(true),
                        r.block_ipv6.unwrap_or(true),
                        r.routing,
                        r.tunnel_mode.unwrap_or(TunnelMode::FullTunnel),
                        r.socks_port.unwrap_or(DEFAULT_SOCKS_PORT),
                    ),
                };
                self.session.connect(config);
            }
            "disconnect" => self.session.disconnect(),
            "listServers" | "refreshServers" | "syncDat" | "probe" | "validateAccount" => {
                let cmd = r.cmd.clone();
                self.handle_v9(&cmd, r, client);
            }
            _ => {
                if let Some(line) = encode(&self.session.snapshot()) {
                    client.send(line);
                }
            }
        }
    }
}

fn encode(e: &HelperEvent) -> Option<Vec<u8>> {
    let mut d = serde_json::to_vec(e).ok()?;
    d.push(b'\n');
    Some(d)
}

/// The connection-handling half of the server, independent of how streams arrive.
pub struct IpcCore {
    inner: Arc<Inner>,
}

impl IpcCore {
    /// Wires the session's events to the clients.
    pub fn new(session: Arc<dyn SessionControlling>) -> IpcCore {
        let inner =
            Arc::new(Inner { session: session.clone(), clients: Mutex::new(Vec::new()), engine: Mutex::new(None) });
        let weak = Arc::downgrade(&inner);
        let emit: EmitFn = Arc::new(move |e| {
            if let Some(inner) = weak.upgrade() {
                inner.broadcast(&e);
            }
        });
        session.set_emit(Some(emit));
        IpcCore { inner }
    }

    /// Enables the IPC v9 commands that need the network (`listServers`, `refreshServers`, `syncDat`, `probe`).
    pub fn set_engine(&self, engine: Arc<Engine>) {
        *lock(&self.inner.engine) = Some(engine);
    }

    /// Serves one already-authenticated connection. Must run inside a Tokio runtime.
    pub fn attach<S>(&self, stream: S)
    where
        S: AsyncRead + AsyncWrite + Send + 'static,
    {
        let client = Client::new();
        lock(&self.inner.clients).push(client.clone());
        let (rd, wr) = tokio::io::split(stream);
        tokio::spawn(write_loop(wr, client.clone()));
        tokio::spawn(serve(rd, client, self.inner.clone()));
    }

    /// Drops every client.
    pub fn close_clients(&self) {
        let clients = std::mem::take(&mut *lock(&self.inner.clients));
        for c in clients {
            c.close();
        }
    }

    pub fn client_count(&self) -> usize {
        lock(&self.inner.clients).len()
    }
}

impl Drop for IpcCore {
    fn drop(&mut self) {
        self.close_clients();
        self.inner.session.set_emit(None);
    }
}

#[cfg(unix)]
pub struct IpcServer {
    path: PathBuf,
    allowed_uid: Option<u32>,
    auth: Arc<dyn PeerAuth>,
    core: Arc<IpcCore>,
    accept: Mutex<Option<JoinHandle<()>>>,
}

#[cfg(unix)]
impl IpcServer {
    /// Wires the session's events to the clients. `allowed_uid` only decides the socket's mode (0600 and owned by
    /// that user, or 0666 and left to `auth`).
    pub fn new(
        path: impl Into<PathBuf>,
        allowed_uid: Option<u32>,
        auth: Arc<dyn PeerAuth>,
        session: Arc<dyn SessionControlling>,
    ) -> IpcServer {
        IpcServer {
            path: path.into(),
            allowed_uid,
            auth,
            core: Arc::new(IpcCore::new(session)),
            accept: Mutex::new(None),
        }
    }

    pub fn set_engine(&self, engine: Arc<Engine>) {
        self.core.set_engine(engine);
    }

    /// Binds the socket and starts accepting. Must run inside a Tokio runtime.
    pub fn start(&self) -> io::Result<()> {
        let _ = std::fs::remove_file(&self.path);
        let listener = UnixListener::bind(&self.path)
            .map_err(|e| io::Error::new(e.kind(), format!("bind {}: {e}", self.path.display())))?;
        // Clients are authenticated by uid in accept, so with no configured user the socket is connectable by anyone
        // and `PeerAuth` decides (the console user is not known at install time).
        let mode = if self.allowed_uid.is_none() { 0o666 } else { 0o600 };
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(mode))?;
        }
        if let Some(uid) = self.allowed_uid {
            std::os::unix::fs::chown(&self.path, Some(uid), None)?;
        }
        *lock(&self.accept) = Some(tokio::spawn(accept_loop(listener, self.auth.clone(), self.core.clone())));
        Ok(())
    }

    /// Stops listening and drops every client.
    pub fn stop(&self) {
        if let Some(t) = lock(&self.accept).take() {
            t.abort();
        }
        self.core.close_clients();
        let _ = std::fs::remove_file(&self.path);
    }

    pub fn client_count(&self) -> usize {
        self.core.client_count()
    }
}

#[cfg(unix)]
impl Drop for IpcServer {
    fn drop(&mut self) {
        self.stop();
    }
}

#[cfg(unix)]
async fn accept_loop(listener: UnixListener, auth: Arc<dyn PeerAuth>, core: Arc<IpcCore>) {
    loop {
        let stream = match listener.accept().await {
            Ok((s, _)) => s,
            Err(e) => {
                if !matches!(e.kind(), io::ErrorKind::Interrupted | io::ErrorKind::ConnectionAborted) {
                    tokio::time::sleep(Duration::from_millis(50)).await; // e.g. EMFILE: don't spin
                }
                continue;
            }
        };
        let allowed = stream.peer_cred().is_ok_and(|c| auth.is_allowed(&Peer { uid: c.uid() }));
        if !allowed {
            continue; // dropping the stream closes it without a byte sent
        }
        core.attach(stream);
    }
}

/// Drains the client's outbox; a write that makes no progress for `STALL_TIMEOUT` closes the client.
async fn write_loop<W: AsyncWrite + Unpin>(mut wr: W, client: Arc<Client>) {
    loop {
        let Some(line) = client.next() else {
            tokio::select! {
                _ = client.wake.notified() => continue,
                _ = client.wait_closed() => break,
            }
        };
        match tokio::time::timeout(STALL_TIMEOUT, wr.write_all(&line)).await {
            Ok(Ok(())) => {}
            _ => {
                client.close(); // stalled or broken: drop this client only
                break;
            }
        }
    }
    let _ = wr.shutdown().await;
}

async fn serve<R: AsyncRead + Unpin>(mut rd: R, client: Arc<Client>, inner: Arc<Inner>) {
    if let Some(line) = encode(&inner.session.snapshot()) {
        client.send(line);
    }
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 4096];
    'read: while !client.is_closed() {
        let n = tokio::select! {
            r = rd.read(&mut chunk) => match r {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            },
            _ = client.wait_closed() => break,
        };
        buf.extend_from_slice(&chunk[..n]);
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            if line.len() > MAX_LINE_BYTES {
                break 'read;
            }
            if let Ok(req) = serde_json::from_slice::<HelperRequest>(&line[..nl]) {
                inner.handle(req, &client);
            }
        }
        if buf.len() > MAX_LINE_BYTES {
            break; // runaway line: drop the client
        }
    }
    lock(&inner.clients).retain(|c| !Arc::ptr_eq(c, &client));
    client.close();
}

#[cfg(all(test, unix))]
mod tests;
