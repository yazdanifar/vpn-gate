//! The TCP connections of one SoftEther session (Protocol.c ConnectionPool). Each socket is owned by a task that decodes
//! the frames it receives and writes the batches the pool hands it; outgoing batches go to the least-loaded socket.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, Weak};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tokio::time::{sleep_until, Instant};
use vpngate_core::data_phase::{DataPhaseDecoder, DataPhaseItem};

use crate::stream::{ByteStream, StreamError};

/// Which way a half-connection socket may carry application data (Connection.c:109-113's IsSendDirection /
/// IsRecvDirection, from the client's point of view). A normal (non-half-connection) session only ever uses `Both`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketDirection {
    Both,
    ServerToClient,
    ClientToServer,
}

impl SocketDirection {
    pub fn can_send(self) -> bool {
        matches!(self, SocketDirection::Both | SocketDirection::ClientToServer)
    }

    pub fn can_receive(self) -> bool {
        matches!(self, SocketDirection::Both | SocketDirection::ServerToClient)
    }

    /// The server's `direction` field on an additional_connect reply (0 both, 1 server→client, 2 client→server,
    /// Protocol.c:5257); anything else (including absent, the normal case) is `Both`.
    pub fn from_wire(value: Option<u32>) -> Self {
        match value {
            Some(1) => SocketDirection::ServerToClient,
            Some(2) => SocketDirection::ClientToServer,
            _ => SocketDirection::Both,
        }
    }
}

pub type FrameFn = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
pub type CloseFn = Arc<dyn Fn(Option<StreamError>) + Send + Sync>;
/// `(bytes_in, bytes_out)`; one of them is 0.
pub type ByteCountFn = Arc<dyn Fn(usize, usize) + Send + Sync>;

#[derive(Clone)]
pub struct PoolCallbacks {
    pub on_frame: FrameFn,
    /// Called once, when the last socket is gone or the pool is closed.
    pub on_close: CloseFn,
    pub on_byte_count: ByteCountFn,
}

enum Cmd {
    Send(Vec<u8>, Option<oneshot::Sender<Result<(), StreamError>>>),
    Close,
}

struct Entry {
    tx: mpsc::UnboundedSender<Cmd>,
    direction: SocketDirection,
    bytes_out: u64,
}

#[derive(Default)]
struct State {
    sockets: HashMap<u64, Entry>,
    next_id: u64,
    closed: bool,
}

struct Inner {
    state: Mutex<State>,
    callbacks: PoolCallbacks,
}

#[derive(Clone)]
pub struct ConnectionPool {
    inner: Arc<Inner>,
}

impl ConnectionPool {
    pub fn new(callbacks: PoolCallbacks) -> Self {
        ConnectionPool { inner: Arc::new(Inner { state: Mutex::new(State::default()), callbacks }) }
    }

    pub fn active_count(&self) -> usize {
        self.inner.lock().sockets.len()
    }

    /// Adds an established socket to the pool and starts reading frames from it. `direction` is `Both` for a normal
    /// session; a client-to-server-only socket is never expected to receive application data, so the idle-read
    /// watchdog is skipped for it (silence there is correct, not a stall).
    pub fn add(
        &self,
        mut stream: Box<dyn ByteStream>,
        use_compress: bool,
        timeout_ms: u64,
        direction: SocketDirection,
    ) {
        let mut state = self.inner.lock();
        if state.closed {
            drop(state);
            stream.cancel();
            return;
        }
        let id = state.next_id;
        state.next_id += 1;
        let (tx, rx) = mpsc::unbounded_channel();
        state.sockets.insert(id, Entry { tx, direction, bytes_out: 0 });
        drop(state);

        let pool = Arc::downgrade(&self.inner);
        tokio::spawn(run_socket(pool, id, stream, use_compress, timeout_ms, direction, rx));
    }

    /// Sends the data on the least-loaded socket eligible to send (every socket, in a normal session).
    pub async fn send(&self, data: Vec<u8>, byte_count: usize) -> Result<(), StreamError> {
        let tx = {
            let mut state = self.inner.lock();
            if state.closed {
                return Err(StreamError::Closed);
            }
            // Least loaded by bytes_out, among the sockets this direction allows us to send on.
            let chosen = state
                .sockets
                .iter()
                .filter(|(_, e)| e.direction.can_send())
                .min_by_key(|(id, e)| (e.bytes_out, **id))
                .map(|(id, _)| *id);
            let Some(id) = chosen else { return Err(StreamError::Closed) };
            let entry = state.sockets.get_mut(&id).expect("chosen socket");
            entry.bytes_out += byte_count as u64;
            entry.tx.clone()
        };
        let (reply_tx, reply_rx) = oneshot::channel();
        tx.send(Cmd::Send(data, Some(reply_tx))).map_err(|_| StreamError::Closed)?;
        reply_rx.await.map_err(|_| StreamError::Closed)??;
        (self.inner.callbacks.on_byte_count)(0, byte_count);
        Ok(())
    }

    /// Queues a keep-alive packet on every socket eligible to send (receive-only sockets never send anything).
    pub fn broadcast_keep_alive(&self, data: &[u8]) {
        let state = self.inner.lock();
        if state.closed {
            return;
        }
        for e in state.sockets.values().filter(|e| e.direction.can_send()) {
            let _ = e.tx.send(Cmd::Send(data.to_vec(), None));
        }
    }

    pub fn close(&self, error: Option<StreamError>) {
        self.inner.close(error);
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("pool state")
    }

    /// Drops a socket; the session ends when the last one goes.
    fn remove(&self, id: u64, error: Option<StreamError>) {
        let last = {
            let mut state = self.lock();
            state.sockets.remove(&id).is_some() && state.sockets.is_empty() && !state.closed
        };
        if last {
            self.close(error);
        }
    }

    fn close(&self, error: Option<StreamError>) {
        let entries = {
            let mut state = self.lock();
            if state.closed {
                return;
            }
            state.closed = true;
            std::mem::take(&mut state.sockets)
        };
        for e in entries.values() {
            let _ = e.tx.send(Cmd::Close);
        }
        (self.callbacks.on_close)(error);
    }
}

async fn run_socket(
    pool: Weak<Inner>,
    id: u64,
    mut stream: Box<dyn ByteStream>,
    use_compress: bool,
    timeout_ms: u64,
    direction: SocketDirection,
    mut rx: mpsc::UnboundedReceiver<Cmd>,
) {
    let mut decoder = DataPhaseDecoder::new(use_compress);
    // Bytes the server sent right behind the welcome / additional_connect reply.
    let mut chunk = stream.buffer().take_all();
    let timeout = Duration::from_millis(timeout_ms);
    let mut last_rx = Instant::now();

    let error = loop {
        match decoder.feed(&chunk) {
            Ok(items) => {
                let Some(p) = pool.upgrade() else { break None };
                for item in items {
                    if let DataPhaseItem::Frame(f) = item {
                        (p.callbacks.on_byte_count)(f.len(), 0);
                        (p.callbacks.on_frame)(f);
                    }
                }
            }
            Err(e) => break Some(StreamError::Protocol(e.to_string())),
        }
        tokio::select! {
            r = stream.read_chunk() => match r {
                Ok(c) => {
                    chunk = c;
                    last_rx = Instant::now();
                }
                Err(e) => break Some(e),
            },
            cmd = rx.recv() => match cmd {
                Some(Cmd::Send(data, reply)) => {
                    let result = stream.send(&data).await;
                    let failed = result.clone().err();
                    if let Some(reply) = reply {
                        let _ = reply.send(result);
                    }
                    if let Some(e) = failed {
                        break Some(e);
                    }
                    // Nothing new was read; the decoder has nothing more to do on the next pass.
                    chunk = Vec::new();
                }
                Some(Cmd::Close) | None => {
                    stream.cancel();
                    return;
                }
            },
            // A send-only socket never receiving is expected, not a timeout.
            _ = sleep_until(last_rx + timeout), if direction.can_receive() => {
                break Some(StreamError::Protocol(format!("Read idle timeout ({timeout_ms} ms)")));
            }
        }
    };
    stream.cancel();
    if let Some(p) = pool.upgrade() {
        p.remove(id, error);
    }
}

#[cfg(test)]
mod tests;
