//! A scriptable daemon on a Unix socket, for testing IPC clients: it records every request, answers through a closure
//! and can push events whenever a test wants.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use vpngate_core::ipc::{ConnectionState, HelperEvent, HelperReply, HelperRequest, HELPER_VERSION, IPC_VERSION};

/// One line the fake daemon sends.
pub enum Line {
    Event(HelperEvent),
    Reply(HelperReply),
    /// Sent as is (plus the newline), for malformed-input tests.
    Raw(String),
}

type Responder = Box<dyn Fn(&HelperRequest) -> Vec<Line> + Send>;

struct State {
    requests: Vec<HelperRequest>,
    clients: Vec<mpsc::UnboundedSender<Vec<u8>>>,
    responder: Responder,
    snapshot: HelperEvent,
    /// The per-connection tasks, aborted by `stop` so clients really see the connection end.
    serving: Vec<JoinHandle<()>>,
}

fn lock(s: &Mutex<State>) -> MutexGuard<'_, State> {
    s.lock().unwrap_or_else(|e| e.into_inner())
}

fn encode(l: &Line) -> Vec<u8> {
    let mut d = match l {
        Line::Event(e) => serde_json::to_vec(e).unwrap_or_default(),
        Line::Reply(r) => serde_json::to_vec(r).unwrap_or_default(),
        Line::Raw(s) => s.clone().into_bytes(),
    };
    d.push(b'\n');
    d
}

pub struct FakeDaemon {
    path: PathBuf,
    state: Arc<Mutex<State>>,
    accept: Option<JoinHandle<()>>,
}

impl FakeDaemon {
    /// Binds `path` and starts accepting. Must run inside a Tokio runtime. A `status` request is answered with the
    /// snapshot; everything else with nothing, until `on_request` says otherwise.
    pub fn start(path: impl Into<PathBuf>) -> io::Result<FakeDaemon> {
        let path = path.into();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path)?;
        let mut snapshot = HelperEvent::new(ConnectionState::Disconnected);
        snapshot.helper_version = Some(HELPER_VERSION);
        snapshot.ipc_version = Some(IPC_VERSION);
        let state = Arc::new(Mutex::new(State {
            requests: Vec::new(),
            clients: Vec::new(),
            responder: Box::new(|_| Vec::new()),
            snapshot,
            serving: Vec::new(),
        }));
        let accept = tokio::spawn(accept_loop(listener, state.clone()));
        Ok(FakeDaemon { path, state, accept: Some(accept) })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Decides what each request is answered with (besides the automatic `status` snapshot).
    pub fn on_request(&self, f: impl Fn(&HelperRequest) -> Vec<Line> + Send + 'static) {
        lock(&self.state).responder = Box::new(f);
    }

    pub fn set_snapshot(&self, e: HelperEvent) {
        lock(&self.state).snapshot = e;
    }

    /// Every request received so far, in order.
    pub fn requests(&self) -> Vec<HelperRequest> {
        lock(&self.state).requests.clone()
    }

    pub fn client_count(&self) -> usize {
        let mut s = lock(&self.state);
        s.clients.retain(|c| !c.is_closed());
        s.clients.len()
    }

    pub fn push(&self, line: &Line) {
        let bytes = encode(line);
        for c in &lock(&self.state).clients {
            let _ = c.send(bytes.clone());
        }
    }

    /// Stops listening and drops every client, like a daemon that exits.
    pub fn stop(&mut self) {
        if let Some(t) = self.accept.take() {
            t.abort();
        }
        let mut s = lock(&self.state);
        s.clients.clear();
        for t in s.serving.drain(..) {
            t.abort();
        }
        drop(s);
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn accept_loop(listener: UnixListener, state: Arc<Mutex<State>>) {
    while let Ok((stream, _)) = listener.accept().await {
        let task = tokio::spawn(serve(stream, state.clone()));
        lock(&state).serving.push(task);
    }
}

async fn serve(stream: UnixStream, state: Arc<Mutex<State>>) {
    let (mut rd, mut wr) = stream.into_split();
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let snapshot = encode(&Line::Event(lock(&state).snapshot.clone()));
    let _ = tx.send(snapshot);
    lock(&state).clients.push(tx.clone());
    tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if wr.write_all(&bytes).await.is_err() {
                break;
            }
        }
    });
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        match rd.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(n) => buf.extend_from_slice(&chunk[..n]),
        }
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line: Vec<u8> = buf.drain(..=nl).collect();
            let Ok(req) = serde_json::from_slice::<HelperRequest>(&line[..nl]) else { continue };
            let lines = {
                let mut s = lock(&state);
                s.requests.push(req.clone());
                let mut out = (s.responder)(&req);
                if req.cmd == "status" && out.is_empty() {
                    out.push(Line::Event(s.snapshot.clone()));
                }
                out
            };
            for l in &lines {
                let _ = tx.send(encode(l));
            }
        }
    }
}
