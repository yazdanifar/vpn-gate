//! Scripted in-memory SoftEther server speaking the real wire format for the handshake (HTTP + PACK). Everything the
//! client sends after the welcome is swallowed; the data phase is added by the units that need it.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::http_head::HttpHead;
use vpngate_core::ipc::ProxySettings;
use vpngate_core::pack::Pack;

use crate::stream::{ByteStream, StreamError, StreamFactory};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub path: String,
    pub content_type: String,
    pub body: Vec<u8>,
}

/// Behaviour knobs.
pub struct FakeConfig {
    pub reject_watermark: bool,
    pub omit_random: bool,
    pub login_error: u32,
    pub redirect: bool,
    pub redirect_host: String,
    pub redirect_port: u32,
    /// If set, the redirect offers this whole port list instead of `redirect_port`.
    pub redirect_ports: Option<Vec<u32>>,
    pub redirect_ticket: Vec<u8>,
    /// If set, the redirect `Ip` is sent as SoftEther's pack integer instead of a string.
    pub redirect_ip_int: Option<u32>,
    /// Replaces the whole (non-error, non-redirect) welcome pack.
    pub welcome_override: Option<Pack>,
    pub use_compress: bool,
    pub max_connections: u32,
    pub session_key: Vec<u8>,
    pub hello_status: u32,
    pub welcome_timeout_ms: u32,
    pub fail_start: Option<StreamError>,
    /// What every stream reports as the peer it really connected to.
    pub remote_ipv4: Option<String>,
    /// Bytes sent right after the welcome (same TCP segment).
    pub trailing_after_welcome: Vec<u8>,
    /// If set, server→client bytes are delivered in chunks of this size.
    pub chunk_size: Option<usize>,
}

impl Default for FakeConfig {
    fn default() -> Self {
        FakeConfig {
            reject_watermark: false,
            omit_random: false,
            login_error: 0,
            redirect: false,
            redirect_host: "5.6.7.8".into(),
            redirect_port: 443,
            redirect_ports: None,
            redirect_ticket: vec![0x42; 20],
            redirect_ip_int: None,
            welcome_override: None,
            use_compress: false,
            max_connections: 1,
            session_key: vec![0x11; 20],
            hello_status: 200,
            welcome_timeout_ms: 20000,
            fail_start: None,
            remote_ipv4: None,
            trailing_after_welcome: Vec::new(),
            chunk_size: None,
        }
    }
}

#[derive(Default)]
struct State {
    config: FakeConfig,
    requests: Vec<Request>,
    logins: Vec<Pack>,
    streams: Vec<Arc<Mutex<StreamState>>>,
}

#[derive(Default)]
struct StreamState {
    cancelled: bool,
    incoming: VecDeque<Vec<u8>>,
}

#[derive(Clone, Default)]
pub struct FakeSoftEtherServer {
    state: Arc<Mutex<State>>,
}

impl FakeSoftEtherServer {
    pub fn new() -> Self {
        Self::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().expect("fake server state")
    }

    /// Changes the knobs, e.g. `server.configure(|c| c.reject_watermark = true)`.
    pub fn configure(&self, f: impl FnOnce(&mut FakeConfig)) {
        f(&mut self.lock().config);
    }

    pub fn requests(&self) -> Vec<Request> {
        self.lock().requests.clone()
    }

    pub fn logins(&self) -> Vec<Pack> {
        self.lock().logins.clone()
    }

    pub fn streams_created(&self) -> usize {
        self.lock().streams.len()
    }

    /// Whether stream `i` (creation order) was cancelled by the client.
    pub fn stream_cancelled(&self, i: usize) -> bool {
        self.lock().streams[i].lock().expect("stream state").cancelled
    }

    pub fn factory(&self) -> StreamFactory {
        let server = self.clone();
        Arc::new(move |_host: &str, _port: u16, _proxy: &ProxySettings| {
            let st = Arc::new(Mutex::new(StreamState::default()));
            server.lock().streams.push(st.clone());
            Box::new(FakeStream {
                server: server.clone(),
                st,
                buffer: ByteBuffer::new(),
                rx: Vec::new(),
                data_mode: false,
            }) as Box<dyn ByteStream>
        })
    }

    pub fn http(status: u32, body: &[u8]) -> Vec<u8> {
        let mut out = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn hello_pack(c: &FakeConfig) -> Pack {
        let mut p = Pack::new();
        p.add_str("hello", "SoftEther VPN Server");
        p.add_int("version", 432);
        p.add_int("build", 9729);
        if !c.omit_random {
            p.add_data("random", &(0..20).collect::<Vec<u8>>());
        }
        p
    }

    fn welcome_pack(c: &FakeConfig) -> Pack {
        let mut p = Pack::new();
        if c.login_error != 0 {
            p.add_int("error", c.login_error);
            return p;
        }
        if c.redirect {
            p.add_int("Redirect", 1);
            match c.redirect_ip_int {
                Some(ip) => p.add_int("Ip", ip),
                None => p.add_str("Ip", &c.redirect_host),
            }
            match &c.redirect_ports {
                Some(ports) => p.add_ints("Port", ports),
                None => p.add_int("Port", c.redirect_port),
            }
            p.add_data("Ticket", &c.redirect_ticket);
            return p;
        }
        if let Some(o) = &c.welcome_override {
            return o.clone();
        }
        p.add_str("session_name", "SID-VPN-TEST-1");
        p.add_str("connection_name", "CID-1");
        p.add_int("timeout", c.welcome_timeout_ms);
        p.add_data("session_key", &c.session_key);
        p.add_int("max_connection", c.max_connections);
        p.add_bool("use_compress", c.use_compress);
        p
    }
}

pub struct FakeStream {
    server: FakeSoftEtherServer,
    st: Arc<Mutex<StreamState>>,
    buffer: ByteBuffer,
    rx: Vec<u8>,
    data_mode: bool,
}

impl FakeStream {
    fn deliver(&self, bytes: Vec<u8>) {
        let chunk = self.server.lock().config.chunk_size;
        let mut st = self.st.lock().expect("stream state");
        match chunk {
            Some(n) if n > 0 => bytes.chunks(n).for_each(|c| st.incoming.push_back(c.to_vec())),
            _ => st.incoming.push_back(bytes),
        }
    }

    fn respond(&mut self, path: &str, content_type: &str, body: Vec<u8>) {
        let mut state = self.server.lock();
        state.requests.push(Request { path: path.into(), content_type: content_type.into(), body: body.clone() });
        let reply = match path {
            "/vpnsvc/connect.cgi" => {
                let c = &state.config;
                let plain = body == b"VPNCONNECT";
                if c.hello_status != 200 || (c.reject_watermark && !plain) {
                    let status = if c.hello_status == 200 { 403 } else { c.hello_status };
                    format!("HTTP/1.1 {status} Forbidden\r\nContent-Length: 0\r\n\r\n").into_bytes()
                } else {
                    FakeSoftEtherServer::http(200, &FakeSoftEtherServer::hello_pack(c).serialize())
                }
            }
            "/vpnsvc/vpn.cgi" => match Pack::parse(&body) {
                Err(_) => error_reply(4),
                Ok(p) => {
                    state.logins.push(p.clone());
                    // Real servers reject packs with duplicate (case-insensitive) element names.
                    let mut names: Vec<String> = p.elements().iter().map(|e| e.name.to_lowercase()).collect();
                    let total = names.len();
                    names.sort();
                    names.dedup();
                    if names.len() != total {
                        error_reply(3)
                    } else {
                        let c = &state.config;
                        let mut r = FakeSoftEtherServer::http(200, &FakeSoftEtherServer::welcome_pack(c).serialize());
                        r.extend_from_slice(&c.trailing_after_welcome);
                        self.data_mode = c.login_error == 0 && !c.redirect;
                        r
                    }
                }
            },
            _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".to_vec(),
        };
        drop(state);
        self.deliver(reply);
    }
}

fn error_reply(code: u32) -> Vec<u8> {
    let mut e = Pack::new();
    e.add_int("error", code);
    FakeSoftEtherServer::http(200, &e.serialize())
}

fn find_header_end(rx: &[u8]) -> Option<usize> {
    rx.windows(4).position(|w| w == b"\r\n\r\n")
}

#[async_trait]
impl ByteStream for FakeStream {
    fn buffer(&mut self) -> &mut ByteBuffer {
        &mut self.buffer
    }

    async fn start(&mut self) -> Result<(), StreamError> {
        match &self.server.lock().config.fail_start {
            Some(e) => Err(e.clone()),
            None => Ok(()),
        }
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
        if self.st.lock().expect("stream state").cancelled {
            return Err(StreamError::Closed);
        }
        if self.data_mode {
            return Ok(()); // the data phase is not interpreted
        }
        self.rx.extend_from_slice(data);
        while let Some(end) = find_header_end(&self.rx) {
            let head = HttpHead::parse(&self.rx[..end]);
            let len = head.headers.get("content-length").and_then(|v| v.parse::<usize>().ok()).unwrap_or(0);
            if self.rx.len() < end + 4 + len {
                break;
            }
            let body = self.rx[end + 4..end + 4 + len].to_vec();
            self.rx.drain(..end + 4 + len);
            let path = head.status.split(' ').nth(1).unwrap_or("").to_string();
            let content_type = head.headers.get("content-type").cloned().unwrap_or_default();
            self.respond(&path, &content_type, body);
        }
        Ok(())
    }

    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        let mut st = self.st.lock().expect("stream state");
        if st.cancelled {
            return Err(StreamError::Closed);
        }
        // Every reply is queued synchronously by `send`, so an empty queue means the server has nothing more to say.
        st.incoming.pop_front().ok_or(StreamError::Closed)
    }

    fn cancel(&mut self) {
        self.st.lock().expect("stream state").cancelled = true;
    }

    fn remote_ipv4(&self) -> Option<String> {
        self.server.lock().config.remote_ipv4.clone()
    }
}
