//! Scripted in-memory SoftEther server speaking the real wire format: the handshake (HTTP + PACK), additional
//! connections and the data phase (frames and keep-alives the client sends are decoded and recorded).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use async_trait::async_trait;
use tokio::sync::Notify;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::data_phase::{DataPhaseDecoder, DataPhaseItem};
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
    /// The next N additional_connect requests are answered with an error.
    pub fail_additional_connects: u32,
    /// `direction` values (0 both, 1 server→client, 2 client→server) handed out to successive additional_connect
    /// requests, in order; once empty, replies carry no `direction` (plain "both").
    pub additional_connect_directions: Vec<u32>,
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
            fail_additional_connects: 0,
            additional_connect_directions: Vec::new(),
        }
    }
}

#[derive(Default)]
struct State {
    config: FakeConfig,
    requests: Vec<Request>,
    logins: Vec<Pack>,
    additional_connects: Vec<Pack>,
    frames: Vec<Vec<u8>>,
    keep_alives: usize,
    streams: Vec<Arc<Mutex<StreamState>>>,
}

#[derive(Default)]
struct StreamState {
    cancelled: bool,
    incoming: VecDeque<Vec<u8>>,
    /// Once set, the next `read_chunk` fails with it (the server dropped the connection).
    failure: Option<StreamError>,
    /// After the welcome / additional_connect reply: reads wait for data instead of failing on an empty queue.
    data_mode: bool,
    assigned_direction: Option<u32>,
    bytes_from_client: usize,
    notify: Arc<Notify>,
}

/// Test-side view of one stream the client created.
#[derive(Clone)]
pub struct StreamHandle {
    server: FakeSoftEtherServer,
    st: Arc<Mutex<StreamState>>,
}

impl StreamHandle {
    /// Server→client bytes, as if the server had sent them.
    pub fn deliver(&self, bytes: &[u8]) {
        deliver_to(&self.server, &self.st, bytes.to_vec());
    }

    /// The connection breaks: the client's next read fails with `e`.
    pub fn fail_from_server(&self, e: StreamError) {
        let mut st = self.st.lock().expect("stream state");
        st.failure = Some(e);
        st.notify.notify_one();
    }

    pub fn is_cancelled(&self) -> bool {
        self.st.lock().expect("stream state").cancelled
    }

    /// The `direction` the additional_connect reply assigned (`None` for the primary and for plain replies).
    pub fn assigned_direction(&self) -> Option<u32> {
        self.st.lock().expect("stream state").assigned_direction
    }

    pub fn bytes_received_from_client(&self) -> usize {
        self.st.lock().expect("stream state").bytes_from_client
    }
}

fn deliver_to(server: &FakeSoftEtherServer, st: &Arc<Mutex<StreamState>>, bytes: Vec<u8>) {
    let chunk = server.lock().config.chunk_size;
    let mut st = st.lock().expect("stream state");
    match chunk {
        Some(n) if n > 0 => bytes.chunks(n).for_each(|c| st.incoming.push_back(c.to_vec())),
        _ => st.incoming.push_back(bytes),
    }
    st.notify.notify_one();
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

    /// The `additional_connect` packs received, in order.
    pub fn additional_connects(&self) -> Vec<Pack> {
        self.lock().additional_connects.clone()
    }

    /// Every Ethernet frame the client sent in the data phase.
    pub fn frames_received(&self) -> Vec<Vec<u8>> {
        self.lock().frames.clone()
    }

    pub fn keep_alives_received(&self) -> usize {
        self.lock().keep_alives
    }

    /// Stream `i` in creation order (0 is the primary connection, 1+ the additional ones).
    pub fn stream(&self, i: usize) -> StreamHandle {
        StreamHandle { server: self.clone(), st: self.lock().streams[i].clone() }
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
                decoder: None,
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
    /// Set in the data phase; decodes what the client sends.
    decoder: Option<DataPhaseDecoder>,
}

impl FakeStream {
    fn deliver(&self, bytes: Vec<u8>) {
        deliver_to(&self.server, &self.st, bytes);
    }

    fn enter_data_mode(&mut self, use_compress: bool) {
        self.decoder = Some(DataPhaseDecoder::new(use_compress));
        self.st.lock().expect("stream state").data_mode = true;
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
                    // Real servers reject packs with duplicate (case-insensitive) element names.
                    let mut names: Vec<String> = p.elements().iter().map(|e| e.name.to_lowercase()).collect();
                    let total = names.len();
                    names.sort();
                    names.dedup();
                    if names.len() != total {
                        error_reply(3)
                    } else if p.str("method") == Some("additional_connect") {
                        state.additional_connects.push(p);
                        if state.config.fail_additional_connects > 0 {
                            state.config.fail_additional_connects -= 1;
                            error_reply(5)
                        } else {
                            let mut reply = Pack::new();
                            reply.add_int("error", 0);
                            if !state.config.additional_connect_directions.is_empty() {
                                let d = state.config.additional_connect_directions.remove(0);
                                reply.add_int("direction", d);
                                self.st.lock().expect("stream state").assigned_direction = Some(d);
                            }
                            let use_compress = state.config.use_compress;
                            drop(state);
                            self.enter_data_mode(use_compress);
                            self.deliver(FakeSoftEtherServer::http(200, &reply.serialize()));
                            return;
                        }
                    } else {
                        state.logins.push(p);
                        let c = &state.config;
                        let mut r = FakeSoftEtherServer::http(200, &FakeSoftEtherServer::welcome_pack(c).serialize());
                        r.extend_from_slice(&c.trailing_after_welcome);
                        if c.login_error == 0 && !c.redirect {
                            let use_compress = c.use_compress;
                            drop(state);
                            self.enter_data_mode(use_compress);
                            self.deliver(r);
                            return;
                        }
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
        if let Some(decoder) = &mut self.decoder {
            let mut st = self.st.lock().expect("stream state");
            st.bytes_from_client += data.len();
            drop(st);
            let items = decoder.feed(data).map_err(|e| StreamError::Protocol(e.to_string()))?;
            let mut state = self.server.lock();
            for item in items {
                match item {
                    DataPhaseItem::Frame(f) => state.frames.push(f),
                    DataPhaseItem::KeepAlive => state.keep_alives += 1,
                }
            }
            return Ok(());
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
        loop {
            let notify = {
                let mut st = self.st.lock().expect("stream state");
                if st.cancelled {
                    return Err(StreamError::Closed);
                }
                if let Some(e) = st.failure.take() {
                    return Err(e);
                }
                if let Some(chunk) = st.incoming.pop_front() {
                    return Ok(chunk);
                }
                // In the handshake every reply is queued synchronously by `send`, so an empty queue means the server
                // has nothing more to say; in the data phase the client waits for the next delivery.
                if !st.data_mode {
                    return Err(StreamError::Closed);
                }
                st.notify.clone()
            };
            notify.notified().await;
        }
    }

    fn cancel(&mut self) {
        let mut st = self.st.lock().expect("stream state");
        st.cancelled = true;
        st.notify.notify_one();
    }

    fn remote_ipv4(&self) -> Option<String> {
        self.server.lock().config.remote_ipv4.clone()
    }
}
