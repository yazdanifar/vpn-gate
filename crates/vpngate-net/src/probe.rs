//! Connectivity test of one relay: TLS to the SSL-VPN port plus the first step of the real SoftEther handshake.

use std::time::{Duration, Instant};

use vpngate_core::ipc::ProxySettings;
use vpngate_core::pack::Pack;
use vpngate_core::server_list::VpnServer;

use crate::stream::{ByteStream, StreamError, StreamFactory};

/// What a connectivity test of one relay found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// Chosen for the run but not started yet (only a few relays are tested at a time).
    Queued,
    Testing,
    /// A SoftEther server answered the protocol hello on `port`. `connect_ms` is TCP + TLS set-up, `hello_ms` the whole
    /// test including the server's hello, so a relay that merely accepts TCP (a firewall, a captive proxy) is not "ok".
    Ok {
        port: u16,
        connect_ms: i64,
        hello_ms: i64,
        build: Option<i64>,
    },
    Failed(String),
}

impl ProbeOutcome {
    /// Ascending order = best first: working relays by connect time, then untested/in progress, then failed.
    pub fn sort_rank(o: Option<&ProbeOutcome>) -> i64 {
        match o {
            Some(ProbeOutcome::Ok { connect_ms, .. }) => *connect_ms,
            Some(ProbeOutcome::Failed(_)) => i64::MAX,
            Some(ProbeOutcome::Queued | ProbeOutcome::Testing) | None => i64::MAX - 1,
        }
    }

    pub fn is_ok(&self) -> bool {
        matches!(self, ProbeOutcome::Ok { .. })
    }
}

/// How many of a relay's ports are tried before giving up (in the Windows client's priority order).
pub const MAX_PORTS: usize = 3;

pub fn ports(server: &VpnServer) -> Vec<u16> {
    let mut out = server.prioritized_ssl_ports();
    if out.is_empty() {
        if let Some(p) = server.connect_port().and_then(|p| u16::try_from(p).ok()) {
            out = vec![p];
        }
    }
    if out.is_empty() {
        out = vec![443];
    }
    out.truncate(MAX_PORTS);
    out
}

pub async fn run(
    host: &str,
    ports: &[u16],
    proxy: &ProxySettings,
    timeout: Duration,
    factory: &StreamFactory,
) -> ProbeOutcome {
    let mut last_error = "No port to test".to_string();
    for &port in ports {
        match attempt(host, port, proxy, timeout, factory).await {
            Ok(ok) => return ok,
            Err(message) => {
                last_error = if ports.len() > 1 { format!("{message} (port {port})") } else { message };
            }
        }
    }
    ProbeOutcome::Failed(last_error)
}

async fn attempt(
    host: &str,
    port: u16,
    proxy: &ProxySettings,
    timeout: Duration,
    factory: &StreamFactory,
) -> Result<ProbeOutcome, String> {
    let mut stream = factory(host, port, proxy);
    // Dropping the handshake future on timeout abandons whatever it was waiting for.
    let result = match tokio::time::timeout(timeout, handshake(stream.as_mut(), host, port)).await {
        Ok(r) => r,
        Err(_) => Err(format!("No answer in {} s", timeout.as_secs())),
    };
    stream.cancel();
    result
}

fn ms_since(t: Instant) -> i64 {
    i64::try_from(t.elapsed().as_millis()).unwrap_or(i64::MAX).max(1)
}

async fn handshake(s: &mut dyn ByteStream, host: &str, port: u16) -> Result<ProbeOutcome, String> {
    let t0 = Instant::now();
    if let Err(e) = s.start().await {
        return Err(match e {
            StreamError::Timeout => "No answer".to_string(),
            StreamError::Io(_) => "Cannot connect".to_string(),
            other => other.to_string(),
        });
    }
    let connect_ms = ms_since(t0);
    // The plain marker is accepted by every SoftEther server, which is all that is needed to make it say hello.
    let body = b"VPNCONNECT";
    let mut req = format!("POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: {host}\r\n").into_bytes();
    req.extend_from_slice(
        format!("Content-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: {}\r\n\r\n", body.len())
            .as_bytes(),
    );
    req.extend_from_slice(body);

    let no_handshake = || "Connected, but no VPN handshake".to_string();
    s.send(&req).await.map_err(|_| no_handshake())?;
    let head = s.recv_http_head().await.map_err(|_| no_handshake())?;
    if head.status_code() != Some(200) {
        return Err(format!("Not a VPN server (HTTP {})", head.status_code().unwrap_or(0)));
    }
    let len = head
        .headers
        .get("content-length")
        .and_then(|v| v.parse::<i64>().ok())
        .filter(|l| *l > 0 && *l < 1 << 20)
        .ok_or_else(|| "Not a VPN server".to_string())? as usize;
    let bytes = s.recv(len).await.map_err(|_| no_handshake())?;
    let pack = Pack::parse(&bytes).map_err(|_| no_handshake())?;
    match pack.data("random") {
        Some(r) if r.len() == 20 => {}
        _ => return Err("Not a SoftEther server".to_string()),
    }
    Ok(ProbeOutcome::Ok { port, connect_ms, hello_ms: ms_since(t0), build: pack.int("build").map(i64::from) })
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use vpngate_core::byte_buffer::ByteBuffer;

    use super::*;

    /// Plays a canned server reply once the request has been sent; `None` stands for a closed or filtered port.
    struct Scripted {
        buffer: ByteBuffer,
        reply: Option<Vec<u8>>,
        silent: bool,
        sent: Arc<Mutex<Vec<u8>>>,
    }

    fn http(status: u16, body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status} X\r\nContent-Length: {}\r\n\r\n", body.len()).into_bytes();
        out.extend_from_slice(body);
        out
    }

    fn hello(omit_random: bool) -> Vec<u8> {
        let mut p = Pack::new();
        p.add_str("hello", "SoftEther VPN Server");
        p.add_int("build", 9729);
        if !omit_random {
            p.add_data("random", &[7u8; 20]);
        }
        p.serialize()
    }

    #[async_trait]
    impl ByteStream for Scripted {
        fn buffer(&mut self) -> &mut ByteBuffer {
            &mut self.buffer
        }
        async fn start(&mut self) -> Result<(), StreamError> {
            if self.reply.is_none() && !self.silent {
                return Err(StreamError::Io("refused".into()));
            }
            Ok(())
        }
        async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
            self.sent.lock().unwrap().extend_from_slice(data);
            Ok(())
        }
        async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
            if self.silent {
                std::future::pending::<()>().await;
            }
            self.reply.take().ok_or(StreamError::Closed)
        }
        fn cancel(&mut self) {}
    }

    fn factory(
        reply: impl Fn(u16) -> Option<Vec<u8>> + Send + Sync + 'static,
        sent: Arc<Mutex<Vec<u8>>>,
    ) -> StreamFactory {
        Arc::new(move |_, port, _| {
            Box::new(Scripted { buffer: ByteBuffer::new(), reply: reply(port), silent: false, sent: sent.clone() })
        })
    }

    async fn run_with(f: &StreamFactory, ports: &[u16]) -> ProbeOutcome {
        run("h", ports, &ProxySettings::default(), Duration::from_secs(5), f).await
    }

    #[tokio::test]
    async fn real_softether_hello_counts_as_reachable() {
        let sent = Arc::default();
        let f = factory(|_| Some(http(200, &hello(false))), Arc::clone(&sent));
        let ProbeOutcome::Ok { port, connect_ms, hello_ms, build } = run_with(&f, &[443]).await else { panic!() };
        assert_eq!((port, build), (443, Some(9729)));
        assert!(connect_ms >= 1 && hello_ms >= connect_ms);
        let req = String::from_utf8(sent.lock().unwrap().clone()).unwrap();
        assert!(
            req.starts_with("POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: h\r\n") && req.ends_with("VPNCONNECT"),
            "{req}"
        );
    }

    #[tokio::test]
    async fn plain_tcp_or_https_server_is_not_reachable_as_vpn() {
        let a = run_with(&factory(|_| Some(http(404, b"")), Arc::default()), &[443]).await;
        assert_eq!(a, ProbeOutcome::Failed("Not a VPN server (HTTP 404)".into()));
        let b = run_with(&factory(|_| Some(http(200, &hello(true))), Arc::default()), &[443]).await;
        assert_eq!(b, ProbeOutcome::Failed("Not a SoftEther server".into()));
        let c = run_with(&factory(|_| Some(http(200, b"")), Arc::default()), &[443]).await;
        assert_eq!(c, ProbeOutcome::Failed("Not a VPN server".into()));
        let d = run_with(&factory(|_| Some(http(200, b"garbage")), Arc::default()), &[443]).await;
        assert_eq!(d, ProbeOutcome::Failed("Connected, but no VPN handshake".into()));
    }

    #[tokio::test]
    async fn connection_failure_is_reported_and_next_port_is_tried() {
        let dead = run_with(&factory(|_| None, Arc::default()), &[443]).await;
        assert_eq!(dead, ProbeOutcome::Failed("Cannot connect".into()));
        let f = factory(|p| (p != 443).then(|| http(200, &hello(false))), Arc::default());
        let ProbeOutcome::Ok { port, .. } = run_with(&f, &[443, 992]).await else { panic!() };
        assert_eq!(port, 992);
    }

    #[tokio::test]
    async fn all_ports_failing_names_the_last_port() {
        let ProbeOutcome::Failed(why) = run_with(&factory(|_| None, Arc::default()), &[443, 992]).await else {
            panic!()
        };
        assert!(why.contains("992"), "{why}");
    }

    #[tokio::test]
    async fn times_out_on_a_silent_server() {
        let f: StreamFactory = Arc::new(|_, _, _| {
            Box::new(Scripted { buffer: ByteBuffer::new(), reply: None, silent: true, sent: Arc::default() })
        });
        let t0 = Instant::now();
        let r = run("h", &[443], &ProxySettings::default(), Duration::from_millis(300), &f).await;
        assert!(!r.is_ok() && t0.elapsed() < Duration::from_secs(3), "{r:?}");
    }

    #[test]
    fn sort_rank_puts_fast_first_then_untested_then_failed() {
        let fast = ProbeOutcome::Ok { port: 443, connect_ms: 90, hello_ms: 200, build: None };
        let slow = ProbeOutcome::Ok { port: 443, connect_ms: 900, hello_ms: 1500, build: None };
        let failed = ProbeOutcome::Failed("x".into());
        let mut order =
            [Some(&failed), None, Some(&slow), Some(&ProbeOutcome::Testing), Some(&ProbeOutcome::Queued), Some(&fast)];
        order.sort_by_key(|o| ProbeOutcome::sort_rank(*o));
        assert_eq!(order.first(), Some(&Some(&fast)));
        assert_eq!(order[1], Some(&slow));
        assert_eq!(order.last(), Some(&Some(&failed)));
    }

    #[test]
    fn port_choice_follows_the_windows_order_and_is_capped() {
        let mut s = VpnServer::new("a", "1.2.3.4");
        s.ssl_ports = vec![5555, 22, 443, 992, 995];
        assert_eq!(ports(&s), [443, 992, 995]);
        s.ssl_ports = vec![];
        s.listed_port = 1194;
        assert_eq!(ports(&s), [1194]);
        s.listed_port = 0;
        assert_eq!(ports(&s), [443]);
    }
}
