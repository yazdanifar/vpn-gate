//! A minimal SOCKS5 server (RFC 1928): no authentication, CONNECT only, IPv4 and host-name destinations. It listens on
//! loopback only; any process on this machine can use it while it runs (the port of `SocksServer.swift`).
//!
//! The outbound half is a [`SocksConnector`]. [`TunnelConnector`] opens sockets through a [`SocketBinder`] so only they
//! follow the tunnel interface, and resolves host names with the VPN's own resolver over the same bound path.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::runtime::Handle;
use tokio::sync::watch;
use vpngate_core::validation;
use vpngate_platform::{PlatformError, SocketBinder};

use crate::dns_message;
use crate::dns_proxy::DnsUpstream;
use crate::entropy::{Entropy, SystemEntropy};
use crate::session::SocksService;

pub const MAX_CLIENTS: usize = 256;
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const DNS_TIMEOUT_MS: u32 = 4000;

/// The SOCKS5 reply code (RFC 1928 §6) that explains why a connection could not be made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SocksFailure {
    GeneralFailure = 1,
    NetworkUnreachable = 3,
    HostUnreachable = 4,
    ConnectionRefused = 5,
    CommandUnsupported = 7,
    AddressTypeUnsupported = 8,
}

/// Opens the outbound half of a proxied connection. A trait so the SOCKS server can be tested on loopback.
#[async_trait]
pub trait SocksConnector: Send + Sync {
    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, SocksFailure>;
}

/// Connects through the VPN without touching the system's routes: each socket comes from the [`SocketBinder`], which
/// pins it to the tunnel interface, so only it follows the interface-scoped default route. Host names are resolved by
/// the VPN's own resolver over the same bound path, so a name is never looked up outside it.
pub struct TunnelConnector {
    binder: Arc<dyn SocketBinder>,
    dns_servers: Vec<String>,
    upstream: Arc<dyn DnsUpstream>,
    connect_timeout: Duration,
}

impl TunnelConnector {
    pub fn new(binder: Arc<dyn SocketBinder>, dns_servers: Vec<String>, upstream: Arc<dyn DnsUpstream>) -> Self {
        TunnelConnector { binder, dns_servers, upstream, connect_timeout: CONNECT_TIMEOUT }
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    async fn resolve(&self, name: &str) -> Option<Ipv4Addr> {
        for server in &self.dns_servers {
            let id = 1 + SystemEntropy.below(usize::from(u16::MAX)) as u16;
            let query = dns_message::a_query(name, id);
            if let Some(response) = self.upstream.query(&query, server, DNS_TIMEOUT_MS).await {
                if let Some(first) = dns_message::resolved_ipv4_addresses(&response).first() {
                    return first.parse().ok();
                }
            }
        }
        None
    }
}

#[async_trait]
impl SocksConnector for TunnelConnector {
    async fn connect(&self, host: &str, port: u16) -> Result<TcpStream, SocksFailure> {
        let ip = if validation::is_ipv4_literal(host) {
            host.parse().map_err(|_| SocksFailure::AddressTypeUnsupported)?
        } else {
            self.resolve(host).await.ok_or(SocksFailure::HostUnreachable)?
        };
        let socket = self.binder.tcp_socket().map_err(|_| SocksFailure::GeneralFailure)?;
        let (addr, timeout) = (SocketAddrV4::new(ip, port), self.connect_timeout);
        // `connect_timeout` blocks until the handshake finishes or the deadline passes, so it runs off the reactor.
        let std_stream = tokio::task::spawn_blocking(move || {
            socket.connect_timeout(&addr.into(), timeout)?;
            socket.set_nonblocking(true)?;
            Ok::<_, io::Error>(std::net::TcpStream::from(socket))
        })
        .await
        .map_err(|_| SocksFailure::GeneralFailure)?
        .map_err(|e| failure_for(&e))?;
        let _ = std_stream.set_nodelay(true);
        TcpStream::from_std(std_stream).map_err(|_| SocksFailure::GeneralFailure)
    }
}

/// The SOCKS reply for a failed connect, from the OS error.
pub fn failure_for(e: &io::Error) -> SocksFailure {
    match e.kind() {
        io::ErrorKind::ConnectionRefused => SocksFailure::ConnectionRefused,
        io::ErrorKind::NetworkUnreachable => SocksFailure::NetworkUnreachable,
        io::ErrorKind::HostUnreachable | io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => {
            SocksFailure::HostUnreachable
        }
        _ => SocksFailure::GeneralFailure,
    }
}

struct Running {
    port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
    shutdown: watch::Sender<bool>,
}

pub struct SocksServer {
    connector: Arc<dyn SocksConnector>,
    port: u16,
    state: Mutex<Option<Running>>,
}

impl SocksServer {
    pub fn new(port: u16, connector: Arc<dyn SocksConnector>) -> Self {
        SocksServer { connector, port, state: Mutex::new(None) }
    }

    pub fn is_listening(&self) -> bool {
        self.state.lock().expect("socks state").is_some()
    }
}

impl Drop for SocksServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl SocksService for SocksServer {
    /// Needs a Tokio runtime: accepted connections are served on it.
    fn start(&self) -> Result<(), PlatformError> {
        let mut state = self.state.lock().expect("socks state");
        if state.is_some() {
            return Ok(());
        }
        let handle = Handle::try_current().map_err(|_| PlatformError::new("SOCKS proxy needs a running runtime"))?;
        let addr = SocketAddrV4::new(Ipv4Addr::LOCALHOST, self.port);
        let listener =
            bind_listener(addr).map_err(|e| PlatformError::new(format!("SOCKS proxy cannot listen on {addr}: {e}")))?;
        let port = listener.local_addr().map(|a| a.port()).unwrap_or(self.port);
        let (shutdown, rx) = watch::channel(false);
        let stop = Arc::new(AtomicBool::new(false));
        let live = Arc::new(AtomicUsize::new(0));
        let (connector, stop_flag) = (self.connector.clone(), stop.clone());
        // The accept loop is a plain thread: `stop` can close the listener before it returns, so the port is free for
        // an immediate re-bind, which a task that is only aborted could not promise.
        let accept = std::thread::Builder::new()
            .name("vpngate-socks-accept".into())
            .spawn(move || {
                for conn in listener.incoming() {
                    if stop_flag.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(conn) = conn else { continue };
                    if live.fetch_add(1, Ordering::SeqCst) >= MAX_CLIENTS {
                        live.fetch_sub(1, Ordering::SeqCst);
                        continue; // dropped: the client sees the connection close
                    }
                    let (connector, mut rx, live) = (connector.clone(), rx.clone(), live.clone());
                    handle.spawn(async move {
                        if conn.set_nonblocking(true).is_ok() {
                            if let Ok(stream) = TcpStream::from_std(conn) {
                                tokio::select! {
                                    () = serve(stream, connector.as_ref()) => {}
                                    _ = rx.changed() => {}
                                }
                            }
                        }
                        live.fetch_sub(1, Ordering::SeqCst);
                    });
                }
            })
            .map_err(|e| PlatformError::new(format!("SOCKS proxy thread: {e}")))?;
        *state = Some(Running { port, stop, accept: Some(accept), shutdown });
        Ok(())
    }

    /// The port actually bound (differs from the requested one only when that was 0, which tests use).
    fn bound_port(&self) -> u16 {
        self.state.lock().expect("socks state").as_ref().map_or(0, |r| r.port)
    }

    /// Returns once the listening socket is closed, so the port can be re-bound. Established sessions end shortly
    /// after.
    fn stop(&self) {
        let Some(mut running) = self.state.lock().expect("socks state").take() else { return };
        running.stop.store(true, Ordering::SeqCst);
        let _ = running.shutdown.send(true);
        // `accept` blocks, so a throwaway connection wakes the loop to see the flag.
        let _ = std::net::TcpStream::connect_timeout(
            &SocketAddr::from((Ipv4Addr::LOCALHOST, running.port)),
            Duration::from_secs(1),
        );
        if let Some(t) = running.accept.take() {
            let _ = t.join();
        }
    }
}

fn bind_listener(addr: SocketAddrV4) -> io::Result<TcpListener> {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    // Not on Windows, where SO_REUSEADDR would let another process share the port.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(64)?;
    Ok(socket.into())
}

fn reply(code: u8) -> [u8; 10] {
    [5, code, 0, 1, 0, 0, 0, 0, 0, 0]
}

async fn serve(mut client: TcpStream, connector: &dyn SocksConnector) {
    let negotiated = tokio::time::timeout(HANDSHAKE_TIMEOUT, negotiate(&mut client)).await;
    let Ok(Some((host, port))) = negotiated else { return };
    match connector.connect(&host, port).await {
        Err(f) => {
            let _ = client.write_all(&reply(f as u8)).await;
        }
        Ok(mut out) => {
            if client.write_all(&reply(0)).await.is_err() {
                return;
            }
            // Both ways until each side has finished; a half-close on one side is passed on to the other.
            let _ = tokio::io::copy_bidirectional(&mut client, &mut out).await;
        }
    }
}

/// Greeting + request. Returns the destination, or `None` after answering with the right failure.
async fn negotiate(c: &mut TcpStream) -> Option<(String, u16)> {
    let mut head = [0u8; 2];
    c.read_exact(&mut head).await.ok()?;
    if head[0] != 5 || head[1] == 0 {
        return None;
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    c.read_exact(&mut methods).await.ok()?;
    if !methods.contains(&0) {
        let _ = c.write_all(&[5, 0xFF]).await;
        return None;
    }
    c.write_all(&[5, 0]).await.ok()?;
    let mut req = [0u8; 4];
    c.read_exact(&mut req).await.ok()?;
    if req[0] != 5 {
        return None;
    }
    if req[1] != 1 {
        let _ = c.write_all(&reply(SocksFailure::CommandUnsupported as u8)).await;
        return None;
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            c.read_exact(&mut a).await.ok()?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut n = [0u8; 1];
            c.read_exact(&mut n).await.ok()?;
            if n[0] == 0 {
                return None;
            }
            let mut name = vec![0u8; usize::from(n[0])];
            c.read_exact(&mut name).await.ok()?;
            let host = String::from_utf8_lossy(&name).into_owned();
            // Only a plain DNS name may continue: it ends up in a resolver query.
            if !validation::is_valid_host(&host) {
                let _ = c.write_all(&reply(SocksFailure::HostUnreachable as u8)).await;
                return None;
            }
            host
        }
        _ => {
            let _ = c.write_all(&reply(SocksFailure::AddressTypeUnsupported as u8)).await; // IPv6 is not carried
            return None;
        }
    };
    let mut p = [0u8; 2];
    c.read_exact(&mut p).await.ok()?;
    Some((host, u16::from_be_bytes(p)))
}

#[cfg(test)]
mod tests;
