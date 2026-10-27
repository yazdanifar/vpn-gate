//! The OS-facing halves of the DNS proxy: a UDP client that sends one query through a [`SocketBinder`] socket, and the
//! loopback UDP listener that feeds [`DnsProxy::handle`] (`SystemDNSUpstream` and `DNSProxy.start` in `DNSProxy.swift`).

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;
use vpngate_core::routing_rule::RoutingConfig;
use vpngate_platform::{PlatformError, SocketBinder};

use crate::dns_proxy::{DnsProxy, DnsUpstream, DynamicRuleSink};
use crate::session::DnsProxyService;

/// A plain UDP DNS client: one query, one answer, no retries (the OS resolver that is asking will retry). The socket
/// comes from the binder, so the query leaves through the interface the binder pins it to.
pub struct SocketDnsUpstream {
    binder: Arc<dyn SocketBinder>,
    port: u16,
}

impl SocketDnsUpstream {
    pub fn new(binder: Arc<dyn SocketBinder>) -> Self {
        SocketDnsUpstream { binder, port: 53 }
    }

    /// Queries a non-standard port (tests).
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }

    async fn exchange(&self, message: &[u8], server: &str) -> Option<Vec<u8>> {
        let ip: Ipv4Addr = server.parse().ok()?;
        let socket = self.binder.udp_socket().ok()?;
        socket.set_nonblocking(true).ok()?;
        let socket = UdpSocket::from_std(std::net::UdpSocket::from(socket)).ok()?;
        socket.connect(SocketAddrV4::new(ip, self.port)).await.ok()?;
        socket.send(message).await.ok()?;
        let mut buf = vec![0u8; 4096];
        let n = socket.recv(&mut buf).await.ok()?;
        (n > 0).then(|| buf[..n].to_vec())
    }
}

#[async_trait]
impl DnsUpstream for SocketDnsUpstream {
    async fn query(&self, message: &[u8], server: &str, timeout_ms: u32) -> Option<Vec<u8>> {
        tokio::time::timeout(Duration::from_millis(u64::from(timeout_ms)), self.exchange(message, server))
            .await
            .ok()
            .flatten()
    }
}

struct Listening {
    task: JoinHandle<()>,
    socket: Arc<UdpSocket>,
}

struct Config {
    routing: RoutingConfig,
    tunnel: Vec<String>,
    direct: Vec<String>,
}

struct Shared {
    sink: Arc<dyn DynamicRuleSink>,
    upstream: Arc<dyn DnsUpstream>,
    config: Mutex<Config>,
}

impl Shared {
    fn proxy(&self) -> DnsProxy {
        let c = self.config.lock().expect("dns proxy config");
        let mut p = DnsProxy::new(self.sink.clone(), self.upstream.clone());
        p.routing = c.routing.clone();
        p.tunnel_dns_servers = c.tunnel.clone();
        p.direct_dns_servers = c.direct.clone();
        p
    }
}

/// The DNS proxy the session starts when domain routing rules exist: answers queries on a loopback UDP port.
pub struct DnsProxyServer {
    shared: Arc<Shared>,
    listen: SocketAddrV4,
    running: Mutex<Option<Listening>>,
}

impl DnsProxyServer {
    pub fn new(
        sink: Arc<dyn DynamicRuleSink>,
        upstream: Arc<dyn DnsUpstream>,
        routing: RoutingConfig,
        listen: SocketAddrV4,
    ) -> Self {
        let config = Mutex::new(Config { routing, tunnel: Vec::new(), direct: Vec::new() });
        DnsProxyServer { shared: Arc::new(Shared { sink, upstream, config }), listen, running: Mutex::new(None) }
    }

    /// The address actually bound, once started.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.running.lock().expect("dns proxy state").as_ref().and_then(|l| l.socket.local_addr().ok())
    }
}

impl Drop for DnsProxyServer {
    fn drop(&mut self) {
        self.stop();
    }
}

impl DnsProxyService for DnsProxyServer {
    /// Needs a Tokio runtime.
    fn start(&self) -> Result<(), PlatformError> {
        let mut running = self.running.lock().expect("dns proxy state");
        if running.is_some() {
            return Ok(());
        }
        let bind = |e: std::io::Error| PlatformError::new(format!("dns proxy bind {}: {e}", self.listen));
        let std_socket = std::net::UdpSocket::bind(self.listen).map_err(bind)?;
        std_socket.set_nonblocking(true).map_err(bind)?;
        let socket = Arc::new(UdpSocket::from_std(std_socket).map_err(bind)?);
        let (task_socket, shared) = (socket.clone(), self.shared.clone());
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, from)) = task_socket.recv_from(&mut buf).await else { continue };
                let (query, socket, shared) = (buf[..n].to_vec(), task_socket.clone(), shared.clone());
                tokio::spawn(async move {
                    let response = shared.proxy().handle(&query).await;
                    let _ = socket.send_to(&response, from).await;
                });
            }
        });
        *running = Some(Listening { task, socket });
        Ok(())
    }

    fn stop(&self) {
        if let Some(l) = self.running.lock().expect("dns proxy state").take() {
            l.task.abort();
        }
    }

    fn set_servers(&self, tunnel: Vec<String>, direct: Vec<String>) {
        let mut c = self.shared.config.lock().expect("dns proxy config");
        c.tunnel = tunnel;
        c.direct = direct;
    }
}

#[cfg(test)]
mod tests;
