//! Asks the tunnel itself whether it carries data: a TCP connect plus a TLS handshake to a well-known public host,
//! through a socket pinned to the tunnel interface (so it still goes through the relay after the capture routes have
//! been pulled). A bare TCP handshake is not enough: some relays complete it and carry no usable data.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::ServerName;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use vpngate_core::cert_pin::ServerCertPolicy;
use vpngate_platform::SocketBinder;

use crate::session::TunnelProbe;

/// Several independent hosts: a network that blocks one of them must not look like a dead relay.
pub const TARGETS: [Ipv4Addr; 3] = [Ipv4Addr::new(1, 1, 1, 1), Ipv4Addr::new(8, 8, 8, 8), Ipv4Addr::new(9, 9, 9, 9)];
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(6);

pub struct TlsTunnelProbe {
    binder: Arc<dyn SocketBinder>,
    targets: Vec<SocketAddrV4>,
    timeout: Duration,
}

impl TlsTunnelProbe {
    pub fn new(binder: Arc<dyn SocketBinder>) -> Self {
        TlsTunnelProbe {
            binder,
            targets: TARGETS.iter().map(|ip| SocketAddrV4::new(*ip, 443)).collect(),
            timeout: ATTEMPT_TIMEOUT,
        }
    }

    pub fn with_targets(binder: Arc<dyn SocketBinder>, targets: Vec<SocketAddrV4>, timeout: Duration) -> Self {
        TlsTunnelProbe { binder, targets, timeout }
    }

    async fn attempt(&self, target: SocketAddrV4) -> bool {
        let Ok(socket) = self.binder.tcp_socket() else { return false };
        let timeout = self.timeout;
        // `connect_timeout` blocks until the handshake finishes or the deadline passes, so it runs off the reactor.
        let Ok(Ok(std_stream)) = tokio::task::spawn_blocking(move || {
            socket.connect_timeout(&target.into(), timeout)?;
            socket.set_nonblocking(true)?;
            Ok::<_, std::io::Error>(std::net::TcpStream::from(socket))
        })
        .await
        else {
            return false;
        };
        let Ok(tcp) = TcpStream::from_std(std_stream) else { return false };
        let Ok(config) = crate::tls::client_config_for_probe(&ServerCertPolicy::AcceptAny) else { return false };
        let name = ServerName::IpAddress(std::net::IpAddr::V4(*target.ip()).into());
        matches!(
            tokio::time::timeout(timeout, TlsConnector::from(Arc::new(config)).connect(name, tcp)).await,
            Ok(Ok(_))
        )
    }
}

#[async_trait::async_trait]
impl TunnelProbe for TlsTunnelProbe {
    async fn alive(&self) -> bool {
        for target in &self.targets {
            if self.attempt(*target).await {
                return true;
            }
        }
        false
    }
}
