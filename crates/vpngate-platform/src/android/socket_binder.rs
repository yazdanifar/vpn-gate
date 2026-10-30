//! Plain sockets that `VpnService.protect` exempts from the tunnel: the direct-DNS upstream and anything else that must
//! reach the physical network while the VPN is up.

use std::io;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use socket2::Socket;

use crate::{SocketBinder, UnboundSocketBinder};

pub struct ProtectingSocketBinder {
    inner: UnboundSocketBinder,
    protector: Arc<dyn Fn(i32) -> bool + Send + Sync>,
}

impl ProtectingSocketBinder {
    pub fn new(protector: Arc<dyn Fn(i32) -> bool + Send + Sync>) -> Self {
        ProtectingSocketBinder { inner: UnboundSocketBinder, protector }
    }

    fn guard(&self, socket: Socket) -> io::Result<Socket> {
        if (self.protector)(socket.as_raw_fd()) {
            Ok(socket)
        } else {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "the VPN host refused to protect a socket"))
        }
    }
}

impl SocketBinder for ProtectingSocketBinder {
    fn tcp_socket(&self) -> io::Result<Socket> {
        self.guard(self.inner.tcp_socket()?)
    }

    fn udp_socket(&self) -> io::Result<Socket> {
        self.guard(self.inner.udp_socket()?)
    }
}
