//! Sockets pinned to the tunnel with `SO_BINDTODEVICE`, so only they follow the policy rule `apply_socks` installs
//! (needs `CAP_NET_RAW` on older kernels).

use std::io;

use socket2::{Domain, Protocol, Socket, Type};

use crate::SocketBinder;

pub struct LinuxSocketBinder {
    iface: String,
}

impl LinuxSocketBinder {
    pub fn for_interface(name: &str) -> io::Result<Self> {
        if name.is_empty() || name.len() >= libc::IFNAMSIZ || name.contains('\0') {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "interface name"));
        }
        let c =
            std::ffi::CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
        // SAFETY: `c` is a valid NUL-terminated string.
        if unsafe { libc::if_nametoindex(c.as_ptr()) } == 0 {
            return Err(io::Error::new(io::ErrorKind::NotFound, format!("no interface {name}")));
        }
        Ok(LinuxSocketBinder { iface: name.to_string() })
    }

    fn bound(&self, ty: Type, protocol: Protocol) -> io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, ty, Some(protocol))?;
        socket.bind_device(Some(self.iface.as_bytes()))?;
        Ok(socket)
    }
}

impl SocketBinder for LinuxSocketBinder {
    fn tcp_socket(&self) -> io::Result<Socket> {
        self.bound(Type::STREAM, Protocol::TCP)
    }

    fn udp_socket(&self) -> io::Result<Socket> {
        self.bound(Type::DGRAM, Protocol::UDP)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_or_malformed_interfaces_are_errors() {
        assert!(LinuxSocketBinder::for_interface("nope999").is_err());
        assert!(LinuxSocketBinder::for_interface("a\0b").is_err());
        assert!(LinuxSocketBinder::for_interface("").is_err());
        assert!(LinuxSocketBinder::for_interface("a-name-that-is-too-long").is_err());
    }

    #[test]
    fn loopback_resolves() {
        // Binding itself may need CAP_NET_RAW, so only the lookup is asserted.
        assert!(LinuxSocketBinder::for_interface("lo").is_ok());
    }
}
