//! Sockets pinned to the tunnel interface with `IP_BOUND_IF`, so only they follow the interface-scoped default route
//! `apply_socks` installs (`SocksServer.swift`, `DNSProxy.swift`).

use std::ffi::CString;
use std::io;
use std::num::NonZeroU32;

use socket2::{Domain, Protocol, Socket, Type};

use crate::SocketBinder;

pub struct MacSocketBinder {
    index: NonZeroU32,
}

impl MacSocketBinder {
    pub fn for_interface(name: &str) -> io::Result<Self> {
        let c = CString::new(name).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interface name"))?;
        // SAFETY: `c` is a valid NUL-terminated string.
        let index = unsafe { libc::if_nametoindex(c.as_ptr()) };
        NonZeroU32::new(index)
            .map(|index| MacSocketBinder { index })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no interface {name}")))
    }

    fn bound(&self, ty: Type, protocol: Protocol) -> io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, ty, Some(protocol))?;
        socket.bind_device_by_index_v4(Some(self.index))?;
        Ok(socket)
    }
}

impl SocketBinder for MacSocketBinder {
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
    fn binds_sockets_to_loopback() {
        let binder = MacSocketBinder::for_interface("lo0").expect("lo0 exists");
        binder.tcp_socket().expect("bound tcp socket");
        binder.udp_socket().expect("bound udp socket");
    }

    #[test]
    fn unknown_interface_is_an_error() {
        assert!(MacSocketBinder::for_interface("nope999").is_err());
        assert!(MacSocketBinder::for_interface("a\0b").is_err());
    }
}
