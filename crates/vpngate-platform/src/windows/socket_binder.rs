//! Sockets pinned to the tunnel adapter with `IP_UNICAST_IF`, so only they follow the scoped default route
//! `apply_socks` installs (the Windows twin of `macos::socket_binder`).

use std::io;
use std::os::windows::io::AsRawSocket;

use socket2::{Domain, Protocol, Socket, Type};
use windows_sys::Win32::Networking::WinSock::{setsockopt, IPPROTO_IP, IP_UNICAST_IF, SOCKET};

use super::ip_helper::IpHelper;
use crate::SocketBinder;

pub struct WinSocketBinder {
    index: u32,
}

impl WinSocketBinder {
    pub fn for_interface(name: &str, ip: &dyn IpHelper) -> io::Result<Self> {
        ip.if_index(name)
            .map(|index| WinSocketBinder { index })
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, format!("no interface {name}")))
    }

    fn bound(&self, ty: Type, protocol: Protocol) -> io::Result<Socket> {
        let socket = Socket::new(Domain::IPV4, ty, Some(protocol))?;
        // For IPv4 the option takes the interface index in network byte order.
        let value = self.index.to_be();
        // SAFETY: the socket is valid and `value` is a 4-byte option value.
        let code = unsafe {
            setsockopt(
                socket.as_raw_socket() as SOCKET,
                IPPROTO_IP,
                IP_UNICAST_IF,
                (&value as *const u32).cast::<u8>(),
                std::mem::size_of::<u32>() as i32,
            )
        };
        if code != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(socket)
    }
}

impl SocketBinder for WinSocketBinder {
    fn tcp_socket(&self) -> io::Result<Socket> {
        self.bound(Type::STREAM, Protocol::TCP)
    }

    fn udp_socket(&self) -> io::Result<Socket> {
        self.bound(Type::DGRAM, Protocol::UDP)
    }
}
