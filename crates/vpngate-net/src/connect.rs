//! Outgoing TCP connections of the engine. Where the platform installed a socket protector (Android's
//! `VpnService.protect`), each socket is protected before it connects, so the relay link never loops through the tunnel.

use std::io;

use tokio::net::TcpStream;

/// `TcpStream::connect`, with the installed protector applied to every candidate socket first.
pub async fn connect_tcp(host: &str, port: u16) -> io::Result<TcpStream> {
    #[cfg(unix)]
    if let Some(protector) = vpngate_platform::protect::current() {
        use std::os::fd::AsRawFd;

        use tokio::net::TcpSocket;

        let mut last = io::Error::new(io::ErrorKind::NotFound, format!("no address for {host}"));
        for addr in tokio::net::lookup_host((host, port)).await? {
            let socket = if addr.is_ipv4() { TcpSocket::new_v4()? } else { TcpSocket::new_v6()? };
            if !protector(socket.as_raw_fd()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "the VPN host refused to protect a socket",
                ));
            }
            match socket.connect(addr).await {
                Ok(stream) => return Ok(stream),
                Err(e) => last = e,
            }
        }
        return Err(last);
    }
    TcpStream::connect((host, port)).await
}
