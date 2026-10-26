//! HTTP CONNECT and SOCKS5 client dialers: open a TCP stream to `host:port` through a proxy.

use std::net::IpAddr;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use vpngate_core::http_head::{self, HttpHead};
use vpngate_core::ipc::{ProxyKind, ProxySettings};

use crate::stream::StreamError;

fn proto(m: impl Into<String>) -> StreamError {
    StreamError::Protocol(m.into())
}

/// The proxy to dial through, or `None` when the settings mean "direct" (kind none, no host, or an unusable port).
pub fn effective(proxy: &ProxySettings) -> Option<(&ProxySettings, u16)> {
    if proxy.kind == ProxyKind::None || proxy.host.is_empty() {
        return None;
    }
    let port = u16::try_from(proxy.port.clamp(0, i64::from(u16::MAX))).ok().filter(|p| *p != 0)?;
    Some((proxy, port))
}

/// Connects to the proxy and asks it for a tunnel to `host:port`.
pub async fn connect(proxy: &ProxySettings, proxy_port: u16, host: &str, port: u16) -> Result<TcpStream, StreamError> {
    let mut tcp = TcpStream::connect((proxy.host.as_str(), proxy_port)).await?;
    match proxy.kind {
        ProxyKind::Http => http_connect(&mut tcp, proxy, host, port).await?,
        ProxyKind::Socks5 => socks5_connect(&mut tcp, proxy, host, port).await?,
        ProxyKind::None => unreachable!("effective() filters kind none"),
    }
    Ok(tcp)
}

fn credentials(proxy: &ProxySettings) -> Option<(&str, &str)> {
    match (&proxy.username, &proxy.password) {
        (Some(u), Some(p)) if !u.is_empty() => Some((u, p)),
        _ => None,
    }
}

fn authority(host: &str) -> String {
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V6(_)) => format!("[{host}]"),
        _ => host.to_string(),
    }
}

async fn http_connect(tcp: &mut TcpStream, proxy: &ProxySettings, host: &str, port: u16) -> Result<(), StreamError> {
    let target = format!("{}:{port}", authority(host));
    let mut req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some((u, p)) = credentials(proxy) {
        req += &format!("Proxy-Authorization: Basic {}\r\n", STANDARD.encode(format!("{u}:{p}")));
    }
    req += "\r\n";
    tcp.write_all(req.as_bytes()).await?;
    // Nothing follows the reply until we send the TLS ClientHello, so reading in chunks cannot swallow tunnel bytes.
    let mut raw = Vec::new();
    let mut chunk = [0u8; 1024];
    let head_end = loop {
        if let Some(i) = raw.windows(4).position(|w| w == http_head::TERMINATOR) {
            break i;
        }
        if raw.len() > http_head::MAX_SIZE {
            return Err(proto("Proxy answer too large"));
        }
        let n = tcp.read(&mut chunk).await?;
        if n == 0 {
            return Err(StreamError::Closed);
        }
        raw.extend_from_slice(&chunk[..n]);
    };
    let head = HttpHead::parse(&raw[..head_end]);
    match head.status_code() {
        Some(200..=299) => Ok(()),
        Some(407) => Err(proto("Proxy requires (valid) authentication")),
        Some(c) => Err(proto(format!("Proxy refused the connection (HTTP {c})"))),
        None => Err(proto("Not an HTTP proxy")),
    }
}

async fn socks5_connect(tcp: &mut TcpStream, proxy: &ProxySettings, host: &str, port: u16) -> Result<(), StreamError> {
    let creds = credentials(proxy);
    let hello: &[u8] = if creds.is_some() { &[5, 2, 0, 2] } else { &[5, 1, 0] };
    tcp.write_all(hello).await?;
    let mut sel = [0u8; 2];
    tcp.read_exact(&mut sel).await?;
    if sel[0] != 5 {
        return Err(proto("Not a SOCKS5 proxy"));
    }
    match sel[1] {
        0 => {}
        2 => {
            let (u, p) = creds.ok_or_else(|| proto("SOCKS5 proxy requires authentication"))?;
            if u.len() > 255 || p.len() > 255 {
                return Err(proto("SOCKS5 credentials too long"));
            }
            let mut auth = vec![1, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            tcp.write_all(&auth).await?;
            let mut r = [0u8; 2];
            tcp.read_exact(&mut r).await?;
            if r[1] != 0 {
                return Err(proto("SOCKS5 authentication failed"));
            }
        }
        _ => return Err(proto("SOCKS5 proxy accepts no usable authentication method")),
    }
    let mut req = vec![5, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => {
            req.push(1);
            req.extend_from_slice(&a.octets());
        }
        Ok(IpAddr::V6(a)) => {
            req.push(4);
            req.extend_from_slice(&a.octets());
        }
        Err(_) => {
            if host.len() > 255 {
                return Err(proto("Host name too long for SOCKS5"));
            }
            req.push(3);
            req.push(host.len() as u8);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    tcp.write_all(&req).await?;
    let mut r = [0u8; 4];
    tcp.read_exact(&mut r).await?;
    if r[1] != 0 {
        return Err(proto(format!("SOCKS5 proxy refused the connection (code {})", r[1])));
    }
    let skip = match r[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut l = [0u8; 1];
            tcp.read_exact(&mut l).await?;
            usize::from(l[0]) + 2
        }
        _ => return Err(proto("Malformed SOCKS5 reply")),
    };
    let mut rest = vec![0u8; skip];
    tcp.read_exact(&mut rest).await?;
    Ok(())
}
