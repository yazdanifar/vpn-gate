//! Optional TCP tuning of the relay socket, off unless asked for through the daemon's environment. The defaults stay
//! the kernels' own, which autotune their buffers: a fixed `SO_SNDBUF`/`SO_RCVBUF` switches that autotuning off on
//! Linux, so a bigger fixed value is a measurement to make on the link in question, not a better default.
//!
//! - `VPNGATE_TCP_BUFFER_KB=<1..65536>`: send and receive buffer size in KiB (the kernel may round it or cap it).
//! - `VPNGATE_TCP_CONGESTION=<name>` (Linux only, e.g. `bbr`): the congestion control of the relay connection; ignored
//!   quietly when the kernel does not offer it.

use socket2::SockRef;
use tokio::net::TcpStream;

pub const BUFFER_ENV: &str = "VPNGATE_TCP_BUFFER_KB";
pub const CONGESTION_ENV: &str = "VPNGATE_TCP_CONGESTION";

/// The buffer size in bytes for a `VPNGATE_TCP_BUFFER_KB` value; `None` when unset or not a sane number.
pub fn parse_buffer_kb(value: Option<&str>) -> Option<usize> {
    let kb: usize = value?.trim().parse().ok()?;
    (1..=65_536).contains(&kb).then_some(kb * 1024)
}

/// A congestion control name for `VPNGATE_TCP_CONGESTION` (the kernel's names are short lowercase words).
pub fn parse_congestion(value: Option<&str>) -> Option<String> {
    let name = value?.trim();
    let ok = !name.is_empty() && name.len() < 16 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    ok.then(|| name.to_string())
}

/// Applies whatever the environment asks for; every failure is ignored (the connection works without it).
pub fn apply(tcp: &TcpStream) {
    let sock = SockRef::from(tcp);
    if let Some(bytes) = parse_buffer_kb(std::env::var(BUFFER_ENV).ok().as_deref()) {
        let _ = sock.set_send_buffer_size(bytes);
        let _ = sock.set_recv_buffer_size(bytes);
    }
    #[cfg(target_os = "linux")]
    if let Some(name) = parse_congestion(std::env::var(CONGESTION_ENV).ok().as_deref()) {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor is open for the whole call and the pointer/length describe `name`'s bytes.
        unsafe {
            libc::setsockopt(
                tcp.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_CONGESTION,
                name.as_ptr().cast(),
                name.len() as libc::socklen_t,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn buffer_sizes_are_kib_within_a_sane_range() {
        assert_eq!(parse_buffer_kb(Some("512")), Some(512 * 1024));
        assert_eq!(parse_buffer_kb(Some(" 64 ")), Some(64 * 1024));
        for bad in [None, Some(""), Some("0"), Some("-5"), Some("65537"), Some("lots"), Some("1.5")] {
            assert_eq!(parse_buffer_kb(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn congestion_names_are_short_plain_words() {
        assert_eq!(parse_congestion(Some("bbr")).as_deref(), Some("bbr"));
        assert_eq!(parse_congestion(Some(" cubic ")).as_deref(), Some("cubic"));
        for bad in [None, Some(""), Some("a b"), Some("../x"), Some("way_too_long_a_name")] {
            assert_eq!(parse_congestion(bad), None, "{bad:?}");
        }
    }

    #[tokio::test]
    async fn applying_never_fails_the_connection() {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let s = TcpStream::connect(l.local_addr().unwrap()).await.unwrap();
        apply(&s); // with nothing set: a no-op
    }
}
