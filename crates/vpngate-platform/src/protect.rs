//! Keeping the VPN's own sockets out of the tunnel. On Android `VpnService.protect(fd)` exempts a socket from the VPN's
//! routes; the relay, UDP-acceleration and direct-DNS sockets must call it before they connect or send. Other platforms
//! never install a protector (they route around the tunnel with bypass routes), so `protect` is a no-op there.

use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, RwLock};

/// Returns false when the host refused to protect the socket.
pub type ProtectFn = Arc<dyn Fn(RawFd) -> bool + Send + Sync>;

static PROTECTOR: RwLock<Option<ProtectFn>> = RwLock::new(None);

/// Installs (or removes) the process-wide protector.
pub fn set_protector(f: Option<ProtectFn>) {
    *PROTECTOR.write().unwrap_or_else(|e| e.into_inner()) = f;
}

/// The installed protector, if any.
pub fn current() -> Option<ProtectFn> {
    PROTECTOR.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// Protects `fd` when a protector is installed; an error when the host refuses.
pub fn protect(fd: RawFd) -> io::Result<()> {
    match current() {
        Some(f) if !f(fd) => {
            Err(io::Error::new(io::ErrorKind::PermissionDenied, "the VPN host refused to protect a socket"))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    // One test touches the process-wide protector, so parallel tests of this crate never see it half-set.
    #[test]
    fn protector_lifecycle() {
        assert!(protect(5).is_ok(), "no protector installed: a no-op");

        let calls = Arc::new(AtomicUsize::new(0));
        let c = calls.clone();
        set_protector(Some(Arc::new(move |fd| {
            c.fetch_add(1, Ordering::SeqCst);
            fd != 99
        })));
        assert!(protect(5).is_ok());
        assert_eq!(protect(99).unwrap_err().kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        set_protector(None);
        assert!(protect(99).is_ok());
    }
}
