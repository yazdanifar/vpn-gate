//! The Android backend. The engine runs inside the app, so there is no daemon, no root and no routes to edit: the tunnel
//! comes from `VpnService.Builder.establish()` in Kotlin. The backend therefore turns what the other platforms apply
//! (address, routes, DNS, MTU) into a [`TunnelPlan`] and hands it to the [`VpnHost`], which returns the tun descriptor.
//! Everything here compiles and is tested on every Unix; nothing needs Android itself.

pub mod net_config;
pub mod socket_binder;
pub mod tun;

use std::sync::{Arc, Mutex};

use crate::PlatformError;

pub use net_config::{plan_for, AndroidNet};
pub use socket_binder::ProtectingSocketBinder;
pub use tun::AndroidTun;

/// What `VpnService.Builder` must be given to establish the tunnel. Routes and addresses are `a.b.c.d/len` strings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TunnelPlan {
    pub address: String,
    pub prefix_length: u8,
    /// Added with `addRoute`.
    pub routes: Vec<String>,
    /// Added with `excludeRoute` on API 33+; below that Kotlin computes route splits from `routes` minus these.
    pub excluded_routes: Vec<String>,
    pub dns_servers: Vec<String>,
    pub mtu: u16,
    /// IPv6 is blocked: Kotlin adds `::/0` so IPv6 traffic enters the tunnel (the tun then drops it) instead of leaking.
    pub block_ipv6: bool,
}

/// The Kotlin side of the engine (`VpnService`).
pub trait VpnHost: Send + Sync {
    /// Builds and establishes the tunnel; returns the tun descriptor, whose ownership passes to the engine
    /// (`ParcelFileDescriptor.detachFd()`), or the reason it could not be created (consent revoked, ...).
    fn establish(&self, plan: &TunnelPlan) -> Result<i32, String>;
    /// `VpnService.protect(fd)`.
    fn protect(&self, fd: i32) -> bool;
    /// The tunnel was torn down by the engine; Kotlin stops the foreground notification.
    fn tunnel_closed(&self) {}
}

/// Shared by the tun and the net configurator of one connection attempt: the descriptor only exists once `apply` has
/// asked the host to establish the tunnel, after the tun object was created.
pub(crate) struct Link {
    pub(crate) host: Arc<dyn VpnHost>,
    pub(crate) fd: Mutex<Option<i32>>,
}

impl Link {
    pub(crate) fn new(host: Arc<dyn VpnHost>) -> Arc<Link> {
        Arc::new(Link { host, fd: Mutex::new(None) })
    }

    pub(crate) fn establish(&self, plan: &TunnelPlan) -> Result<(), PlatformError> {
        let fd = self.host.establish(plan).map_err(PlatformError::new)?;
        if fd < 0 {
            return Err(PlatformError::new("The system did not create the VPN interface"));
        }
        *self.fd.lock().unwrap_or_else(|e| e.into_inner()) = Some(fd);
        Ok(())
    }
}

/// The tun and net factories for one session: each `make_tun` starts a new link that the next `make_net` picks up.
pub struct AndroidBackend {
    host: Arc<dyn VpnHost>,
    current: Mutex<Option<Arc<Link>>>,
}

impl AndroidBackend {
    pub fn new(host: Arc<dyn VpnHost>) -> Arc<Self> {
        Arc::new(AndroidBackend { host, current: Mutex::new(None) })
    }

    pub fn make_tun(&self) -> Result<Arc<AndroidTun>, PlatformError> {
        let link = Link::new(self.host.clone());
        *self.current.lock().unwrap_or_else(|e| e.into_inner()) = Some(link.clone());
        Ok(Arc::new(AndroidTun::new(link)))
    }

    pub fn make_net(&self) -> Arc<AndroidNet> {
        let link = self
            .current
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
            .unwrap_or_else(|| Link::new(self.host.clone()));
        Arc::new(AndroidNet::new(link))
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::RawFd;
    use std::sync::atomic::{AtomicI32, Ordering};
    use std::sync::mpsc::channel;
    use std::time::Duration;

    use super::*;
    use crate::{Lease, NetApply, NetConfiguring, SocketBinder, TunDevice};

    struct FakeHost {
        fd: AtomicI32,
        error: Option<String>,
        plans: Mutex<Vec<TunnelPlan>>,
        closed: Mutex<u32>,
        protected: Mutex<Vec<i32>>,
        allow_protect: bool,
    }

    impl FakeHost {
        fn new(fd: i32) -> Arc<Self> {
            Arc::new(FakeHost {
                fd: AtomicI32::new(fd),
                error: None,
                plans: Mutex::default(),
                closed: Mutex::default(),
                protected: Mutex::default(),
                allow_protect: true,
            })
        }
    }

    impl VpnHost for FakeHost {
        fn establish(&self, plan: &TunnelPlan) -> Result<i32, String> {
            self.plans.lock().unwrap().push(plan.clone());
            match &self.error {
                Some(e) => Err(e.clone()),
                None => Ok(self.fd.load(Ordering::SeqCst)),
            }
        }
        fn protect(&self, fd: i32) -> bool {
            self.protected.lock().unwrap().push(fd);
            self.allow_protect
        }
        fn tunnel_closed(&self) {
            *self.closed.lock().unwrap() += 1;
        }
    }

    fn pair() -> (RawFd, RawFd) {
        let mut fds = [0 as RawFd; 2];
        // SAFETY: `fds` has room for the two descriptors; datagrams keep packet boundaries like a tun does.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_DGRAM, 0, fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    }

    fn request() -> NetApply {
        NetApply {
            iface: "tun0".into(),
            lease: Lease {
                ip: 0x0A00_0002,
                mask: 0xFFFF_FF00,
                router: 0x0A00_0001,
                dns: vec![],
                seconds: 60,
                server_id: 1,
                mtu: None,
            },
            bypass_host: "1.1.1.1".into(),
            block_ipv6: false,
            mtu_override: None,
            routing: None,
            dns_proxy_address: None,
        }
    }

    #[test]
    fn apply_establishes_and_packets_flow_both_ways() {
        let (ours, theirs) = pair();
        let host = FakeHost::new(ours);
        let backend = AndroidBackend::new(host.clone());
        let tun = backend.make_tun().unwrap();
        let net = backend.make_net();
        let (tx, rx) = channel();
        tun.set_on_packet(Box::new(move |p| {
            let _ = tx.send(p);
        }));
        assert_eq!(tun.name(), "tun0");

        net.apply(&request()).unwrap();
        assert_eq!(host.plans.lock().unwrap().len(), 1);
        tun.start_reading();

        let packet = [0x45u8, 0, 0, 20, 1, 2, 3, 4];
        // SAFETY: `theirs` is an open datagram socket and `packet` is valid for its length.
        unsafe { libc::write(theirs, packet.as_ptr().cast(), packet.len()) };
        assert_eq!(rx.recv_timeout(Duration::from_secs(2)).unwrap(), packet);

        tun.write_ipv4(vec![0x45, 9, 9]);
        let mut buf = [0u8; 16];
        // SAFETY: `buf` is valid for 16 bytes; the read blocks until the tun wrote its datagram.
        let n = unsafe { libc::read(theirs, buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(&buf[..n as usize], [0x45, 9, 9]);

        tun.close();
        assert_eq!(*host.closed.lock().unwrap(), 1);
        // SAFETY: closing our end of the pair once.
        unsafe { libc::close(theirs) };
    }

    #[test]
    fn closing_before_reading_closes_the_descriptor() {
        let (ours, theirs) = pair();
        let host = FakeHost::new(ours);
        let backend = AndroidBackend::new(host.clone());
        let tun = backend.make_tun().unwrap();
        backend.make_net().apply(&request()).unwrap();
        tun.close();
        let mut buf = [0u8; 4];
        // SAFETY: valid buffer; the peer is closed, so the read reports end of stream or a reset, never data.
        assert!(unsafe { libc::read(theirs, buf.as_mut_ptr().cast(), 4) } <= 0);
        // SAFETY: closing our end of the pair once.
        unsafe { libc::close(theirs) };
    }

    #[test]
    fn host_errors_and_bad_descriptors_fail_apply() {
        let mut failing = FakeHost::new(-1);
        Arc::get_mut(&mut failing).unwrap().error = Some("VPN permission was revoked".into());
        let backend = AndroidBackend::new(failing);
        let _tun = backend.make_tun().unwrap();
        let err = backend.make_net().apply(&request()).unwrap_err();
        assert_eq!(err.0, "VPN permission was revoked");

        let backend = AndroidBackend::new(FakeHost::new(-1));
        let _tun = backend.make_tun().unwrap();
        assert!(backend.make_net().apply(&request()).is_err());
    }

    #[test]
    fn packets_before_the_tunnel_exists_are_dropped() {
        let backend = AndroidBackend::new(FakeHost::new(-1));
        let tun = backend.make_tun().unwrap();
        tun.start_reading();
        tun.write_ipv4(vec![1, 2, 3]);
        tun.close();
    }

    #[test]
    fn socks_mode_is_refused() {
        let backend = AndroidBackend::new(FakeHost::new(-1));
        let net = backend.make_net();
        assert!(net.apply_socks("tun0", &request().lease, None).is_err());
    }

    #[test]
    fn protecting_binder_protects_each_socket_and_can_refuse() {
        let host = FakeHost::new(-1);
        let h = host.clone();
        let binder = ProtectingSocketBinder::new(Arc::new(move |fd| h.protect(fd)));
        assert!(binder.tcp_socket().is_ok());
        assert!(binder.udp_socket().is_ok());
        assert_eq!(host.protected.lock().unwrap().len(), 2);

        let refusing = ProtectingSocketBinder::new(Arc::new(|_| false));
        assert!(refusing.tcp_socket().is_err());
    }
}
