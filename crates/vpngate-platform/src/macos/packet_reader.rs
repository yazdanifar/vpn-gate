//! Reads utun-framed packets (4-byte address-family header + IP packet) from a file descriptor. Separate from the
//! utun device so it can be tested with a socket pair.
//!
//! The reader thread is the only one that ever polls or reads the descriptor, and `close` waits for it to stop before
//! closing the descriptor, so a recycled fd number can never be read by a stale thread.

use std::os::fd::RawFd;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use crate::PacketFn;

/// Address-family values of the utun header as macOS writes them, whatever OS runs the tests.
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

type Callback = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

struct Running {
    wake_read: RawFd,
    wake_write: RawFd,
    stopped: Receiver<()>,
}

pub struct FdPacketReader {
    /// -1 once closed. Held while writing, so a write never lands on a closed (or recycled) descriptor.
    fd: Mutex<RawFd>,
    running: Mutex<Option<Running>>,
    on_packet: Arc<Mutex<Option<Callback>>>,
    forward_ipv6: Arc<AtomicBool>,
    /// Packets carry no 4-byte header (Linux `IFF_NO_PI`); the IP version nibble tells the family.
    raw: bool,
}

impl FdPacketReader {
    pub fn new(fd: RawFd) -> Self {
        Self::with_framing(fd, false)
    }

    /// For a tun device without packet information: bare IP packets in both directions.
    pub fn new_raw(fd: RawFd) -> Self {
        Self::with_framing(fd, true)
    }

    fn with_framing(fd: RawFd, raw: bool) -> Self {
        FdPacketReader {
            raw,
            fd: Mutex::new(fd),
            running: Mutex::new(None),
            on_packet: Arc::default(),
            forward_ipv6: Arc::default(),
        }
    }

    pub fn set_on_packet(&self, f: PacketFn) {
        *lock(&self.on_packet) = Some(Arc::from(f));
    }

    pub fn set_forward_ipv6(&self, on: bool) {
        self.forward_ipv6.store(on, Ordering::SeqCst);
    }

    pub fn start_reading(&self) {
        let mut running = lock(&self.running);
        let fd = *lock(&self.fd);
        if fd < 0 || running.is_some() {
            return;
        }
        let mut pipe = [0 as RawFd; 2];
        // SAFETY: `pipe` is a valid two-element array.
        if unsafe { libc::pipe(pipe.as_mut_ptr()) } != 0 {
            return;
        }
        let (tx, rx) = channel();
        let (on_packet, forward6, raw) = (self.on_packet.clone(), self.forward_ipv6.clone(), self.raw);
        let wake = pipe[0];
        std::thread::Builder::new()
            .name("vpngate-tun-reader".into())
            .spawn(move || {
                read_loop(fd, wake, &on_packet, &forward6, raw);
                let _ = tx.send(());
            })
            .expect("spawn tun reader");
        *running = Some(Running { wake_read: pipe[0], wake_write: pipe[1], stopped: rx });
    }

    fn write_framed(&self, family: u8, packet: &[u8]) {
        let fd = lock(&self.fd);
        if *fd < 0 {
            return;
        }
        let mut out = Vec::with_capacity(packet.len() + 4);
        if !self.raw {
            out.extend_from_slice(&[0, 0, 0, family]);
        }
        out.extend_from_slice(packet);
        // SAFETY: the descriptor is open while the lock is held, and `out` is valid for `out.len()` bytes.
        unsafe { libc::write(*fd, out.as_ptr().cast(), out.len()) };
    }

    pub fn write_ipv4(&self, packet: &[u8]) {
        self.write_framed(AF_INET, packet);
    }

    pub fn write_ipv6(&self, packet: &[u8]) {
        self.write_framed(AF_INET6, packet);
    }

    pub fn close(&self) {
        if let Some(r) = lock(&self.running).take() {
            // SAFETY: the wake pipe is ours; one byte wakes the poll.
            unsafe { libc::write(r.wake_write, [1u8].as_ptr().cast(), 1) };
            let _ = r.stopped.recv_timeout(Duration::from_secs(2));
            // SAFETY: both ends are open and no longer used by the (stopped) thread.
            unsafe {
                libc::close(r.wake_read);
                libc::close(r.wake_write);
            }
        }
        let mut fd = lock(&self.fd);
        if *fd >= 0 {
            // SAFETY: closed exactly once; the stored value becomes -1.
            unsafe { libc::close(*fd) };
            *fd = -1;
        }
    }
}

impl Drop for FdPacketReader {
    fn drop(&mut self) {
        self.close();
    }
}

fn read_loop(fd: RawFd, wake: RawFd, on_packet: &Mutex<Option<Callback>>, forward6: &AtomicBool, raw: bool) {
    let mut buf = vec![0u8; 65536];
    loop {
        let mut fds = [
            libc::pollfd { fd, events: libc::POLLIN, revents: 0 },
            libc::pollfd { fd: wake, events: libc::POLLIN, revents: 0 },
        ];
        // SAFETY: `fds` is a valid array of two pollfds.
        let r = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if r < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if fds[1].revents != 0 {
            return; // close() asked us to stop
        }
        if fds[0].revents & libc::POLLIN == 0 {
            if fds[0].revents != 0 {
                return;
            }
            continue;
        }
        // SAFETY: `buf` is valid for `buf.len()` bytes.
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
        if n < 0 {
            match std::io::Error::last_os_error().kind() {
                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted => continue,
                _ => return,
            }
        }
        let n = n as usize;
        let skip = if raw { 0 } else { 4 };
        if n <= skip {
            continue;
        }
        // The header is the address family: 2 = AF_INET (IPv4), 30 = AF_INET6 (IPv6). Without one, the IP version.
        let family = if raw {
            match buf[0] >> 4 {
                4 => AF_INET,
                6 => AF_INET6,
                _ => continue,
            }
        } else {
            buf[3]
        };
        if family == AF_INET || (family == AF_INET6 && forward6.load(Ordering::SeqCst)) {
            let callback = lock(on_packet).clone();
            if let Some(f) = callback {
                f(buf[skip..n].to_vec());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixDatagram;
    use std::time::Instant;

    use super::*;

    /// Tests that create descriptors run one at a time: the recycling test `dup2`s onto a descriptor number, which
    /// would hijack one a parallel test had just been given.
    fn serial() -> MutexGuard<'static, ()> {
        static LOCK: Mutex<()> = Mutex::new(());
        lock(&LOCK)
    }

    fn eventually(mut cond: impl FnMut() -> bool) -> bool {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if cond() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        cond()
    }

    fn collecting(reader: &FdPacketReader) -> Arc<Mutex<Vec<Vec<u8>>>> {
        let got = Arc::new(Mutex::new(Vec::new()));
        let sink = got.clone();
        reader.set_on_packet(Box::new(move |p| lock(&sink).push(p)));
        got
    }

    fn pair() -> (FdPacketReader, UnixDatagram) {
        let (a, b) = UnixDatagram::pair().unwrap();
        (FdPacketReader::new(a.into_raw_fd()), b)
    }

    fn put(peer: &UnixDatagram, af: u8, body: &[u8]) {
        let mut d = vec![0, 0, 0, af];
        d.extend_from_slice(body);
        peer.send(&d).unwrap();
    }

    #[test]
    fn delivers_ipv4_and_skips_other_families() {
        let _serial = serial();
        let (reader, peer) = pair();
        let got = collecting(&reader);
        reader.start_reading();
        put(&peer, 30, &[1, 2, 3, 4]); // AF_INET6 → ignored
        put(&peer, 2, &[9, 8, 7, 6]);
        assert!(eventually(|| lock(&got).len() == 1));
        assert_eq!(*lock(&got), vec![vec![9, 8, 7, 6]]);
        reader.write_ipv4(&[5, 5, 5, 5]);
        let mut buf = [0u8; 64];
        let n = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0, 0, 0, 2, 5, 5, 5, 5]);
        reader.close();
    }

    #[test]
    fn ipv6_is_forwarded_only_when_enabled_and_written_as_af_inet6() {
        let _serial = serial();
        let (reader, peer) = pair();
        reader.set_forward_ipv6(true);
        let got = collecting(&reader);
        reader.start_reading();
        put(&peer, 30, &[0x60, 1, 2, 3]);
        put(&peer, 18, &[7, 7, 7, 7]);
        assert!(eventually(|| lock(&got).len() == 1));
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(*lock(&got), vec![vec![0x60, 1, 2, 3]], "AF_INET6 forwarded, other families still skipped");
        reader.write_ipv6(&[0x60, 9, 9, 9]);
        let mut buf = [0u8; 64];
        let n = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0, 0, 0, 30, 0x60, 9, 9, 9], "utun header for IPv6 is AF_INET6 = 30 on macOS");
        reader.close();
    }

    #[test]
    fn raw_mode_has_no_header_and_sniffs_the_ip_version() {
        let _serial = serial();
        let (a, peer) = UnixDatagram::pair().unwrap();
        let reader = FdPacketReader::new_raw(a.into_raw_fd());
        let got = collecting(&reader);
        reader.start_reading();
        peer.send(&[0x60, 1, 2, 3]).unwrap(); // IPv6 → dropped while not forwarded
        peer.send(&[0x45, 9, 8, 7]).unwrap();
        peer.send(&[0x10, 9, 8, 7]).unwrap(); // neither
        assert!(eventually(|| lock(&got).len() == 1));
        assert_eq!(*lock(&got), vec![vec![0x45, 9, 8, 7]]);
        reader.write_ipv4(&[0x45, 5, 5, 5]);
        let mut buf = [0u8; 64];
        let n = peer.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], &[0x45, 5, 5, 5]);
        reader.close();
    }

    #[test]
    fn ipv6_is_dropped_by_default() {
        let _serial = serial();
        let (reader, peer) = pair();
        let got = collecting(&reader);
        reader.start_reading();
        put(&peer, 30, &[0x60, 1, 2, 3]);
        put(&peer, 2, &[1, 1, 1, 1]);
        assert!(eventually(|| lock(&got).len() == 1));
        assert_eq!(*lock(&got), vec![vec![1, 1, 1, 1]]);
        reader.close();
    }

    #[test]
    fn closed_reader_never_reads_from_a_recycled_descriptor() {
        let _serial = serial();
        let (a, _peer) = UnixDatagram::pair().unwrap();
        let old = a.into_raw_fd();
        let reader = FdPacketReader::new(old);
        let got = collecting(&reader);
        reader.start_reading();
        std::thread::sleep(Duration::from_millis(100)); // the reader thread is parked in poll()
        reader.close();
        // The kernel hands the same descriptor number to the next tunnel.
        let (next, next_peer) = UnixDatagram::pair().unwrap();
        let next = next.into_raw_fd();
        // SAFETY: both descriptors are open; `old` was closed by the reader and is reused here.
        unsafe {
            libc::dup2(next, old);
        }
        // Other tests' file I/O can close a number this test shares; a failed send then just means nothing to consume.
        let _ = next_peer.send(&[0, 0, 0, 2, 1, 2, 3, 4]);
        std::thread::sleep(Duration::from_millis(300));
        assert!(lock(&got).is_empty(), "stale reader consumed a packet that belongs to the next tunnel");
        // SAFETY: closing the descriptors this test opened.
        unsafe {
            libc::close(old);
            libc::close(next);
        }
    }

    #[test]
    fn writes_after_close_are_ignored() {
        let _serial = serial();
        let (reader, peer) = pair();
        reader.close();
        reader.write_ipv4(&[1, 2, 3, 4]);
        peer.set_nonblocking(true).unwrap();
        assert!(peer.recv(&mut [0u8; 8]).is_err());
    }
}
