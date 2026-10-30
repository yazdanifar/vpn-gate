//! The Linux tun device (L3) from `/dev/net/tun` with `IFF_TUN | IFF_NO_PI`: bare IP packets, no header.

use std::ffi::CStr;
use std::os::fd::RawFd;

use crate::macos::packet_reader::FdPacketReader;
use crate::{PacketFn, PlatformError, TunDevice};

const TUN_PATH: &[u8] = b"/dev/net/tun\0";
const TUNSETIFF: u64 = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
/// The kernel replaces `%d` with the first free number.
const NAME_TEMPLATE: &[u8] = b"vpngate%d";

pub struct LinuxTun {
    name: String,
    reader: FdPacketReader,
}

fn os_error(what: &str) -> PlatformError {
    PlatformError::new(format!("{what}: {}", std::io::Error::last_os_error()))
}

impl LinuxTun {
    /// Creates `vpngateN`. Needs `CAP_NET_ADMIN`.
    pub fn create() -> Result<Self, PlatformError> {
        // SAFETY: `TUN_PATH` is NUL-terminated.
        let fd: RawFd =
            unsafe { libc::open(TUN_PATH.as_ptr().cast(), libc::O_RDWR | libc::O_CLOEXEC | libc::O_NONBLOCK) };
        if fd < 0 {
            return Err(os_error("open /dev/net/tun (need CAP_NET_ADMIN, and the tun module)"));
        }
        // SAFETY: `ifreq` is plain old data; zeroed is a valid value.
        let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
        for (dst, src) in req.ifr_name.iter_mut().zip(NAME_TEMPLATE) {
            *dst = *src as libc::c_char;
        }
        req.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;
        // SAFETY: `req` is a valid `ifreq` for TUNSETIFF.
        if unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut req) } != 0 {
            let e = os_error("TUNSETIFF");
            // SAFETY: `fd` was opened above and is closed once on this error path.
            unsafe { libc::close(fd) };
            return Err(e);
        }
        // SAFETY: the kernel NUL-terminates the name it wrote into the zero-initialised buffer.
        let name = unsafe { CStr::from_ptr(req.ifr_name.as_ptr()) }.to_string_lossy().into_owned();
        Ok(LinuxTun { name, reader: FdPacketReader::new_raw(fd) })
    }
}

impl TunDevice for LinuxTun {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn set_on_packet(&self, f: PacketFn) {
        self.reader.set_on_packet(f);
    }

    fn start_reading(&self) {
        self.reader.start_reading();
    }

    fn write_ipv4(&self, packet: Vec<u8>) {
        self.reader.write_ipv4(&packet);
    }

    fn write_ipv6(&self, packet: Vec<u8>) {
        self.reader.write_ipv6(&packet);
    }

    fn set_forward_ipv6(&self, on: bool) {
        self.reader.set_forward_ipv6(on);
    }

    fn close(&self) {
        self.reader.close();
    }
}
