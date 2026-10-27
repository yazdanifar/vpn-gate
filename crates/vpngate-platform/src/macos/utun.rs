//! The macOS utun device (L3), created through the `PF_SYSTEM` control socket (`Utun.swift`).

use std::mem;
use std::os::fd::RawFd;

use super::packet_reader::FdPacketReader;
use crate::{PacketFn, PlatformError, TunDevice};

pub struct Utun {
    name: String,
    reader: FdPacketReader,
}

fn os_error(what: &str) -> PlatformError {
    PlatformError::new(format!("{what}: {}", std::io::Error::last_os_error()))
}

fn close_after(fd: RawFd, e: PlatformError) -> PlatformError {
    // SAFETY: `fd` is the control socket opened by `Utun::create`, closed once on this error path.
    unsafe { libc::close(fd) };
    e
}

impl Utun {
    /// Creates the next free `utunN`. Needs root.
    pub fn create() -> Result<Self, PlatformError> {
        // SAFETY: plain socket(2) call.
        let fd = unsafe { libc::socket(libc::PF_SYSTEM, libc::SOCK_DGRAM, libc::SYSPROTO_CONTROL) };
        if fd < 0 {
            return Err(os_error("socket"));
        }
        // SAFETY: `ctl_info` is plain old data; zeroed is a valid value.
        let mut info: libc::ctl_info = unsafe { mem::zeroed() };
        let control = b"com.apple.net.utun_control";
        for (dst, src) in info.ctl_name.iter_mut().zip(control) {
            *dst = *src as libc::c_char;
        }
        // SAFETY: `info` is a valid `ctl_info` for this ioctl.
        if unsafe { libc::ioctl(fd, libc::CTLIOCGINFO, &mut info) } != 0 {
            return Err(close_after(fd, os_error("CTLIOCGINFO")));
        }
        // SAFETY: plain old data again.
        let mut addr: libc::sockaddr_ctl = unsafe { mem::zeroed() };
        addr.sc_len = mem::size_of::<libc::sockaddr_ctl>() as u8;
        addr.sc_family = libc::AF_SYSTEM as u8;
        addr.ss_sysaddr = libc::AF_SYS_CONTROL as u16;
        addr.sc_id = info.ctl_id;
        addr.sc_unit = 0; // lets the kernel pick the next free utunN
                          // SAFETY: `addr` is a valid `sockaddr_ctl` of the stated length.
        let rc = unsafe {
            libc::connect(fd, (&addr as *const libc::sockaddr_ctl).cast(), mem::size_of::<libc::sockaddr_ctl>() as u32)
        };
        if rc != 0 {
            return Err(close_after(fd, os_error("connect utun (need root)")));
        }
        let mut name = [0 as libc::c_char; 32];
        let mut len = name.len() as libc::socklen_t;
        // SAFETY: `name` and `len` describe a valid buffer.
        let rc = unsafe {
            libc::getsockopt(fd, libc::SYSPROTO_CONTROL, libc::UTUN_OPT_IFNAME, name.as_mut_ptr().cast(), &mut len)
        };
        if rc != 0 {
            return Err(close_after(fd, os_error("UTUN_OPT_IFNAME")));
        }
        // SAFETY: the kernel NUL-terminates the name within the buffer.
        let name = unsafe { std::ffi::CStr::from_ptr(name.as_ptr()) }.to_string_lossy().into_owned();
        // SAFETY: `fd` is open.
        unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) };
        Ok(Utun { name, reader: FdPacketReader::new(fd) })
    }
}

impl TunDevice for Utun {
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
