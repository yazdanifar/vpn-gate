//! The tun device of an Android connection: raw IP packets on the descriptor `VpnService` handed over. The descriptor
//! arrives late (see [`super::Link`]), so the reader is created on `start_reading`.

use std::sync::{Arc, Mutex};

use super::Link;
use crate::macos::packet_reader::FdPacketReader;
use crate::{PacketFn, TunDevice};

/// `VpnService` names the interface itself (`tunN`); the engine never needs the real name on Android.
pub const TUN_NAME: &str = "tun0";

pub struct AndroidTun {
    link: Arc<Link>,
    reader: Mutex<Option<Arc<FdPacketReader>>>,
    on_packet: Mutex<Option<PacketFn>>,
    forward_ipv6: Mutex<bool>,
}

impl AndroidTun {
    pub(crate) fn new(link: Arc<Link>) -> Self {
        AndroidTun { link, reader: Mutex::new(None), on_packet: Mutex::new(None), forward_ipv6: Mutex::new(false) }
    }

    fn reader(&self) -> Option<Arc<FdPacketReader>> {
        self.reader.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }
}

impl TunDevice for AndroidTun {
    fn name(&self) -> String {
        TUN_NAME.to_string()
    }

    fn set_on_packet(&self, f: PacketFn) {
        *self.on_packet.lock().unwrap_or_else(|e| e.into_inner()) = Some(f);
    }

    fn start_reading(&self) {
        let Some(fd) = *self.link.fd.lock().unwrap_or_else(|e| e.into_inner()) else { return };
        let mut slot = self.reader.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_some() {
            return;
        }
        let reader = Arc::new(FdPacketReader::new_raw(fd));
        reader.set_forward_ipv6(*self.forward_ipv6.lock().unwrap_or_else(|e| e.into_inner()));
        if let Some(f) = self.on_packet.lock().unwrap_or_else(|e| e.into_inner()).take() {
            reader.set_on_packet(f);
        }
        reader.start_reading();
        *slot = Some(reader);
    }

    fn write_ipv4(&self, packet: Vec<u8>) {
        if let Some(r) = self.reader() {
            r.write_ipv4(&packet);
        }
    }

    fn write_ipv6(&self, packet: Vec<u8>) {
        if let Some(r) = self.reader() {
            r.write_ipv6(&packet);
        }
    }

    fn set_forward_ipv6(&self, on: bool) {
        *self.forward_ipv6.lock().unwrap_or_else(|e| e.into_inner()) = on;
    }

    fn close(&self) {
        let reader = self.reader.lock().unwrap_or_else(|e| e.into_inner()).take();
        match reader {
            Some(r) => r.close(),
            None => {
                // `apply` ran but reading never started: the descriptor is still ours to close.
                if let Some(fd) = self.link.fd.lock().unwrap_or_else(|e| e.into_inner()).take() {
                    // SAFETY: ownership of the descriptor was transferred to us by `establish` and nothing else has it.
                    unsafe { libc::close(fd) };
                }
            }
        }
        self.link.host.tunnel_closed();
    }
}
