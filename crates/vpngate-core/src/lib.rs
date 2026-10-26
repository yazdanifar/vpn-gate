//! Pure protocol and logic: pack, packets, crypto, server list, IPC messages.

pub mod byte_buffer;
pub mod cert_pin;
mod chacha_poly;
pub mod data_phase;
pub mod http_head;
pub mod pack;
pub mod packets;
pub mod rc4;
pub mod sha0;
pub mod softether_error;
pub mod udp_accel;
pub mod validation;
pub mod vgdat;
