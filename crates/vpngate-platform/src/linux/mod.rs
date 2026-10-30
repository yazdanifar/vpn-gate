//! The Linux backend: `/dev/net/tun`, addresses and routes through iproute2, DNS through systemd-resolved (with a
//! `/etc/resolv.conf` backup as the fallback), and `SO_BINDTODEVICE` sockets. As on macOS, everything that decides
//! *which* commands to run sits behind [`crate::CommandRunner`] and compiles everywhere, so its tests run on every CI
//! OS; only the syscalls are `cfg(target_os = "linux")`.

pub mod dns;
pub mod net_config;
#[cfg(target_os = "linux")]
pub mod socket_binder;
#[cfg(target_os = "linux")]
pub mod tun;

pub use dns::LinuxDns;
pub use net_config::{LinuxNetConfig, LinuxUndoer};
