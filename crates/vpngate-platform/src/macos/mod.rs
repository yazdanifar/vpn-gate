//! The macOS backend (`Utun.swift`, `NetConfig.swift`): a utun device, `/sbin/route` + `/sbin/ifconfig` behind
//! [`CommandRunner`], configd DNS, and `IP_BOUND_IF` sockets. The command-building parts compile everywhere so their
//! tests run on every CI OS; only the syscalls are `cfg(target_os = "macos")`.

pub mod dns;
pub mod net_config;
#[cfg(unix)]
pub mod packet_reader;
#[cfg(target_os = "macos")]
pub mod socket_binder;
#[cfg(target_os = "macos")]
pub mod utun;

pub use net_config::{MacNetConfig, MacUndoer};
