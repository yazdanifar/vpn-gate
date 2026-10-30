//! The Windows backend: a Wintun adapter, and addresses, MTU and routes through the IP Helper API. Everything that
//! decides *which* changes to make lives behind the [`ip_helper::IpHelper`] trait and compiles on every OS, so its tests
//! run on every CI OS against a recording fake; only the syscalls are `cfg(windows)`.

pub mod dns;
pub mod ip_helper;
pub mod net_config;
#[cfg(windows)]
pub mod socket_binder;
#[cfg(windows)]
pub mod sys;
#[cfg(windows)]
pub mod wintun;

pub use dns::WinDns;
pub use net_config::{WinNetConfig, WinUndoer};
