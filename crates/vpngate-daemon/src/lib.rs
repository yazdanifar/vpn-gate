//! The privileged daemon: IPC server, stale-state undo list, CLI parsing and the run loop around a `Session`.

pub mod args;
pub mod backend;
pub mod daemon;
pub mod engine;
// Bionic only has `getgrnam_r` from API 28, and Android has no daemon to authenticate anyway.
#[cfg(all(unix, not(target_os = "android")))]
pub mod group_auth;
pub mod ipc_server;
#[cfg(windows)]
pub mod pipe_server;
pub mod probe;
#[cfg(windows)]
pub mod service;
pub mod sid_policy;
pub mod stale;
pub mod validate;
