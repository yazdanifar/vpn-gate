//! The privileged daemon: IPC server, stale-state undo list, CLI parsing and the run loop around a `Session`.

pub mod args;
pub mod backend;
pub mod daemon;
pub mod engine;
#[cfg(unix)]
pub mod ipc_server;
pub mod probe;
pub mod stale;
pub mod validate;
