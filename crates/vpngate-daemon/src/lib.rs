//! The privileged daemon: IPC server, stale-state undo list, CLI parsing and the run loop around a `Session`.

pub mod args;
pub mod backend;
pub mod daemon;
pub mod engine;
pub mod ipc_server;
#[cfg(windows)]
pub mod pipe_server;
pub mod probe;
#[cfg(windows)]
pub mod service;
pub mod sid_policy;
pub mod stale;
pub mod validate;
