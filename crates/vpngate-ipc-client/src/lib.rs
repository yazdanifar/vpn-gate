//! Rust client for the daemon IPC (GTK app, integration tests). Unix sockets only until the Windows named-pipe
//! transport arrives with U17.

#[cfg(unix)]
mod client;
#[cfg(unix)]
pub use client::*;
