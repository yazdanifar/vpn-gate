//! Test support shared by the Rust crates: golden vector loader and recording doubles for the platform traits.

#[cfg(unix)]
pub mod fake_daemon;
pub mod fakes;
pub mod golden;
