//! State and logic of the desktop apps without any UI toolkit: what the GTK window shows (UI-SPEC sections 1, 4, 10, 11)
//! and the controller that drives the daemon. Mirrors `VPNGate.Core/MainViewModel.cs`. The widgets live in `apps/linux`.

pub mod accounts;
pub mod autostart;
pub mod cert_import;
pub mod columns;
pub mod format;
pub mod history;
pub mod model;
pub mod secrets;
pub mod settings;

#[cfg(unix)]
mod controller;
#[cfg(unix)]
pub use controller::*;
