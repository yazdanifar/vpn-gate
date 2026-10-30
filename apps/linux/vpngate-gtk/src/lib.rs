//! The widgets of the VPN Gate GTK app. `main.rs` is only the entry point; the modules are a library so the in-process UI
//! tests (`tests/ui.rs`, under Xvfb) can build every window against a fake daemon.

pub mod account_editor;
pub mod accounts_window;
pub mod ctx;
pub mod details;
pub mod history_window;
pub mod log_window;
pub mod routing_editor;
pub mod settings_window;
pub mod tray;
pub mod window;

pub const APP_ID: &str = "net.vpngate.App";
