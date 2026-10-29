//! VPN Gate for Linux: the GTK4 / libadwaita front end. All state and daemon logic lives in `vpngate-app-model`; this crate
//! is widgets, the tray and the glue between the tokio runtime and the GTK main loop.

mod account_editor;
mod accounts_window;
mod ctx;
mod details;
mod history_window;
mod log_window;
mod routing_editor;
mod settings_window;
mod tray;
mod window;

use std::sync::Arc;

use adw::prelude::*;

/// Where the daemon listens (`vpngate-daemon::backend::default_socket_path` on Linux); `VPNGATE_SOCKET` overrides it.
const DEFAULT_SOCKET: &str = "/run/vpngate.sock";
pub const APP_ID: &str = "net.vpngate.App";

fn main() -> gtk::glib::ExitCode {
    let rt = Arc::new(
        tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build().expect("tokio runtime"),
    );
    let app = adw::Application::builder().application_id(APP_ID).build();
    app.connect_activate(move |app| {
        if let Some(w) = app.active_window() {
            w.present();
            return;
        }
        let socket = std::env::var("VPNGATE_SOCKET").unwrap_or_else(|_| DEFAULT_SOCKET.into());
        window::build(app, rt.clone(), socket);
    });
    app.run()
}
