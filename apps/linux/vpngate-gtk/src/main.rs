//! VPN Gate for Linux: the GTK4 / libadwaita front end. All state and daemon logic lives in `vpngate-app-model`; this crate
//! is widgets, the tray and the glue between the tokio runtime and the GTK main loop (the modules are in `lib.rs` so the
//! UI tests in `tests/` can build the windows).

use std::sync::Arc;

use adw::prelude::*;
use vpngate_gtk::{window, APP_ID};

/// Where the daemon listens (`vpngate-daemon::backend::default_socket_path` on Linux); `VPNGATE_SOCKET` overrides it.
const DEFAULT_SOCKET: &str = "/run/vpngate.sock";

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
