//! Privileged daemon: `--version` only until U11.

fn main() {
    if std::env::args().nth(1).as_deref() == Some("--version") {
        println!("vpngate-daemon {}", env!("CARGO_PKG_VERSION"));
    }
}
