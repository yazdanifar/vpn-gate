//! Privileged daemon: `--daemon`, `--connect`, `--probe`, `--version`.

use std::io::Write;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use vpngate_core::ipc::HELPER_VERSION;
use vpngate_core::validation;
use vpngate_daemon::args::{self, Mode};
use vpngate_daemon::backend;
use vpngate_daemon::{daemon, probe};
use vpngate_net::session::{Session, SessionTiming};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = args::parse(&argv);
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("cannot start the async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    let code = runtime.block_on(run(parsed));
    let _ = std::io::stdout().flush();
    ExitCode::from(code)
}

async fn run(parsed: args::Args) -> u8 {
    let socket = parsed.socket.clone().unwrap_or_else(|| backend::default_socket_path().to_string());
    match parsed.mode {
        Mode::Version => {
            println!("{HELPER_VERSION}");
            0
        }
        Mode::Usage => {
            println!("{}", args::USAGE);
            2
        }
        Mode::Probe { host, port, watch_udp } => probe::run_probe(&host, port, watch_udp).await as u8,
        Mode::Connect { host, port, allow_ipv6 } => {
            if !is_root() {
                eprintln!("vpngate-daemon must run as root (use sudo)");
                return 1;
            }
            if !validation::is_valid_host(&host) {
                println!("invalid host");
                return 2;
            }
            let session = new_session();
            daemon::run_connect(session, &host, port, allow_ipv6, daemon::wait_for_signal()).await;
            0
        }
        Mode::Daemon { uid } => run_daemon_mode(socket, uid).await,
    }
}

fn new_session() -> Arc<Session> {
    let deps = backend::default_dependencies(std::path::Path::new(backend::default_unique_id_path()));
    Session::new(deps, SessionTiming::default())
}

#[cfg(unix)]
fn is_root() -> bool {
    // Without libc: the peer credentials of a socket pair report our own effective uid.
    tokio::net::UnixStream::pair().ok().and_then(|(a, _)| a.peer_cred().ok()).is_some_and(|c| c.uid() == 0)
}

#[cfg(not(unix))]
fn is_root() -> bool {
    true
}

#[cfg(unix)]
async fn run_daemon_mode(socket: String, uid: Option<u32>) -> u8 {
    let session = new_session();
    let result = daemon::run_daemon(
        PathBuf::from(socket),
        uid,
        vpngate_daemon::ipc_server::current_console_uid,
        session,
        daemon::wait_for_signal(),
    )
    .await;
    match result {
        Ok(()) => 0,
        Err(e) => {
            println!("IPC: {e}");
            1
        }
    }
}

#[cfg(not(unix))]
async fn run_daemon_mode(_socket: String, _uid: Option<u32>) -> u8 {
    println!("the Windows service entry point arrives with U17");
    2
}
