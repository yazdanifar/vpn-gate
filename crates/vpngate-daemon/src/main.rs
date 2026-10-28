//! Privileged daemon: `--daemon`, `--connect`, `--probe`, `--version`.

use std::io::Write;
#[cfg(unix)]
use std::path::PathBuf;
use std::process::ExitCode;
#[cfg(unix)]
use std::sync::Arc;

use vpngate_core::ipc::HELPER_VERSION;
use vpngate_core::validation;
use vpngate_daemon::args::{self, Mode};
use vpngate_daemon::backend;
#[cfg(unix)]
use vpngate_daemon::engine::Engine;
use vpngate_daemon::{daemon, probe};

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let parsed = args::parse(&argv);
    if parsed.mode == Mode::Service {
        // The service dispatcher builds its own runtime, so it must not start inside one.
        return ExitCode::from(run_service());
    }
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
            let session = daemon::new_session();
            daemon::run_connect(session, &host, port, allow_ipv6, daemon::wait_for_signal()).await;
            0
        }
        Mode::Daemon { uid, bundle, cache } => run_daemon_mode(socket, uid, bundle, cache).await,
        Mode::Service => 2, // handled in `main`
    }
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
async fn run_daemon_mode(socket: String, uid: Option<u32>, bundle: Option<String>, cache: Option<String>) -> u8 {
    let session = daemon::new_session();
    let engine = Arc::new(Engine::production(
        PathBuf::from(cache.unwrap_or_else(|| backend::default_cache_path().to_string())),
        bundle.into_iter().map(PathBuf::from).collect(),
    ));
    let result = daemon::run_daemon(
        PathBuf::from(socket),
        uid,
        vpngate_daemon::ipc_server::current_console_uid,
        session,
        Some(engine),
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

/// `--daemon` on a console: the same pipe server the service runs, stopped with Ctrl-C.
#[cfg(windows)]
async fn run_daemon_mode(socket: String, _uid: Option<u32>, bundle: Option<String>, cache: Option<String>) -> u8 {
    match daemon::run_pipe_daemon(socket, cache, bundle, daemon::wait_for_signal()).await {
        Ok(()) => 0,
        Err(e) => {
            println!("IPC: {e}");
            1
        }
    }
}

#[cfg(windows)]
fn run_service() -> u8 {
    match vpngate_daemon::service::run() {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("cannot start as a service: {e}");
            1
        }
    }
}

#[cfg(not(any(unix, windows)))]
async fn run_daemon_mode(_socket: String, _uid: Option<u32>, _bundle: Option<String>, _cache: Option<String>) -> u8 {
    println!("no platform backend for this OS yet");
    2
}

#[cfg(not(windows))]
fn run_service() -> u8 {
    println!("--service is only available on Windows");
    2
}
