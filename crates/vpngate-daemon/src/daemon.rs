//! The run loops behind `--daemon` and `--connect`, with shutdown injected so tests can drive them.

use std::future::Future;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::path::PathBuf;
use std::sync::Arc;

use vpngate_core::ipc::{ConnectionState, ProxySettings};
use vpngate_net::session::{simple_connect_config, EmitFn, SessionControlling};

#[cfg(unix)]
use crate::engine::Engine;
#[cfg(unix)]
use crate::group_auth::{GroupPeerAuth, SystemDirectory, GROUP_NAME};
#[cfg(unix)]
use crate::ipc_server::{IpcServer, PeerAuth, UidPeerAuth};

/// Serves IPC clients until `shutdown` completes, then disconnects the session and removes the socket.
#[cfg(unix)]
pub async fn run_daemon(
    socket: PathBuf,
    uid: Option<u32>,
    console_uid: impl Fn() -> Option<u32> + Send + Sync + 'static,
    session: Arc<dyn SessionControlling>,
    engine: Option<Arc<Engine>>,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    // With a fixed uid the console is not consulted at all.
    let auth: Arc<dyn PeerAuth> = if uid.is_some() {
        Arc::new(UidPeerAuth::new(uid, || None))
    } else if cfg!(target_os = "linux") {
        // No console owner on a Linux server or over SSH: root and the `vpngate` group decide.
        Arc::new(GroupPeerAuth::new(GROUP_NAME, Arc::new(SystemDirectory)))
    } else {
        Arc::new(UidPeerAuth::new(None, console_uid))
    };
    let server = IpcServer::new(&socket, uid, auth, session.clone());
    if let Some(engine) = engine {
        server.set_engine(engine);
    }
    server.start()?;
    println!("vpngate-daemon listening on {}", socket.display());
    shutdown.await;
    session.disconnect();
    server.stop();
    Ok(())
}

/// The Windows twin of [`run_daemon`]: serves the named pipe until `shutdown` completes. Creates the data directory and
/// undoes a crashed run's leftovers first, so the service and `--daemon` on a console behave alike.
#[cfg(windows)]
pub async fn run_pipe_daemon(
    pipe: String,
    cache: Option<String>,
    bundle: Option<String>,
    shutdown: impl Future<Output = ()>,
) -> std::io::Result<()> {
    use std::path::PathBuf;

    use crate::engine::Engine;
    use crate::ipc_server::IpcCore;
    use crate::pipe_server::PipeServer;

    std::fs::create_dir_all(crate::backend::WINDOWS_DATA_DIR)?;
    let session = new_session();
    let core = Arc::new(IpcCore::new(session.clone()));
    core.set_engine(Arc::new(Engine::production(
        PathBuf::from(cache.unwrap_or_else(|| crate::backend::default_cache_path().to_string())),
        bundle.into_iter().map(PathBuf::from).collect(),
    )));
    let server = PipeServer::new(pipe.clone(), core);
    server.start()?;
    println!("vpngate-daemon listening on {pipe}");
    shutdown.await;
    session.disconnect();
    server.stop();
    Ok(())
}

/// A session with this OS's backend, after undoing what a daemon that died without tearing down left behind.
pub fn new_session() -> Arc<vpngate_net::session::Session> {
    use crate::backend;
    use crate::stale::StaleState;
    let stale = Arc::new(StaleState::new(backend::default_state_path()));
    backend::cleanup_stale(&stale);
    let deps = backend::default_dependencies(std::path::Path::new(backend::default_unique_id_path()), stale);
    vpngate_net::session::Session::new(deps, vpngate_net::session::SessionTiming::default())
}

/// Connects once and prints the session's log until `shutdown` completes (`--connect`, debugging).
pub async fn run_connect(
    session: Arc<dyn SessionControlling>,
    host: &str,
    port: Option<i64>,
    allow_ipv6: bool,
    shutdown: impl Future<Output = ()>,
) {
    let emit: EmitFn = Arc::new(|e| {
        if let Some(l) = &e.log {
            println!("[{}] {l}", state_name(e.state));
        }
        if let Some(err) = &e.error {
            println!("[error] {err}");
        }
        if e.state == ConnectionState::Connected && e.bytes_in == 0 && e.bytes_out == 0 {
            println!("[connected] virtual IP {}", e.virtual_ip.as_deref().unwrap_or("?"));
        }
    });
    session.set_emit(Some(emit));
    session.connect(simple_connect_config(host, port, ProxySettings::default(), false, !allow_ipv6));
    shutdown.await;
    session.disconnect();
}

fn state_name(s: ConnectionState) -> String {
    serde_json::to_value(s).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

/// Resolves on SIGINT or SIGTERM (Ctrl-C elsewhere). A service stop on Windows (U17) supplies its own future.
pub async fn wait_for_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        match (signal(SignalKind::interrupt()), signal(SignalKind::terminate())) {
            (Ok(mut int), Ok(mut term)) => tokio::select! { _ = int.recv() => {}, _ = term.recv() => {} },
            _ => std::future::pending::<()>().await,
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use tokio::io::AsyncReadExt;
    use vpngate_core::ipc::{ConnectConfig, HelperEvent};

    #[derive(Default)]
    struct Fake {
        disconnects: AtomicUsize,
        connects: Mutex<Vec<ConnectConfig>>,
    }
    impl SessionControlling for Fake {
        fn set_emit(&self, _emit: Option<EmitFn>) {}
        fn snapshot(&self) -> HelperEvent {
            HelperEvent::new(ConnectionState::Disconnected)
        }
        fn connect(&self, config: ConnectConfig) {
            self.connects.lock().unwrap().push(config);
        }
        fn disconnect(&self) {
            self.disconnects.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn shutdown_disconnects_and_removes_the_socket() {
        let path = PathBuf::from(format!("/tmp/vg-daemon-{}.sock", std::process::id()));
        let session = Arc::new(Fake::default());
        let (tx, rx) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(run_daemon(path.clone(), None, || None, session.clone(), None, async {
            let _ = rx.await;
        }));
        for _ in 0..100 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let mut c = tokio::net::UnixStream::connect(&path).await.unwrap();
        let mut buf = [0u8; 256];
        // root is the only peer allowed without a configured uid or console user
        let n = tokio::time::timeout(std::time::Duration::from_millis(500), c.read(&mut buf)).await;
        assert!(matches!(n, Ok(Ok(_)) | Err(_)));
        tx.send(()).unwrap();
        task.await.unwrap().unwrap();
        assert_eq!(session.disconnects.load(Ordering::SeqCst), 1);
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn connect_mode_connects_once_without_reconnecting() {
        let session = Arc::new(Fake::default());
        run_connect(session.clone(), "1.2.3.4", Some(992), true, async {}).await;
        let cfgs = session.connects.lock().unwrap();
        assert_eq!(cfgs.len(), 1);
        assert_eq!(cfgs[0].host, "1.2.3.4");
        assert!(!cfgs[0].auto_reconnect);
        assert!(!cfgs[0].block_ipv6, "--allow-ipv6 lifts the block");
        assert_eq!(session.disconnects.load(Ordering::SeqCst), 1);
    }
}
