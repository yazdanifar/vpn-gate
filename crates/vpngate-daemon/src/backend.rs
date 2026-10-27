//! Where the platform backends plug in. Until U13/U16/U21 land, every OS gets the engine with a tunnel that cannot be
//! created: a `connect` handshakes with the relay and then reports "no platform backend" as the session error.

use std::path::Path;
use std::sync::Arc;

use vpngate_core::ipc::ConnectConfig;
use vpngate_core::routing_rule::RoutingConfig;
use vpngate_net::entropy::{ClientEnvironment, SystemEntropy};
use vpngate_net::host_unique_id::HostUniqueId;
use vpngate_net::session::{
    softether_transport, tls_stream_factory, DnsProxyService, SessionDependencies, SocksService,
};
use vpngate_platform::{NetApply, NetConfiguring, PlatformError, TunDevice};

const MISSING: &str = "No platform backend for this OS yet";

struct Unsupported;

impl NetConfiguring for Unsupported {
    fn apply(&self, _request: &NetApply) -> Result<(), PlatformError> {
        Err(PlatformError::new(MISSING))
    }
    fn teardown(&self) {}
}

impl DnsProxyService for Unsupported {
    fn start(&self) -> Result<(), PlatformError> {
        Err(PlatformError::new(MISSING))
    }
    fn stop(&self) {}
    fn set_servers(&self, _tunnel: Vec<String>, _direct: Vec<String>) {}
}

impl SocksService for Unsupported {
    fn start(&self) -> Result<(), PlatformError> {
        Err(PlatformError::new(MISSING))
    }
    fn bound_port(&self) -> u16 {
        0
    }
    fn stop(&self) {}
}

/// What the login pack says about this machine; best effort, never fails.
pub fn client_environment() -> ClientEnvironment {
    let os_name = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        other => other,
    };
    let command = |program: &str, args: &[&str]| {
        std::process::Command::new(program)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
    };
    let os_version =
        if cfg!(target_os = "macos") { command("sw_vers", &["-productVersion"]) } else { command("uname", &["-r"]) };
    let hostname = std::env::var("HOSTNAME").ok().filter(|h| !h.is_empty()).or_else(|| command("hostname", &[]));
    ClientEnvironment {
        os_name: os_name.to_string(),
        os_version: os_version.unwrap_or_else(|| "0".to_string()),
        hostname: hostname.unwrap_or_else(|| "localhost".to_string()),
    }
}

/// The real SoftEther transport with a placeholder platform. `unique_id_path` is where the per-install id lives.
pub fn default_dependencies(unique_id_path: &Path) -> SessionDependencies {
    let unique_id = HostUniqueId::load(unique_id_path, |n| vpngate_net::entropy::Entropy::bytes(&mut SystemEntropy, n));
    let environment = client_environment();
    SessionDependencies {
        make_transport: Arc::new(move |config: &ConnectConfig, port| {
            softether_transport(config, port, &unique_id, &environment, tls_stream_factory(config))
        }),
        make_tun: Arc::new(|| Err::<Arc<dyn TunDevice>, _>(PlatformError::new(MISSING))),
        make_net: Arc::new(|| Arc::new(Unsupported) as Arc<dyn NetConfiguring>),
        make_dns_proxy: Arc::new(|_net: Arc<dyn NetConfiguring>, _routing: RoutingConfig| {
            Ok(Arc::new(Unsupported) as Arc<dyn DnsProxyService>)
        }),
        make_socks: Arc::new(|_port, _iface, _dns| Arc::new(Unsupported) as Arc<dyn SocksService>),
    }
}

/// Where the platform keeps the per-install id.
pub fn default_unique_id_path() -> &'static str {
    if cfg!(target_os = "macos") {
        "/var/db/vpngate-mac.uid"
    } else if cfg!(windows) {
        "C:\\ProgramData\\VPNGate\\host.uid"
    } else {
        "/var/lib/vpngate/host.uid"
    }
}

pub fn default_socket_path() -> &'static str {
    if cfg!(target_os = "macos") {
        vpngate_core::ipc::HELPER_SOCKET_PATH
    } else {
        "/run/vpngate.sock"
    }
}

pub fn default_state_path() -> &'static str {
    if cfg!(target_os = "macos") {
        "/var/run/vpngate-mac.state"
    } else {
        "/run/vpngate.state"
    }
}

/// Where the daemon keeps the newest verified server list.
pub fn default_cache_path() -> &'static str {
    if cfg!(target_os = "macos") {
        "/var/db/vpngate-mac.dat"
    } else if cfg!(windows) {
        "C:\\ProgramData\\VPNGate\\VPNGate.dat"
    } else {
        "/var/lib/vpngate/VPNGate.dat"
    }
}
