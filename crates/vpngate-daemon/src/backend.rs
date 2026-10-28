//! Where the platform backends plug in: macOS (U13), Windows (U16/U17) and Linux (U21) have theirs. Any other OS gets the
//! engine with a tunnel that cannot be created: a `connect` handshakes with the relay and then reports "no platform backend" as the session error.

use std::path::Path;
use std::sync::Arc;

use vpngate_core::ipc::ConnectConfig;
use vpngate_core::routing_rule::RoutingConfig;
use vpngate_net::entropy::{ClientEnvironment, SystemEntropy};
use vpngate_net::host_unique_id::HostUniqueId;
use vpngate_net::session::{
    softether_transport, tls_stream_factory, DnsProxyService, SessionDependencies, SocksService, VpnTransport,
};
use vpngate_platform::{NetApply, NetConfiguring, PlatformError, TunDevice};

use crate::stale::StaleState;

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
const MISSING: &str = "No platform backend for this OS yet";

struct Unsupported(String);

impl Unsupported {
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    fn missing() -> Self {
        Unsupported(MISSING.to_string())
    }
}

impl NetConfiguring for Unsupported {
    fn apply(&self, _request: &NetApply) -> Result<(), PlatformError> {
        Err(PlatformError::new(self.0.clone()))
    }
    fn teardown(&self) {}
}

impl DnsProxyService for Unsupported {
    fn start(&self) -> Result<(), PlatformError> {
        Err(PlatformError::new(self.0.clone()))
    }
    fn stop(&self) {}
    fn set_servers(&self, _tunnel: Vec<String>, _direct: Vec<String>) {}
}

impl SocksService for Unsupported {
    fn start(&self) -> Result<(), PlatformError> {
        Err(PlatformError::new(self.0.clone()))
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

pub type MakeTransport = Arc<dyn Fn(&ConnectConfig, u16) -> Arc<dyn VpnTransport> + Send + Sync>;

/// The real SoftEther transport with this OS's platform backend (a placeholder where none exists yet).
/// `unique_id_path` is where the per-install id lives; `stale` is where the backend writes its undo list.
pub fn default_dependencies(unique_id_path: &Path, stale: Arc<StaleState>) -> SessionDependencies {
    let unique_id = HostUniqueId::load(unique_id_path, |n| vpngate_net::entropy::Entropy::bytes(&mut SystemEntropy, n));
    let environment = client_environment();
    let make_transport = Arc::new(move |config: &ConnectConfig, port| {
        softether_transport(config, port, &unique_id, &environment, tls_stream_factory(config))
    });
    platform_dependencies(make_transport, stale)
}

#[cfg(target_os = "macos")]
pub fn platform_dependencies(make_transport: MakeTransport, stale: Arc<StaleState>) -> SessionDependencies {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use vpngate_net::dns_server::{DnsProxyServer, SocketDnsUpstream};
    use vpngate_net::session::{NetRuleSink, DNS_PROXY_LISTEN_ADDRESS};
    use vpngate_net::socks::{SocksServer, TunnelConnector};
    use vpngate_platform::macos::dns::SystemDns;
    use vpngate_platform::macos::socket_binder::MacSocketBinder;
    use vpngate_platform::macos::utun::Utun;
    use vpngate_platform::macos::MacNetConfig;
    use vpngate_platform::{SocketBinder, SystemRunner, UnboundSocketBinder};

    let listen = SocketAddrV4::new(DNS_PROXY_LISTEN_ADDRESS.parse().unwrap_or(Ipv4Addr::LOCALHOST), 53);
    SessionDependencies {
        make_transport,
        make_tun: Arc::new(|| Utun::create().map(|t| Arc::new(t) as Arc<dyn TunDevice>)),
        make_net: Arc::new(move || {
            Arc::new(MacNetConfig::new(Arc::new(SystemRunner), Arc::new(SystemDns), stale.clone()))
                as Arc<dyn NetConfiguring>
        }),
        // The proxy's queries follow the routing table: the tunnel's resolver goes through the capture routes, a
        // `direct` domain's through the bypass routes `apply` added for the physical DNS.
        make_dns_proxy: Arc::new(move |net: Arc<dyn NetConfiguring>, routing: RoutingConfig| {
            let upstream = Arc::new(SocketDnsUpstream::new(Arc::new(UnboundSocketBinder)));
            Ok(Arc::new(DnsProxyServer::new(Arc::new(NetRuleSink(net)), upstream, routing, listen))
                as Arc<dyn DnsProxyService>)
        }),
        make_socks: Arc::new(|port, iface: &str, dns: Vec<String>| match MacSocketBinder::for_interface(iface) {
            Ok(binder) => {
                let binder: Arc<dyn SocketBinder> = Arc::new(binder);
                let upstream = Arc::new(SocketDnsUpstream::new(binder.clone()));
                Arc::new(SocksServer::new(port, Arc::new(TunnelConnector::new(binder, dns, upstream))))
                    as Arc<dyn SocksService>
            }
            Err(e) => {
                Arc::new(Unsupported(format!("SOCKS proxy cannot bind to {iface}: {e}"))) as Arc<dyn SocksService>
            }
        }),
    }
}

#[cfg(windows)]
pub fn platform_dependencies(make_transport: MakeTransport, stale: Arc<StaleState>) -> SessionDependencies {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use vpngate_net::dns_server::{DnsProxyServer, SocketDnsUpstream};
    use vpngate_net::session::{NetRuleSink, DNS_PROXY_LISTEN_ADDRESS};
    use vpngate_net::socks::{SocksServer, TunnelConnector};
    use vpngate_platform::windows::dns::WinDns;
    use vpngate_platform::windows::ip_helper::IpHelper;
    use vpngate_platform::windows::socket_binder::WinSocketBinder;
    use vpngate_platform::windows::sys::{SystemDnsApi, SystemIpHelper};
    use vpngate_platform::windows::wintun::WintunDevice;
    use vpngate_platform::windows::WinNetConfig;
    use vpngate_platform::{SocketBinder, UnboundSocketBinder};

    let listen = SocketAddrV4::new(DNS_PROXY_LISTEN_ADDRESS.parse().unwrap_or(Ipv4Addr::LOCALHOST), 53);
    SessionDependencies {
        make_transport,
        make_tun: Arc::new(|| WintunDevice::create(&wintun_dll_path()).map(|t| Arc::new(t) as Arc<dyn TunDevice>)),
        make_net: Arc::new(move || {
            let dns = Arc::new(WinDns::new(Arc::new(SystemIpHelper), Arc::new(SystemDnsApi)));
            Arc::new(WinNetConfig::new(Arc::new(SystemIpHelper), dns, stale.clone())) as Arc<dyn NetConfiguring>
        }),
        make_dns_proxy: Arc::new(move |net: Arc<dyn NetConfiguring>, routing: RoutingConfig| {
            let upstream = Arc::new(SocketDnsUpstream::new(Arc::new(UnboundSocketBinder)));
            Ok(Arc::new(DnsProxyServer::new(Arc::new(NetRuleSink(net)), upstream, routing, listen))
                as Arc<dyn DnsProxyService>)
        }),
        make_socks: Arc::new(|port, iface: &str, dns: Vec<String>| {
            let ip: &dyn IpHelper = &SystemIpHelper;
            match WinSocketBinder::for_interface(iface, ip) {
                Ok(binder) => {
                    let binder: Arc<dyn SocketBinder> = Arc::new(binder);
                    let upstream = Arc::new(SocketDnsUpstream::new(binder.clone()));
                    Arc::new(SocksServer::new(port, Arc::new(TunnelConnector::new(binder, dns, upstream))))
                        as Arc<dyn SocksService>
                }
                Err(e) => {
                    Arc::new(Unsupported(format!("SOCKS proxy cannot bind to {iface}: {e}"))) as Arc<dyn SocksService>
                }
            }
        }),
    }
}

#[cfg(target_os = "linux")]
pub fn platform_dependencies(make_transport: MakeTransport, stale: Arc<StaleState>) -> SessionDependencies {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use vpngate_net::dns_server::{DnsProxyServer, SocketDnsUpstream};
    use vpngate_net::session::{NetRuleSink, DNS_PROXY_LISTEN_ADDRESS};
    use vpngate_net::socks::{SocksServer, TunnelConnector};
    use vpngate_platform::linux::socket_binder::LinuxSocketBinder;
    use vpngate_platform::linux::tun::LinuxTun;
    use vpngate_platform::linux::{LinuxDns, LinuxNetConfig};
    use vpngate_platform::{SocketBinder, SystemRunner, UnboundSocketBinder};

    let listen = SocketAddrV4::new(DNS_PROXY_LISTEN_ADDRESS.parse().unwrap_or(Ipv4Addr::LOCALHOST), 53);
    SessionDependencies {
        make_transport,
        make_tun: Arc::new(|| LinuxTun::create().map(|t| Arc::new(t) as Arc<dyn TunDevice>)),
        make_net: Arc::new(move || {
            let dns = Arc::new(LinuxDns::new(Arc::new(SystemRunner)));
            Arc::new(LinuxNetConfig::new(Arc::new(SystemRunner), dns, stale.clone())) as Arc<dyn NetConfiguring>
        }),
        // The proxy's queries follow the routing table: the tunnel's resolver goes through the capture routes, a
        // `direct` domain's through the bypass routes `apply` added for the physical DNS.
        make_dns_proxy: Arc::new(move |net: Arc<dyn NetConfiguring>, routing: RoutingConfig| {
            let upstream = Arc::new(SocketDnsUpstream::new(Arc::new(UnboundSocketBinder)));
            Ok(Arc::new(DnsProxyServer::new(Arc::new(NetRuleSink(net)), upstream, routing, listen))
                as Arc<dyn DnsProxyService>)
        }),
        make_socks: Arc::new(|port, iface: &str, dns: Vec<String>| match LinuxSocketBinder::for_interface(iface) {
            Ok(binder) => {
                let binder: Arc<dyn SocketBinder> = Arc::new(binder);
                let upstream = Arc::new(SocketDnsUpstream::new(binder.clone()));
                Arc::new(SocksServer::new(port, Arc::new(TunnelConnector::new(binder, dns, upstream))))
                    as Arc<dyn SocksService>
            }
            Err(e) => {
                Arc::new(Unsupported(format!("SOCKS proxy cannot bind to {iface}: {e}"))) as Arc<dyn SocksService>
            }
        }),
    }
}

/// `wintun.dll` ships next to the service executable.
#[cfg(windows)]
fn wintun_dll_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("wintun.dll")))
        .map_or_else(|| "wintun.dll".to_string(), |p| p.to_string_lossy().into_owned())
}

#[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
pub fn platform_dependencies(make_transport: MakeTransport, _stale: Arc<StaleState>) -> SessionDependencies {
    SessionDependencies {
        make_transport,
        make_tun: Arc::new(|| Err::<Arc<dyn TunDevice>, _>(PlatformError::new(MISSING))),
        make_net: Arc::new(|| Arc::new(Unsupported::missing()) as Arc<dyn NetConfiguring>),
        make_dns_proxy: Arc::new(|_net: Arc<dyn NetConfiguring>, _routing: RoutingConfig| {
            Ok(Arc::new(Unsupported::missing()) as Arc<dyn DnsProxyService>)
        }),
        make_socks: Arc::new(|_port, _iface, _dns| Arc::new(Unsupported::missing()) as Arc<dyn SocksService>),
    }
}

/// Undoes what a daemon that died without tearing down left on the machine (routes, resolver), before a new run.
pub fn cleanup_stale(stale: &StaleState) {
    #[cfg(target_os = "macos")]
    {
        use vpngate_platform::macos::dns::SystemDns;
        use vpngate_platform::macos::MacUndoer;
        let undoer = MacUndoer::new(Arc::new(vpngate_platform::SystemRunner), Arc::new(SystemDns));
        let n = stale.cleanup_stale(&undoer);
        if n > 0 {
            println!("[state] undid {n} leftover change(s) from a previous run");
        }
    }
    #[cfg(windows)]
    {
        use vpngate_platform::windows::dns::WinDns;
        use vpngate_platform::windows::sys::{SystemDnsApi, SystemIpHelper};
        use vpngate_platform::windows::WinUndoer;
        let dns = Arc::new(WinDns::new(Arc::new(SystemIpHelper), Arc::new(SystemDnsApi)));
        let undoer = WinUndoer::new(Arc::new(SystemIpHelper), dns);
        let n = stale.cleanup_stale(&undoer);
        if n > 0 {
            println!("[state] undid {n} leftover change(s) from a previous run");
        }
    }
    #[cfg(not(any(target_os = "macos", windows, target_os = "linux")))]
    let _ = stale;
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

/// The named pipe the Windows service listens on and the WinUI app connects to.
pub const WINDOWS_PIPE_NAME: &str = r"\\.\pipe\VPNGate";

/// Where the Windows service keeps its data.
pub const WINDOWS_DATA_DIR: &str = "C:\\ProgramData\\VPNGate";

pub fn default_socket_path() -> &'static str {
    if cfg!(target_os = "macos") {
        vpngate_core::ipc::HELPER_SOCKET_PATH
    } else if cfg!(windows) {
        WINDOWS_PIPE_NAME
    } else {
        "/run/vpngate.sock"
    }
}

pub fn default_state_path() -> &'static str {
    if cfg!(target_os = "macos") {
        "/var/run/vpngate-mac.state"
    } else if cfg!(windows) {
        "C:\\ProgramData\\VPNGate\\state.json"
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
