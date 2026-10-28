//! OS traits and per-platform backends (tun, routes, DNS, IPC, service).
//!
//! The traits are the seams the session talks to (`Protocols.swift`). Backends live in per-OS modules; tests use the
//! recording fakes in `vpngate-testkit`, which record structured operations instead of command lines.

use std::fmt;
use std::io;
use std::net::Ipv6Addr;

use vpngate_core::routing_rule::{RoutingAction, RoutingConfig};

/// A failed OS operation, already worded for the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformError(pub String);

impl PlatformError {
    pub fn new(message: impl Into<String>) -> Self {
        PlatformError(message.into())
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for PlatformError {}

/// The address configuration a DHCP server handed out. IPv4 values are host-order integers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: u32,
    pub mask: u32,
    pub router: u32,
    pub dns: Vec<u32>,
    pub seconds: u32,
    pub server_id: u32,
    pub mtu: Option<u16>,
}

pub type PacketFn = Box<dyn Fn(Vec<u8>) + Send + Sync>;

/// A layer-3 tunnel interface.
pub trait TunDevice: Send + Sync {
    fn name(&self) -> String;
    /// Receives every packet the host writes to the interface. Set before `start_reading`.
    fn set_on_packet(&self, f: PacketFn);
    fn start_reading(&self);
    fn write_ipv4(&self, packet: Vec<u8>);
    fn write_ipv6(&self, _packet: Vec<u8>) {}
    /// Hand IPv6 packets from the host to the packet callback as well (they are dropped otherwise). Set before
    /// `start_reading`.
    fn set_forward_ipv6(&self, on: bool);
    fn close(&self);
}

pub trait DnsConfigurator: Send + Sync {
    /// Makes the tunnel the primary DNS resolver while connected.
    fn set(&self, servers: &[String], iface: &str, address: &str, router: &str) -> bool;
    fn remove(&self);
    /// The resolver(s) in effect right before `set` overrides them (the physical network's own DNS).
    fn current_servers(&self) -> Vec<String> {
        Vec::new()
    }
}

/// Everything `NetConfiguring::apply` needs for a full tunnel.
#[derive(Debug, Clone, PartialEq)]
pub struct NetApply {
    pub iface: String,
    pub lease: Lease,
    /// The peer the data really flows to; it keeps a route around the tunnel.
    pub bypass_host: String,
    pub block_ipv6: bool,
    pub mtu_override: Option<i64>,
    pub routing: Option<RoutingConfig>,
    /// When given, published as the system resolver instead of the lease's own DNS (a DNS proxy listens there).
    pub dns_proxy_address: Option<String>,
}

/// Routes, addresses and DNS for the tunnel interface.
pub trait NetConfiguring: Send + Sync {
    fn apply(&self, request: &NetApply) -> Result<(), PlatformError>;
    /// Adds a host route around the tunnel for a further peer (redirect target, UDP endpoint); removed by `teardown`.
    fn add_bypass(&self, _host: &str) {}
    /// Puts the SLAAC address learned from a Router Advertisement on the tunnel interface.
    fn configure_ipv6(&self, _address: Ipv6Addr, _prefix_length: usize) {}
    /// Routes one resolved address according to a domain rule's action.
    fn apply_dynamic_rule(&self, _ip: &str, _action: RoutingAction) {}
    /// The physical network's own DNS servers, captured just before `apply` pointed the system at the tunnel.
    fn direct_dns_servers(&self) -> Vec<String> {
        Vec::new()
    }
    /// SOCKS mode: the interface gets its address and a default route only sockets bound to it can use.
    fn apply_socks(&self, _iface: &str, _lease: &Lease, _mtu_override: Option<i64>) -> Result<(), PlatformError> {
        Ok(())
    }
    fn teardown(&self);
}

/// Creates the sockets that must follow the tunnel without touching the system routes (SOCKS mode, the VPN's own
/// DNS upstream): each one is pinned to the tunnel interface (`IP_BOUND_IF`, `SO_BINDTODEVICE`, a source-address
/// bind on Windows). The caller connects it and hands it to its async runtime.
pub trait SocketBinder: Send + Sync {
    fn tcp_socket(&self) -> io::Result<socket2::Socket>;
    fn udp_socket(&self) -> io::Result<socket2::Socket>;
}

/// Sockets that are not pinned to any interface: for tests on loopback and for backends that route by other means.
pub struct UnboundSocketBinder;

impl SocketBinder for UnboundSocketBinder {
    fn tcp_socket(&self) -> io::Result<socket2::Socket> {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
    }

    fn udp_socket(&self) -> io::Result<socket2::Socket> {
        socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
    }
}

/// One change a backend made to the machine, in a form that can be undone later by a process that never saw it (the
/// next daemon start after a crash). `kind` and `args` are the backend's own vocabulary.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UndoOp {
    pub kind: String,
    #[serde(default)]
    pub args: Vec<String>,
}

impl UndoOp {
    pub fn new(kind: impl Into<String>, args: &[&str]) -> Self {
        UndoOp { kind: kind.into(), args: args.iter().map(|a| a.to_string()).collect() }
    }
}

/// Reverts one recorded change. Failures are the backend's to ignore: the thing may be gone already.
pub trait Undoer {
    fn undo(&self, op: &UndoOp);
}

/// Where a backend writes its undo list as it goes (the daemon persists it).
pub trait UndoLog: Send + Sync {
    fn record(&self, op: UndoOp);
    fn clear(&self);
}

/// Runs an external program (`/sbin/route`, `/sbin/ifconfig`), returning its exit status and combined output.
/// Backends build argv-level commands behind this so tests can record them instead of running them.
pub trait CommandRunner: Send + Sync {
    fn run(&self, program: &str, args: &[&str]) -> CommandOutput;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: i32,
    pub output: String,
}

pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&self, program: &str, args: &[&str]) -> CommandOutput {
        match std::process::Command::new(program).args(args).output() {
            Ok(out) => {
                let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
                text.push_str(&String::from_utf8_lossy(&out.stderr));
                CommandOutput { status: out.status.code().unwrap_or(-1), output: text }
            }
            Err(e) => CommandOutput { status: -1, output: e.to_string() },
        }
    }
}

pub mod macos;
pub mod windows;
