//! OS traits and per-platform backends (tun, routes, DNS, IPC, service).
//!
//! The traits are the seams the session talks to (`Protocols.swift`). Backends live in per-OS modules; tests use the
//! recording fakes in `vpngate-testkit`, which record structured operations instead of command lines.

use std::fmt;
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
