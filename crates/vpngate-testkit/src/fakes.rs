//! Recording doubles for the `vpngate-platform` traits. They keep *structured* operations (what was routed, which
//! address was set) rather than command lines, so the same session tests hold on every OS backend.

use std::net::Ipv6Addr;
use std::sync::{Arc, Mutex, MutexGuard};

use vpngate_core::routing_rule::{RoutingAction, RoutingConfig};
use vpngate_platform::{Lease, NetApply, NetConfiguring, PacketFn, PlatformError, TunDevice};

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

type PacketCallback = dyn Fn(Vec<u8>) + Send + Sync;

#[derive(Default)]
struct TunState {
    written: Vec<Vec<u8>>,
    written_v6: Vec<Vec<u8>>,
    closed: bool,
    reading: bool,
    forward_ipv6: bool,
}

pub struct FakeTun {
    name: String,
    on_packet: Mutex<Option<Arc<PacketCallback>>>,
    state: Mutex<TunState>,
}

impl FakeTun {
    pub fn new(name: &str) -> Arc<Self> {
        Arc::new(FakeTun { name: name.to_string(), on_packet: Mutex::new(None), state: Mutex::default() })
    }

    /// IPv4 packets written to the interface (host-bound traffic).
    pub fn written(&self) -> Vec<Vec<u8>> {
        lock(&self.state).written.clone()
    }

    pub fn written_ipv6(&self) -> Vec<Vec<u8>> {
        lock(&self.state).written_v6.clone()
    }

    pub fn is_closed(&self) -> bool {
        lock(&self.state).closed
    }

    pub fn is_reading(&self) -> bool {
        lock(&self.state).reading
    }

    pub fn forward_ipv6(&self) -> bool {
        lock(&self.state).forward_ipv6
    }

    /// Pretends the host stack wrote `packet` to the interface.
    pub fn inject(&self, packet: Vec<u8>) {
        let f = lock(&self.on_packet).clone();
        if let Some(f) = f {
            f(packet);
        }
    }
}

impl TunDevice for FakeTun {
    fn name(&self) -> String {
        self.name.clone()
    }

    fn set_on_packet(&self, f: PacketFn) {
        *lock(&self.on_packet) = Some(Arc::from(f));
    }

    fn start_reading(&self) {
        lock(&self.state).reading = true;
    }

    fn write_ipv4(&self, packet: Vec<u8>) {
        lock(&self.state).written.push(packet);
    }

    fn write_ipv6(&self, packet: Vec<u8>) {
        lock(&self.state).written_v6.push(packet);
    }

    fn set_forward_ipv6(&self, on: bool) {
        lock(&self.state).forward_ipv6 = on;
    }

    fn close(&self) {
        lock(&self.state).closed = true;
    }
}

/// One call to a [`FakeNet`], in call order.
#[derive(Debug, Clone, PartialEq)]
pub enum NetOp {
    Apply(NetApply),
    AddBypass(String),
    ConfigureIpv6 { address: Ipv6Addr, prefix_length: usize },
    DynamicRule { ip: String, action: RoutingAction },
    ApplySocks { iface: String, mtu_override: Option<i64> },
    Teardown,
}

#[derive(Default)]
pub struct FakeNet {
    ops: Mutex<Vec<NetOp>>,
    direct_dns: Mutex<Vec<String>>,
}

impl FakeNet {
    pub fn new() -> Arc<Self> {
        Arc::default()
    }

    pub fn set_direct_dns(&self, servers: Vec<String>) {
        *lock(&self.direct_dns) = servers;
    }

    pub fn ops(&self) -> Vec<NetOp> {
        lock(&self.ops).clone()
    }

    pub fn applied(&self) -> Vec<NetApply> {
        self.ops()
            .into_iter()
            .filter_map(|o| match o {
                NetOp::Apply(a) => Some(a),
                _ => None,
            })
            .collect()
    }

    pub fn torn_down(&self) -> usize {
        self.ops().iter().filter(|o| **o == NetOp::Teardown).count()
    }

    pub fn bypassed(&self) -> Vec<String> {
        self.ops()
            .into_iter()
            .filter_map(|o| match o {
                NetOp::AddBypass(h) => Some(h),
                _ => None,
            })
            .collect()
    }

    pub fn ipv6_addresses(&self) -> Vec<Ipv6Addr> {
        self.ops()
            .into_iter()
            .filter_map(|o| match o {
                NetOp::ConfigureIpv6 { address, .. } => Some(address),
                _ => None,
            })
            .collect()
    }

    pub fn socks_ifaces(&self) -> Vec<String> {
        self.ops()
            .into_iter()
            .filter_map(|o| match o {
                NetOp::ApplySocks { iface, .. } => Some(iface),
                _ => None,
            })
            .collect()
    }

    pub fn dynamic_rules(&self) -> Vec<(String, RoutingAction)> {
        self.ops()
            .into_iter()
            .filter_map(|o| match o {
                NetOp::DynamicRule { ip, action } => Some((ip, action)),
                _ => None,
            })
            .collect()
    }

    pub fn routing_applied(&self) -> Vec<Option<RoutingConfig>> {
        self.applied().into_iter().map(|a| a.routing).collect()
    }

    fn record(&self, op: NetOp) {
        lock(&self.ops).push(op);
    }
}

impl NetConfiguring for FakeNet {
    fn apply(&self, request: &NetApply) -> Result<(), PlatformError> {
        self.record(NetOp::Apply(request.clone()));
        Ok(())
    }

    fn add_bypass(&self, host: &str) {
        self.record(NetOp::AddBypass(host.to_string()));
    }

    fn configure_ipv6(&self, address: Ipv6Addr, prefix_length: usize) {
        self.record(NetOp::ConfigureIpv6 { address, prefix_length });
    }

    fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction) {
        self.record(NetOp::DynamicRule { ip: ip.to_string(), action });
    }

    fn direct_dns_servers(&self) -> Vec<String> {
        lock(&self.direct_dns).clone()
    }

    fn apply_socks(&self, iface: &str, _lease: &Lease, mtu_override: Option<i64>) -> Result<(), PlatformError> {
        self.record(NetOp::ApplySocks { iface: iface.to_string(), mtu_override });
        Ok(())
    }

    fn teardown(&self) {
        self.record(NetOp::Teardown);
    }
}
