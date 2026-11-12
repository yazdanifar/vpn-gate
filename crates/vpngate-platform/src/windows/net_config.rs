//! Interface address, routes and DNS for the Wintun adapter (the Windows twin of `macos::net_config`). Every route is
//! recorded in the [`UndoLog`] as it is made, so a service that died without tearing down can undo it at the next
//! start ([`WinUndoer`]).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};

use vpngate_core::routing_rule::RoutingAction;
use vpngate_core::validation;

use super::ip_helper::{BestRoute, IpHelper, Route};
use crate::{DnsConfigurator, Lease, NetApply, NetConfiguring, PlatformError, UndoLog, UndoOp, Undoer};

/// `UndoOp.kind`: `args` are [`Route::to_args`].
pub const UNDO_ROUTE: &str = "route-delete";
/// `UndoOp.kind`: take the tunnel's resolver out again.
pub const UNDO_DNS: &str = "dns-remove";

/// Tunnel routes win over the physical default by being more specific; this keeps them ahead of any equal prefix.
const TUNNEL_METRIC: u32 = 1;
/// SOCKS mode: a default route only sockets pinned to the adapter (`IP_UNICAST_IF`) can pick, never the system.
const SCOPED_DEFAULT_METRIC: u32 = 9000;
/// Used to learn the physical path when the relay itself is a loopback address.
const PROBE: Ipv4Addr = Ipv4Addr::new(1, 1, 1, 1);

#[derive(Default)]
struct Active {
    if_index: u32,
    bypass_host: String,
    gateway: Option<Ipv4Addr>,
    original: Option<BestRoute>,
    captured_dns: Vec<String>,
    undo: Vec<UndoOp>,
}

pub struct WinNetConfig {
    api: Arc<dyn IpHelper>,
    dns: Arc<dyn DnsConfigurator>,
    log: Arc<dyn UndoLog>,
    state: Mutex<Option<Active>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn valid_mtu(v: Option<i64>) -> Option<u32> {
    v.filter(|m| (576..=1500).contains(m)).map(|m| m as u32)
}

fn v4(ip: &str) -> Option<Ipv4Addr> {
    ip.parse().ok()
}

impl WinNetConfig {
    pub fn new(api: Arc<dyn IpHelper>, dns: Arc<dyn DnsConfigurator>, log: Arc<dyn UndoLog>) -> Self {
        WinNetConfig { api, dns, log, state: Mutex::new(None) }
    }

    /// Adds a route; remembers how to delete it only if it was created, so teardown never removes a route that
    /// already existed (`CreateIpForwardEntry2` fails with `ERROR_OBJECT_ALREADY_EXISTS`) or failed to be created.
    fn add_route(&self, active: &mut Active, route: Route) {
        match self.api.add_route(&route) {
            Ok(()) => {
                let op = UndoOp { kind: UNDO_ROUTE.into(), args: route.to_args() };
                self.log.record(op.clone());
                active.undo.push(op);
            }
            Err(e) => println!("[route] add {} failed: {e}", route.to_args().join(" ")),
        }
    }

    fn remember(&self, active: &mut Active, op: UndoOp) {
        self.log.record(op.clone());
        active.undo.push(op);
    }

    fn route(dest: IpAddr, prefix: u8, next_hop: Option<IpAddr>, if_index: u32, metric: u32) -> Route {
        Route { dest, prefix, next_hop, if_index, metric }
    }

    /// Host route that keeps traffic to `host` on the original path instead of the tunnel.
    fn add_bypass_route(&self, active: &mut Active, host: Ipv4Addr, via: &BestRoute) {
        let route = Self::route(host.into(), 32, via.next_hop.map(IpAddr::V4), via.if_index, TUNNEL_METRIC);
        self.add_route(active, route);
    }

    /// An explicit route for one IP/CIDR routing rule, overriding whatever the default capture (or its absence, with a
    /// `direct` default) would otherwise do with that address.
    fn add_rule_route(&self, active: &mut Active, value: &str, action: RoutingAction) {
        let (addr, prefix) = match value.split_once('/') {
            Some((a, p)) => (a, p.parse::<u8>().ok()),
            None => (value, None),
        };
        let Ok(dest) = addr.parse::<IpAddr>() else { return };
        let max = if dest.is_ipv6() { 128 } else { 32 };
        let prefix = prefix.unwrap_or(max);
        if prefix > max {
            return;
        }
        let (tunnel, gw, original) = (active.if_index, active.gateway, active.original.clone());
        let route = match action {
            RoutingAction::Direct => {
                let Some(o) = original else { return };
                match (dest, o.next_hop) {
                    (IpAddr::V4(_), hop) => Self::route(dest, prefix, hop.map(IpAddr::V4), o.if_index, TUNNEL_METRIC),
                    (IpAddr::V6(_), _) => Self::route(dest, prefix, None, o.if_index, TUNNEL_METRIC),
                }
            }
            RoutingAction::Proxy => match dest {
                IpAddr::V4(_) => Self::route(dest, prefix, gw.map(IpAddr::V4), tunnel, TUNNEL_METRIC),
                IpAddr::V6(_) => Self::route(dest, prefix, None, tunnel, TUNNEL_METRIC),
            },
            // Windows has no blackhole flag: a route out of the loopback pseudo-interface to a non-local address is
            // discarded by the stack.
            RoutingAction::Block => {
                let Some(lo) = self.api.best_route(Ipv4Addr::LOCALHOST) else { return };
                Self::route(dest, prefix, None, lo.if_index, TUNNEL_METRIC)
            }
        };
        self.add_route(active, route);
    }

    fn address_interface(&self, if_index: u32, lease: &Lease, mtu_override: Option<i64>) -> Ipv4Addr {
        let (ip, gw) = (Ipv4Addr::from(lease.ip), Ipv4Addr::from(lease.router));
        let mtu = valid_mtu(mtu_override).or_else(|| valid_mtu(lease.mtu.map(i64::from))).unwrap_or(1400);
        if let Err(e) = self.api.add_address(if_index, ip.into(), 32) {
            println!("[ip] add address {ip} failed: {e}");
        }
        if let Err(e) = self.api.set_mtu(if_index, false, mtu) {
            println!("[ip] set mtu {mtu} failed: {e}");
        }
        gw
    }

    fn physical_path(&self, bypass_host: &str) -> Option<BestRoute> {
        let target = v4(bypass_host).filter(|h| !validation::is_local_address(&h.to_string())).unwrap_or(PROBE);
        self.api.best_route(target)
    }
}

impl NetConfiguring for WinNetConfig {
    fn apply(&self, request: &NetApply) -> Result<(), PlatformError> {
        let mut guard = lock(&self.state);
        let if_index = self
            .api
            .if_index(&request.iface)
            .ok_or_else(|| PlatformError::new(format!("adapter {} not found", request.iface)))?;
        // Learned before any route is added, so it is still the physical path.
        let original = self.physical_path(&request.bypass_host);
        let gw = self.address_interface(if_index, &request.lease, request.mtu_override);
        let routing = request.routing.clone().unwrap_or_default();
        let mut active = Active {
            if_index,
            bypass_host: request.bypass_host.clone(),
            gateway: Some(gw),
            original: original.clone(),
            ..Active::default()
        };
        // Keep the tunnel's own transport outside the tunnel (never for loopback/link-local proxies).
        if !validation::is_local_address(&request.bypass_host) {
            if let (Some(o), Some(host)) = (&original, v4(&request.bypass_host)) {
                self.add_bypass_route(&mut active, host, o);
            }
        }
        self.add_route(&mut active, Self::route(gw.into(), 32, None, if_index, TUNNEL_METRIC));

        let rules = routing.effective_rules();
        let route_rules = |this: &Self, active: &mut Active, keep: fn(RoutingAction) -> bool| {
            for rule in rules.iter().filter(|r| r.enabled && !r.rule_type.is_domain() && keep(r.action)) {
                this.add_rule_route(active, &rule.value, rule.action);
            }
        };
        if routing.default_action == RoutingAction::Direct {
            route_rules(self, &mut active, |a| a != RoutingAction::Direct);
        } else {
            for half in [Ipv4Addr::new(0, 0, 0, 0), Ipv4Addr::new(128, 0, 0, 0)] {
                self.add_route(&mut active, Self::route(half.into(), 1, Some(gw.into()), if_index, TUNNEL_METRIC));
            }
            route_rules(self, &mut active, |a| a != RoutingAction::Proxy);
        }
        // Both halves of the IPv6 space point at the tunnel either way, so native IPv6 never leaks around it.
        for half in [Ipv6Addr::UNSPECIFIED, Ipv6Addr::new(0x8000, 0, 0, 0, 0, 0, 0, 0)] {
            self.add_route(&mut active, Self::route(half.into(), 1, None, if_index, TUNNEL_METRIC));
        }

        if !routing.is_empty() {
            active.captured_dns =
                self.dns.current_servers().into_iter().filter(|s| validation::is_ipv4_literal(s)).collect();
            if let Some(o) = &original {
                for server in active.captured_dns.clone().iter().filter(|s| !validation::is_local_address(s)) {
                    if let Some(host) = v4(server) {
                        self.add_bypass_route(&mut active, host, o);
                    }
                }
            }
        }

        if !request.lease.dns.is_empty() {
            let published = match &request.dns_proxy_address {
                Some(a) => vec![a.clone()],
                None => request.lease.dns.iter().map(|d| Ipv4Addr::from(*d).to_string()).collect(),
            };
            if self.dns.set(&published, &request.iface, &Ipv4Addr::from(request.lease.ip).to_string(), &gw.to_string())
            {
                self.remember(&mut active, UndoOp::new(UNDO_DNS, &[]));
            }
        }
        *guard = Some(active);
        Ok(())
    }

    /// SOCKS mode: the adapter gets its address and a high-metric default route that only sockets pinned to it can
    /// pick. Nothing global changes: no capture, no resolver, no IPv6.
    fn apply_socks(&self, iface: &str, lease: &Lease, mtu_override: Option<i64>) -> Result<(), PlatformError> {
        let mut guard = lock(&self.state);
        let if_index =
            self.api.if_index(iface).ok_or_else(|| PlatformError::new(format!("adapter {iface} not found")))?;
        let gw = self.address_interface(if_index, lease, mtu_override);
        let mut active = Active { if_index, gateway: Some(gw), ..Active::default() };
        self.add_route(&mut active, Self::route(gw.into(), 32, None, if_index, TUNNEL_METRIC));
        let any = Ipv4Addr::UNSPECIFIED;
        self.add_route(&mut active, Self::route(any.into(), 0, Some(gw.into()), if_index, SCOPED_DEFAULT_METRIC));
        *guard = Some(active);
        Ok(())
    }

    fn direct_dns_servers(&self) -> Vec<String> {
        lock(&self.state).as_ref().map(|a| a.captured_dns.clone()).unwrap_or_default()
    }

    fn add_bypass(&self, host: &str) {
        let mut guard = lock(&self.state);
        let Some(active) = guard.as_mut() else { return };
        let Some(original) = active.original.clone() else { return };
        if !validation::is_ipv4_literal(host) || validation::is_local_address(host) || host == active.bypass_host {
            return;
        }
        if let Some(host) = v4(host) {
            self.add_bypass_route(active, host, &original);
        }
    }

    fn configure_ipv6(&self, address: Ipv6Addr, prefix_length: usize) {
        let guard = lock(&self.state);
        let Some(active) = guard.as_ref() else { return };
        let octets = address.octets();
        let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
        if !(1..=128).contains(&prefix_length) || address.is_unspecified() || address.is_multicast() || link_local {
            return;
        }
        if let Err(e) = self.api.add_address(active.if_index, address.into(), prefix_length as u8) {
            println!("[ip] add address {address} failed: {e}");
        }
        // The address disappears with the adapter, so there is nothing to undo or persist.
    }

    fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction) {
        let mut guard = lock(&self.state);
        let Some(active) = guard.as_mut() else { return };
        if active.gateway.is_none() || !validation::is_ip_literal(ip) {
            return;
        }
        self.add_rule_route(active, ip, action);
    }

    fn teardown(&self) {
        let Some(active) = lock(&self.state).take() else { return };
        let undoer = WinUndoer::new(self.api.clone(), self.dns.clone());
        for op in active.undo.iter().rev() {
            undoer.undo(op);
        }
        self.log.clear();
    }
}

/// Reverts [`WinNetConfig`] changes from the persisted undo list.
pub struct WinUndoer {
    api: Arc<dyn IpHelper>,
    dns: Arc<dyn DnsConfigurator>,
}

impl WinUndoer {
    pub fn new(api: Arc<dyn IpHelper>, dns: Arc<dyn DnsConfigurator>) -> Self {
        WinUndoer { api, dns }
    }
}

impl Undoer for WinUndoer {
    fn undo(&self, op: &UndoOp) {
        match op.kind.as_str() {
            UNDO_ROUTE => {
                if let Some(route) = Route::from_args(&op.args) {
                    let _ = self.api.delete_route(&route);
                }
            }
            UNDO_DNS => self.dns.remove(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
