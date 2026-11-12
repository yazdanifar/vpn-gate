//! Interface address, routes and DNS for the tunnel (`NetConfig.swift`). Every change is recorded in the [`UndoLog`] as
//! it is made, so a daemon that died without tearing down can undo it at the next start ([`MacUndoer`]).

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};

use vpngate_core::routing_rule::RoutingAction;
use vpngate_core::validation;

use crate::{CommandRunner, DnsConfigurator, Lease, NetApply, NetConfiguring, PlatformError, UndoLog, UndoOp, Undoer};

const ROUTE: &str = "/sbin/route";
const IFCONFIG: &str = "/sbin/ifconfig";
/// `UndoOp.kind`: `args` are the arguments after `route -n delete`.
pub const UNDO_ROUTE: &str = "route-delete";
/// `UndoOp.kind`: take the tunnel's resolver out of configd again.
pub const UNDO_DNS: &str = "dns-remove";

#[derive(Debug, Clone, PartialEq, Eq)]
struct DefaultRoute {
    gateway: Option<String>,
    iface: String,
}

#[derive(Default)]
struct Active {
    iface: String,
    bypass_host: String,
    gateway: String,
    original: Option<DefaultRoute>,
    captured_dns: Vec<String>,
    /// How to undo each change that really happened, oldest first.
    undo: Vec<UndoOp>,
}

pub struct MacNetConfig {
    runner: Arc<dyn CommandRunner>,
    dns: Arc<dyn DnsConfigurator>,
    log: Arc<dyn UndoLog>,
    state: Mutex<Option<Active>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn valid_mtu(v: Option<i64>) -> Option<String> {
    v.filter(|m| (576..=1500).contains(m)).map(|m| m.to_string())
}

impl MacNetConfig {
    pub fn new(runner: Arc<dyn CommandRunner>, dns: Arc<dyn DnsConfigurator>, log: Arc<dyn UndoLog>) -> Self {
        MacNetConfig { runner, dns, log, state: Mutex::new(None) }
    }

    fn route(&self, args: &[&str]) -> crate::CommandOutput {
        let mut full = vec!["-n"];
        full.extend_from_slice(args);
        self.runner.run(ROUTE, &full)
    }

    /// Adds a route; remembers how to delete it only if `route add` succeeded, so teardown never removes a route that
    /// already existed (or that failed to be created).
    fn add_route(&self, active: &mut Active, add: &[&str], undo: &[&str]) {
        let mut args = vec!["add"];
        args.extend_from_slice(add);
        let r = self.route(&args);
        if r.status == 0 {
            let op = UndoOp::new(UNDO_ROUTE, undo);
            self.log.record(op.clone());
            active.undo.push(op);
        } else {
            println!("[route] add {} failed ({}): {}", add.join(" "), r.status, r.output.trim());
        }
    }

    fn remember(&self, active: &mut Active, op: UndoOp) {
        self.log.record(op.clone());
        active.undo.push(op);
    }

    /// Host route that keeps traffic to `host` on the original default path instead of the tunnel.
    fn add_bypass_route(&self, active: &mut Active, host: &str, via: &DefaultRoute) {
        match &via.gateway {
            Some(g) => self.add_route(active, &["-host", host, g], &["-host", host]),
            None => self.add_route(active, &["-host", host, "-interface", &via.iface], &["-host", host]),
        }
    }

    /// An explicit route for one IP/CIDR routing rule, overriding whatever the default capture (or its absence, with a
    /// `direct` default) would otherwise do with that address.
    fn add_rule_route(
        &self,
        active: &mut Active,
        value: &str,
        action: RoutingAction,
        iface: &str,
        gw: &str,
        original: Option<&DefaultRoute>,
    ) {
        let v6 = value.contains(':');
        let mut net: Vec<&str> = Vec::new();
        if v6 {
            net.push("-inet6");
        }
        net.push(if value.contains('/') { "-net" } else { "-host" });
        net.push(value);
        let with = |extra: &[&str]| -> Vec<String> { net.iter().chain(extra).map(|s| s.to_string()).collect() };
        let add = |this: &Self, active: &mut Active, extra: &[&str]| {
            let args = with(extra);
            let undo = with(&[]);
            let (a, u): (Vec<&str>, Vec<&str>) =
                (args.iter().map(String::as_str).collect(), undo.iter().map(String::as_str).collect());
            this.add_route(active, &a, &u);
        };
        match action {
            RoutingAction::Direct => {
                let Some(o) = original else { return };
                match &o.gateway {
                    Some(g) if !v6 => add(self, active, &[g]),
                    _ => add(self, active, &["-interface", &o.iface]),
                }
            }
            RoutingAction::Proxy => {
                if v6 {
                    add(self, active, &["-interface", iface])
                } else {
                    add(self, active, &[gw])
                }
            }
            RoutingAction::Block => add(self, active, &["-blackhole"]),
        }
    }

    fn address_interface(&self, iface: &str, lease: &Lease, mtu_override: Option<i64>) -> (String, String) {
        let (ip, gw) = (Ipv4Addr::from(lease.ip).to_string(), Ipv4Addr::from(lease.router).to_string());
        // The account's own MTU wins when valid; otherwise the DHCP lease's option 26 (the parser already ignores
        // out-of-range values there; checked again here for leases built elsewhere).
        let mtu =
            valid_mtu(mtu_override).or_else(|| valid_mtu(lease.mtu.map(i64::from))).unwrap_or_else(|| "1400".into());
        self.runner.run(IFCONFIG, &[iface, "inet", &ip, &gw, "netmask", "255.255.255.255", "mtu", &mtu, "up"]);
        (ip, gw)
    }

    fn default_route(&self) -> Option<DefaultRoute> {
        parse_default_route(&self.route(&["get", "default"]).output)
    }
}

/// `route -n get default` → gateway (none for a `link#` gateway) and interface.
fn parse_default_route(out: &str) -> Option<DefaultRoute> {
    let (mut gateway, mut iface) = (None, None);
    for line in out.lines() {
        let t = line.trim();
        if let Some(g) = t.strip_prefix("gateway:") {
            gateway = Some(g.trim().to_string());
        }
        if let Some(i) = t.strip_prefix("interface:") {
            iface = Some(i.trim().to_string());
        }
    }
    let gateway = gateway.filter(|g| !g.starts_with("link#"));
    iface.map(|iface| DefaultRoute { gateway, iface })
}

impl NetConfiguring for MacNetConfig {
    fn apply(&self, request: &NetApply) -> Result<(), PlatformError> {
        let mut guard = lock(&self.state);
        let original = self.default_route();
        let iface = request.iface.as_str();
        let (ip, gw) = self.address_interface(iface, &request.lease, request.mtu_override);
        let routing = request.routing.clone().unwrap_or_default();
        let mut active = Active {
            iface: iface.to_string(),
            bypass_host: request.bypass_host.clone(),
            gateway: gw.clone(),
            original: original.clone(),
            ..Active::default()
        };
        // Keep the tunnel's own transport outside the tunnel (never for loopback/link-local proxies).
        if !validation::is_local_address(&request.bypass_host) {
            if let Some(o) = &original {
                self.add_bypass_route(&mut active, &request.bypass_host, o);
            }
        }
        self.add_route(&mut active, &["-host", &gw, "-interface", iface], &["-host", &gw]);

        let rules = routing.effective_rules();
        let route_rules = |this: &Self, active: &mut Active, keep: fn(RoutingAction) -> bool| {
            for rule in rules.iter().filter(|r| r.enabled && !r.rule_type.is_domain() && keep(r.action)) {
                this.add_rule_route(active, &rule.value, rule.action, iface, &gw, original.as_ref());
            }
        };
        if routing.default_action == RoutingAction::Direct {
            // Nothing is captured: the original default route is left alone, so unmatched traffic keeps going the way
            // it always did. Explicit `proxy` rules get a specific route back into the tunnel instead.
            route_rules(self, &mut active, |a| a != RoutingAction::Direct);
        } else {
            self.add_route(&mut active, &["-net", "0.0.0.0/1", &gw], &["-net", "0.0.0.0/1", &gw]);
            self.add_route(&mut active, &["-net", "128.0.0.0/1", &gw], &["-net", "128.0.0.0/1", &gw]);
            // Everything is captured by default: explicit `direct`/`block` rules carve an exception back out.
            route_rules(self, &mut active, |a| a != RoutingAction::Proxy);
        }
        // Both halves of the IPv6 space point at the tunnel either way, so native IPv6 never leaks around it. With
        // `block_ipv6` the tun reader drops every non-IPv4 packet and dual-stack sites fall back to IPv4 through the
        // VPN; without it the bridge forwards IPv6 once `configure_ipv6` has given the interface an address, and drops
        // it while the hub offers no IPv6 router.
        for half in ["::/1", "8000::/1"] {
            self.add_route(&mut active, &["-inet6", half, "-interface", iface], &["-inet6", half, "-interface", iface]);
        }

        // Captured before the resolver is switched over, so a `direct` domain rule can still be resolved by the
        // physical network's own DNS (never the tunnel's) once the DNS proxy is listening.
        if !routing.is_empty() {
            active.captured_dns =
                self.dns.current_servers().into_iter().filter(|s| validation::is_ipv4_literal(s)).collect();
            if let Some(o) = &original {
                for server in active.captured_dns.clone().iter().filter(|s| !validation::is_local_address(s)) {
                    self.add_bypass_route(&mut active, server, o);
                }
            }
        }

        if !request.lease.dns.is_empty() {
            let published = match &request.dns_proxy_address {
                Some(a) => vec![a.clone()],
                None => request.lease.dns.iter().map(|d| Ipv4Addr::from(*d).to_string()).collect(),
            };
            if self.dns.set(&published, iface, &ip, &gw) {
                self.remember(&mut active, UndoOp::new(UNDO_DNS, &[]));
            }
        }
        *guard = Some(active);
        Ok(())
    }

    /// SOCKS mode: the interface gets its address, and a default route that exists only for sockets bound to it
    /// (`-ifscope`). Nothing global changes: no unscoped route, no resolver, no IPv6 capture.
    fn apply_socks(&self, iface: &str, lease: &Lease, mtu_override: Option<i64>) -> Result<(), PlatformError> {
        let mut guard = lock(&self.state);
        let (_, gw) = self.address_interface(iface, lease, mtu_override);
        let mut active = Active { iface: iface.to_string(), gateway: gw.clone(), ..Active::default() };
        self.add_route(
            &mut active,
            &["-ifscope", iface, "-host", &gw, "-interface", iface],
            &["-ifscope", iface, "-host", &gw],
        );
        self.add_route(&mut active, &["-ifscope", iface, "default", &gw], &["-ifscope", iface, "default", &gw]);
        *guard = Some(active);
        Ok(())
    }

    fn direct_dns_servers(&self) -> Vec<String> {
        lock(&self.state).as_ref().map(|a| a.captured_dns.clone()).unwrap_or_default()
    }

    fn add_bypass(&self, host: &str) {
        // The host ends up as a `route` argument, so only a plain IPv4 literal is accepted.
        let mut guard = lock(&self.state);
        let Some(active) = guard.as_mut() else { return };
        let Some(original) = active.original.clone() else { return };
        if !validation::is_ipv4_literal(host) || validation::is_local_address(host) || host == active.bypass_host {
            return;
        }
        self.add_bypass_route(active, host, &original);
    }

    fn configure_ipv6(&self, address: Ipv6Addr, prefix_length: usize) {
        // Never a placeholder, multicast or link-local address (the kernel already has its own link-local one).
        let guard = lock(&self.state);
        let Some(active) = guard.as_ref() else { return };
        let octets = address.octets();
        let link_local = octets[0] == 0xfe && octets[1] & 0xc0 == 0x80;
        if !(1..=128).contains(&prefix_length) || address.is_unspecified() || address.is_multicast() || link_local {
            return;
        }
        let (text, prefix) = (address.to_string(), prefix_length.to_string());
        let r = self.runner.run(IFCONFIG, &[&active.iface, "inet6", &text, "prefixlen", &prefix]);
        if r.status != 0 {
            println!("[ifconfig] inet6 {text} failed ({}): {}", r.status, r.output.trim());
        }
        // The address disappears with the utun, so there is nothing to undo or persist.
    }

    /// Routes a single resolved address (from the DNS proxy) the way a domain rule asked for. A no-op before `apply`
    /// or when the address does not parse as a bare IPv4/IPv6 literal.
    fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction) {
        let mut guard = lock(&self.state);
        let Some(active) = guard.as_mut() else { return };
        if active.gateway.is_empty() || !validation::is_ip_literal(ip) {
            return;
        }
        let (iface, gw, original) = (active.iface.clone(), active.gateway.clone(), active.original.clone());
        self.add_rule_route(active, ip, action, &iface, &gw, original.as_ref());
    }

    fn teardown(&self) {
        let Some(active) = lock(&self.state).take() else { return };
        let undoer = MacUndoer::new(self.runner.clone(), self.dns.clone());
        for op in active.undo.iter().rev() {
            undoer.undo(op);
        }
        self.log.clear();
    }
}

/// Reverts [`MacNetConfig`] changes from the persisted undo list.
pub struct MacUndoer {
    runner: Arc<dyn CommandRunner>,
    dns: Arc<dyn DnsConfigurator>,
}

impl MacUndoer {
    pub fn new(runner: Arc<dyn CommandRunner>, dns: Arc<dyn DnsConfigurator>) -> Self {
        MacUndoer { runner, dns }
    }
}

impl Undoer for MacUndoer {
    fn undo(&self, op: &UndoOp) {
        match op.kind.as_str() {
            UNDO_ROUTE => {
                let mut args = vec!["-n", "delete"];
                args.extend(op.args.iter().map(String::as_str));
                self.runner.run(ROUTE, &args);
            }
            UNDO_DNS => self.dns.remove(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
