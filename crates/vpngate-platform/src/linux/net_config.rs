//! Interface address, routes and DNS for the tunnel through iproute2 (the Linux twin of `macos::net_config`). Every
//! change is recorded in the [`UndoLog`] as it is made, so a daemon that died without tearing down can undo it at the
//! next start ([`LinuxUndoer`]).
//!
//! macOS needs `-ifscope` routes for SOCKS mode; here a policy rule does it: `oif <tun> lookup <table>` sends only
//! sockets pinned to the tunnel (`SO_BINDTODEVICE`) to a table whose default route is the tunnel.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, MutexGuard};

use vpngate_core::routing_rule::RoutingAction;
use vpngate_core::validation;

use crate::{CommandRunner, DnsConfigurator, Lease, NetApply, NetConfiguring, PlatformError, UndoLog, UndoOp, Undoer};

const IP: &str = "/usr/sbin/ip";
/// `UndoOp.kind`: `args` are the whole `ip` command line that deletes a route (`[-6] route del ...`).
pub const UNDO_ROUTE: &str = "route-del";
/// `UndoOp.kind`: `args` are the `ip rule del ...` command line.
pub const UNDO_RULE: &str = "rule-del";
/// `UndoOp.kind`: take the tunnel's resolver out again.
pub const UNDO_DNS: &str = "dns-remove";
/// The routing table SOCKS mode sends interface-bound sockets to.
pub const SOCKS_TABLE: &str = "2330";

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

pub struct LinuxNetConfig {
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

/// `1.2.3.4` → `1.2.3.4/32`, `::1` → `::1/128`; a CIDR is kept.
fn with_prefix(value: &str) -> String {
    if value.contains('/') {
        value.to_string()
    } else if value.contains(':') {
        format!("{value}/128")
    } else {
        format!("{value}/32")
    }
}

impl LinuxNetConfig {
    pub fn new(runner: Arc<dyn CommandRunner>, dns: Arc<dyn DnsConfigurator>, log: Arc<dyn UndoLog>) -> Self {
        LinuxNetConfig { runner, dns, log, state: Mutex::new(None) }
    }

    fn remember(&self, active: &mut Active, op: UndoOp) {
        self.log.record(op.clone());
        active.undo.push(op);
    }

    /// Runs `ip <args>` and, only if it succeeded, remembers `undo` so teardown never removes something that already
    /// existed (or failed to be created).
    fn add(&self, active: &mut Active, kind: &str, args: &[&str], undo: &[&str]) {
        let r = self.runner.run(IP, args);
        if r.status == 0 {
            self.remember(active, UndoOp::new(kind, undo));
        } else {
            println!("[ip] {} failed ({}): {}", args.join(" "), r.status, r.output.trim());
        }
    }

    /// `ip [-6] route add <spec>`, undone by `ip [-6] route del <undo>`.
    fn add_route(&self, active: &mut Active, v6: bool, spec: &[&str], undo: &[&str]) {
        let family: &[&str] = if v6 { &["-6"] } else { &[] };
        let build = |verb: &str, rest: &[&str]| -> Vec<String> {
            family.iter().chain(&["route", verb]).chain(rest).map(|s| s.to_string()).collect()
        };
        let (add, del) = (build("add", spec), build("del", undo));
        let (add, del): (Vec<&str>, Vec<&str>) =
            (add.iter().map(String::as_str).collect(), del.iter().map(String::as_str).collect());
        self.add(active, UNDO_ROUTE, &add, &del);
    }

    /// Host route that keeps traffic to `host` on the original default path instead of the tunnel.
    fn add_bypass_route(&self, active: &mut Active, host: &str, via: &DefaultRoute) {
        let target = with_prefix(host);
        match &via.gateway {
            Some(g) => {
                self.add_route(active, false, &[&target, "via", g, "dev", &via.iface], &[&target]);
            }
            None => self.add_route(active, false, &[&target, "dev", &via.iface], &[&target]),
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
        // The value ends up as an `ip` argument; an option-looking one would be read as a flag.
        if value.starts_with('-') {
            return;
        }
        let v6 = value.contains(':');
        let target = with_prefix(value);
        match action {
            RoutingAction::Direct => {
                let Some(o) = original else { return };
                match &o.gateway {
                    Some(g) if !v6 => self.add_route(active, v6, &[&target, "via", g, "dev", &o.iface], &[&target]),
                    _ => self.add_route(active, v6, &[&target, "dev", &o.iface], &[&target]),
                }
            }
            RoutingAction::Proxy => {
                if v6 {
                    self.add_route(active, v6, &[&target, "dev", iface], &[&target]);
                } else {
                    self.add_route(active, v6, &[&target, "via", gw, "dev", iface], &[&target]);
                }
            }
            RoutingAction::Block => self.add_route(active, v6, &["blackhole", &target], &["blackhole", &target]),
        }
    }

    /// Brings the interface up with the lease's address as a point-to-point pair with the router, which gives the
    /// router a host route for free.
    fn address_interface(&self, iface: &str, lease: &Lease, mtu_override: Option<i64>) -> (String, String) {
        let (ip, gw) = (Ipv4Addr::from(lease.ip).to_string(), Ipv4Addr::from(lease.router).to_string());
        let mtu =
            valid_mtu(mtu_override).or_else(|| valid_mtu(lease.mtu.map(i64::from))).unwrap_or_else(|| "1400".into());
        self.runner.run(IP, &["link", "set", "dev", iface, "mtu", &mtu, "up"]);
        let peer = format!("{gw}/32");
        let r = self.runner.run(IP, &["addr", "add", &ip, "peer", &peer, "dev", iface]);
        if r.status != 0 {
            println!("[ip] addr add {ip} failed ({}): {}", r.status, r.output.trim());
        }
        (ip, gw)
    }

    fn default_route(&self) -> Option<DefaultRoute> {
        parse_default_route(&self.runner.run(IP, &["-4", "route", "show", "default"]).output)
    }
}

/// `ip -4 route show default` → gateway (none for an on-link default) and device of the first line.
fn parse_default_route(out: &str) -> Option<DefaultRoute> {
    let line = out.lines().find(|l| l.trim_start().starts_with("default"))?;
    let mut words = line.split_whitespace();
    let (mut gateway, mut iface) = (None, None);
    while let Some(w) = words.next() {
        match w {
            "via" => gateway = words.next().map(str::to_string),
            "dev" => iface = words.next().map(str::to_string),
            _ => {}
        }
    }
    iface.map(|iface| DefaultRoute { gateway, iface })
}

impl NetConfiguring for LinuxNetConfig {
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

        let rules = routing.effective_rules();
        let route_rules = |this: &Self, active: &mut Active, keep: fn(RoutingAction) -> bool| {
            for rule in rules.iter().filter(|r| r.enabled && !r.rule_type.is_domain() && keep(r.action)) {
                this.add_rule_route(active, &rule.value, rule.action, iface, &gw, original.as_ref());
            }
        };
        if routing.default_action == RoutingAction::Direct {
            // Nothing is captured: the original default route is left alone. Explicit `proxy` rules get a specific
            // route back into the tunnel instead.
            route_rules(self, &mut active, |a| a != RoutingAction::Direct);
        } else {
            // Two halves beat the real default route by prefix length without replacing it.
            for half in ["0.0.0.0/1", "128.0.0.0/1"] {
                self.add_route(&mut active, false, &[half, "via", &gw, "dev", iface], &[half]);
            }
            route_rules(self, &mut active, |a| a != RoutingAction::Proxy);
        }
        // Both halves of the IPv6 space point at the tunnel either way, so native IPv6 never leaks around it.
        for half in ["::/1", "8000::/1"] {
            self.add_route(&mut active, true, &[half, "dev", iface], &[half]);
        }

        // Captured before the resolver is switched over, so a `direct` domain rule can still be resolved by the
        // physical network's own DNS once the DNS proxy is listening.
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

    /// SOCKS mode: the interface gets its address, and a default route in a table that only sockets pinned to it reach
    /// (`oif` rule). Nothing global changes: no main-table route, no resolver, no IPv6 capture.
    fn apply_socks(&self, iface: &str, lease: &Lease, mtu_override: Option<i64>) -> Result<(), PlatformError> {
        let mut guard = lock(&self.state);
        let (_, gw) = self.address_interface(iface, lease, mtu_override);
        let mut active = Active { iface: iface.to_string(), gateway: gw.clone(), ..Active::default() };
        self.add_route(
            &mut active,
            false,
            &["default", "via", &gw, "dev", iface, "table", SOCKS_TABLE],
            &["default", "via", &gw, "dev", iface, "table", SOCKS_TABLE],
        );
        self.add(
            &mut active,
            UNDO_RULE,
            &["rule", "add", "oif", iface, "lookup", SOCKS_TABLE],
            &["rule", "del", "oif", iface, "lookup", SOCKS_TABLE],
        );
        *guard = Some(active);
        Ok(())
    }

    fn direct_dns_servers(&self) -> Vec<String> {
        lock(&self.state).as_ref().map(|a| a.captured_dns.clone()).unwrap_or_default()
    }

    fn add_bypass(&self, host: &str) {
        // The host ends up as an `ip` argument, so only a plain IPv4 literal is accepted.
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
        let cidr = format!("{address}/{prefix_length}");
        let r = self.runner.run(IP, &["-6", "addr", "add", &cidr, "dev", &active.iface]);
        if r.status != 0 {
            println!("[ip] -6 addr add {cidr} failed ({}): {}", r.status, r.output.trim());
        }
        // The address disappears with the tun device, so there is nothing to undo or persist.
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
        let undoer = LinuxUndoer::new(self.runner.clone(), self.dns.clone());
        for op in active.undo.iter().rev() {
            undoer.undo(op);
        }
        self.log.clear();
    }
}

/// Reverts [`LinuxNetConfig`] changes from the persisted undo list.
pub struct LinuxUndoer {
    runner: Arc<dyn CommandRunner>,
    dns: Arc<dyn DnsConfigurator>,
}

impl LinuxUndoer {
    pub fn new(runner: Arc<dyn CommandRunner>, dns: Arc<dyn DnsConfigurator>) -> Self {
        LinuxUndoer { runner, dns }
    }
}

impl Undoer for LinuxUndoer {
    fn undo(&self, op: &UndoOp) {
        match op.kind.as_str() {
            UNDO_ROUTE | UNDO_RULE => {
                let args: Vec<&str> = op.args.iter().map(String::as_str).collect();
                self.runner.run(IP, &args);
            }
            UNDO_DNS => self.dns.remove(),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests;
