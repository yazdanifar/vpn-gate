//! `NetConfiguring` for Android: nothing is run on the device. `apply` computes the [`TunnelPlan`] and asks the host to
//! establish the tunnel; the host owns the routes and DNS from then on, and tearing the tun down removes them all.

use std::sync::Arc;

use vpngate_core::routing_rule::{RoutingAction, RoutingRuleType};

use super::{Link, TunnelPlan};
use crate::{Lease, NetApply, NetConfiguring, PlatformError};

const DEFAULT_MTU: u16 = 1400;

fn ip_string(v: u32) -> String {
    std::net::Ipv4Addr::from(v).to_string()
}

fn mtu_for(request: &NetApply) -> u16 {
    request
        .mtu_override
        .filter(|m| (576..=1500).contains(m))
        .map(|m| m as u16)
        .or(request.lease.mtu.filter(|m| (576..=1500).contains(m)))
        .unwrap_or(DEFAULT_MTU)
}

/// `1.2.3.4` → `1.2.3.4/32`; a CIDR is kept; IPv6 and anything unparsable is skipped.
fn ipv4_route(value: &str) -> Option<String> {
    let (ip, len) = match value.split_once('/') {
        Some((ip, len)) => (ip, len.parse::<u8>().ok()?),
        None => (value, 32),
    };
    let ip: std::net::Ipv4Addr = ip.trim().parse().ok()?;
    (len <= 32).then(|| format!("{ip}/{len}"))
}

fn prefix_length(mask: u32) -> u8 {
    mask.count_ones() as u8
}

/// The plan for a full tunnel. IP and CIDR rules that say `Direct` become excluded routes; every other routing
/// feature (block rules, a non-proxy default, domain rules) is left for the routing-rule mapping of the Android app.
pub fn plan_for(request: &NetApply) -> TunnelPlan {
    let lease: &Lease = &request.lease;
    let mut excluded = Vec::new();
    if let Some(routing) = &request.routing {
        for rule in routing.effective_rules() {
            let is_ip = matches!(rule.rule_type, RoutingRuleType::Ip | RoutingRuleType::Cidr);
            if rule.enabled && is_ip && rule.action == RoutingAction::Direct {
                if let Some(route) = ipv4_route(&rule.value) {
                    if !excluded.contains(&route) {
                        excluded.push(route);
                    }
                }
            }
        }
    }
    TunnelPlan {
        address: ip_string(lease.ip),
        prefix_length: prefix_length(lease.mask),
        routes: vec!["0.0.0.0/0".to_string()],
        excluded_routes: excluded,
        dns_servers: lease.dns.iter().map(|d| ip_string(*d)).collect(),
        mtu: mtu_for(request),
        block_ipv6: request.block_ipv6,
    }
}

pub struct AndroidNet {
    link: Arc<Link>,
}

impl AndroidNet {
    pub(crate) fn new(link: Arc<Link>) -> Self {
        AndroidNet { link }
    }
}

impl NetConfiguring for AndroidNet {
    fn apply(&self, request: &NetApply) -> Result<(), PlatformError> {
        self.link.establish(&plan_for(request))
    }

    fn apply_socks(&self, _iface: &str, _lease: &Lease, _mtu: Option<i64>) -> Result<(), PlatformError> {
        Err(PlatformError::new("SOCKS5 mode is not available on Android"))
    }

    fn teardown(&self) {
        // The tun's `close` ends the VPN interface; the host's routes and DNS go with it.
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_core::routing_rule::{RoutingConfig, RoutingRule};

    fn lease() -> Lease {
        Lease {
            ip: u32::from(std::net::Ipv4Addr::new(10, 21, 0, 7)),
            mask: 0xFFFF_0000,
            router: u32::from(std::net::Ipv4Addr::new(10, 21, 0, 1)),
            dns: vec![u32::from(std::net::Ipv4Addr::new(10, 21, 0, 1))],
            seconds: 3600,
            server_id: 0,
            mtu: None,
        }
    }

    fn request(routing: Option<RoutingConfig>) -> NetApply {
        NetApply {
            iface: "tun0".into(),
            lease: lease(),
            bypass_host: "1.2.3.4".into(),
            block_ipv6: true,
            mtu_override: None,
            routing,
            dns_proxy_address: None,
        }
    }

    #[test]
    fn full_tunnel_plan_uses_the_lease() {
        let plan = plan_for(&request(None));
        assert_eq!(plan.address, "10.21.0.7");
        assert_eq!(plan.prefix_length, 16);
        assert_eq!(plan.routes, ["0.0.0.0/0"]);
        assert!(plan.excluded_routes.is_empty());
        assert_eq!(plan.dns_servers, ["10.21.0.1"]);
        assert_eq!(plan.mtu, 1400);
        assert!(plan.block_ipv6);
    }

    #[test]
    fn mtu_prefers_a_valid_override_then_the_lease() {
        let mut r = request(None);
        r.lease.mtu = Some(1350);
        assert_eq!(plan_for(&r).mtu, 1350);
        r.mtu_override = Some(1280);
        assert_eq!(plan_for(&r).mtu, 1280);
        r.mtu_override = Some(100);
        assert_eq!(plan_for(&r).mtu, 1350);
    }

    #[test]
    fn direct_ip_rules_become_excluded_routes() {
        let cfg = RoutingConfig {
            bypass_private_networks: true,
            rules: vec![
                RoutingRule::new(RoutingRuleType::Ip, "8.8.8.8", RoutingAction::Direct),
                RoutingRule::new(RoutingRuleType::Cidr, "203.0.113.0/24", RoutingAction::Direct),
                RoutingRule::new(RoutingRuleType::Cidr, "198.51.100.0/24", RoutingAction::Block),
                RoutingRule::new(RoutingRuleType::Ip, "2001:db8::1", RoutingAction::Direct),
                RoutingRule::new(RoutingRuleType::DomainSuffix, "example.com", RoutingAction::Direct),
            ],
            ..RoutingConfig::default()
        };
        let plan = plan_for(&request(Some(cfg)));
        assert_eq!(plan.excluded_routes[..2], ["8.8.8.8/32", "203.0.113.0/24"]);
        assert!(plan.excluded_routes.contains(&"10.0.0.0/8".to_string()));
        assert!(!plan.excluded_routes.iter().any(|r| r.contains("198.51") || r.contains(':') || r.contains("example")));
    }

    #[test]
    fn disabled_rules_are_ignored() {
        let mut rule = RoutingRule::new(RoutingRuleType::Ip, "8.8.8.8", RoutingAction::Direct);
        rule.enabled = false;
        let cfg = RoutingConfig { rules: vec![rule], ..RoutingConfig::default() };
        assert!(plan_for(&request(Some(cfg))).excluded_routes.is_empty());
    }
}
