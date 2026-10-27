//! Everything that reaches the route table or the network stack from an IPC request must pass this first
//! (`IPCServer.validate`, `IPCServer.swift:164-190`).

use vpngate_core::ipc::{HelperRequest, TunnelMode};
use vpngate_core::routing_rule::{RoutingConfig, RoutingRule};
use vpngate_core::validation;
use vpngate_net::cert_auth::{MAX_CERT_BYTES, MAX_KEY_BYTES};

const MAX_TICKET_BYTES: usize = 1024;

/// `None` when the request may reach the session; otherwise the reason it is rejected.
pub fn validate(r: &HelperRequest) -> Option<String> {
    let host = r.config.as_ref().map(|c| c.host.as_str()).or(r.host.as_deref());
    if !host.is_some_and(validation::is_valid_host) {
        return Some("invalid host".into());
    }
    if let Some(port) = r.port {
        if !validation::is_valid_port(Some(port)) {
            return Some("invalid port".into());
        }
    }
    if let Some(config) = &r.config {
        for &p in &config.ports {
            if !validation::is_valid_port(Some(p)) {
                return Some(format!("invalid port {p}"));
            }
        }
        if config.cert_der.as_ref().is_some_and(|c| c.len() > MAX_CERT_BYTES) {
            return Some("certificate too large".into());
        }
        if config.private_key_der.as_ref().is_some_and(|k| k.len() > MAX_KEY_BYTES) {
            return Some("private key too large".into());
        }
        if config.ticket.as_ref().is_some_and(|t| t.len() > MAX_TICKET_BYTES) {
            return Some("ticket too large".into());
        }
        if !validation::is_valid_identity_field(&config.hub_name) {
            return Some("invalid hub name".into());
        }
        if !validation::is_valid_identity_field(&config.user_name) {
            return Some("invalid user name".into());
        }
    }
    let proxy = r.config.as_ref().map(|c| &c.proxy).or(r.proxy.as_ref());
    if let Some(problem) = proxy.and_then(validate_proxy) {
        return Some(problem);
    }
    // Only SOCKS mode uses the port; a stale value saved in the app must not block full-tunnel connects.
    let socks_port = r.config.as_ref().map(|c| c.socks_port).or(r.socks_port);
    let mode = r.config.as_ref().map(|c| c.tunnel_mode).or(r.tunnel_mode).unwrap_or(TunnelMode::FullTunnel);
    if mode == TunnelMode::SocksProxy && socks_port.is_some_and(|p| !(1024..=65535).contains(&p)) {
        return Some("invalid SOCKS port (use 1024-65535)".into());
    }
    if let Some(routing) = r.config.as_ref().and_then(|c| c.routing.as_ref()).or(r.routing.as_ref()) {
        if let Some(problem) = validate_routing(routing) {
            return Some(problem);
        }
    }
    None
}

/// A proxy that is switched off is not looked at.
pub fn validate_proxy(p: &vpngate_core::ipc::ProxySettings) -> Option<String> {
    if p.kind == vpngate_core::ipc::ProxyKind::None {
        return None;
    }
    if !validation::is_valid_host(&p.host) {
        return Some("invalid proxy host".into());
    }
    if !validation::is_valid_port(Some(p.port)) {
        return Some("invalid proxy port".into());
    }
    None
}

/// Every rule must be well-formed before it reaches `route` or the DNS proxy's regex engine.
fn validate_routing(cfg: &RoutingConfig) -> Option<String> {
    cfg.rules
        .iter()
        .find_map(|rule: &RoutingRule| rule.error().map(|e| format!("routing rule \"{}\": {e}", rule.value)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_core::ipc::{ConnectConfig, ProxyKind, ProxySettings};
    use vpngate_core::routing_rule::{RoutingAction, RoutingRuleType};

    fn req(host: &str) -> HelperRequest {
        let mut r = HelperRequest::new("connect");
        r.host = Some(host.into());
        r
    }

    #[test]
    fn rejects_bad_hosts_and_ports() {
        for h in ["-interface", "1.2.3.4; reboot", "", "a b"] {
            assert_eq!(validate(&req(h)).as_deref(), Some("invalid host"), "{h}");
        }
        for p in [0, 70000, -1] {
            let mut r = req("1.2.3.4");
            r.port = Some(p);
            assert_eq!(validate(&r).as_deref(), Some("invalid port"));
        }
        assert_eq!(validate(&HelperRequest::new("connect")).as_deref(), Some("invalid host"));
        let mut ok = req("vpn1.example.net");
        ok.port = Some(443);
        assert_eq!(validate(&ok), None);
    }

    #[test]
    fn rejects_bad_proxy() {
        let mut r = req("1.2.3.4");
        r.proxy = Some(ProxySettings { kind: ProxyKind::Http, host: "-x".into(), port: 80, ..Default::default() });
        assert_eq!(validate(&r).as_deref(), Some("invalid proxy host"));
        r.proxy = Some(ProxySettings { kind: ProxyKind::Http, host: "p".into(), port: 99999, ..Default::default() });
        assert_eq!(validate(&r).as_deref(), Some("invalid proxy port"));
        // a proxy that is switched off is not looked at
        r.proxy = Some(ProxySettings { kind: ProxyKind::None, host: "-x".into(), port: 0, ..Default::default() });
        assert_eq!(validate(&r), None);
    }

    #[test]
    fn config_fields() {
        let with = |f: &dyn Fn(&mut ConnectConfig)| {
            let mut c = ConnectConfig::new("1.2.3.4");
            f(&mut c);
            let mut r = HelperRequest::new("connect");
            r.config = Some(c);
            validate(&r)
        };
        assert_eq!(with(&|_| {}), None);
        assert_eq!(with(&|c| c.ports = vec![443, 0]).as_deref(), Some("invalid port 0"));
        assert_eq!(with(&|c| c.cert_der = Some(vec![0; MAX_CERT_BYTES + 1])).as_deref(), Some("certificate too large"));
        assert_eq!(
            with(&|c| c.private_key_der = Some(vec![0; MAX_KEY_BYTES + 1])).as_deref(),
            Some("private key too large")
        );
        assert_eq!(with(&|c| c.ticket = Some(vec![0; 1025])).as_deref(), Some("ticket too large"));
        assert_eq!(with(&|c| c.ticket = Some(vec![0; 1024])), None);
        assert_eq!(with(&|c| c.hub_name = "a\0b".into()).as_deref(), Some("invalid hub name"));
        assert_eq!(with(&|c| c.user_name = "x".repeat(256)).as_deref(), Some("invalid user name"));
        assert_eq!(with(&|c| c.host = "-x".into()).as_deref(), Some("invalid host"));
    }

    #[test]
    fn socks_port_only_matters_in_socks_mode() {
        let mut r = req("1.2.3.4");
        r.socks_port = Some(80);
        assert_eq!(validate(&r), None);
        r.tunnel_mode = Some(TunnelMode::SocksProxy);
        assert_eq!(validate(&r).as_deref(), Some("invalid SOCKS port (use 1024-65535)"));
        r.socks_port = Some(1080);
        assert_eq!(validate(&r), None);
    }

    #[test]
    fn routing_rules_must_be_well_formed() {
        let mut r = req("1.2.3.4");
        r.routing = Some(RoutingConfig {
            rules: vec![RoutingRule::new(RoutingRuleType::DomainRegex, "(", RoutingAction::Direct)],
            ..Default::default()
        });
        assert_eq!(validate(&r).as_deref(), Some("routing rule \"(\": Not a valid regular expression."));
        r.routing = Some(RoutingConfig {
            rules: vec![RoutingRule::new(RoutingRuleType::Cidr, "10.0.0.0/8", RoutingAction::Direct)],
            ..Default::default()
        });
        assert_eq!(validate(&r), None);
    }
}
