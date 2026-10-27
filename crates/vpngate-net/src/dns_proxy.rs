//! Resolves DNS the way the user's routing rules say to: a domain explicitly marked `direct` is asked of the physical
//! network's own resolver (never the tunnel's), `block` gets NXDOMAIN with no query sent anywhere, and everything else
//! (the default, `proxy`) goes to the tunnel's own resolver, so nothing but `direct` domains ever reaches an
//! ISP-controlled resolver. Every resolved address is also reported to a [`DynamicRuleSink`] so the matching route
//! exists before the answer reaches the asking app.
//!
//! This is the decision-and-forward logic only. The UDP listener and the interface-bound upstream socket need
//! `SocketBinder` and belong to the session units.

use std::sync::Arc;

use async_trait::async_trait;
use vpngate_core::routing_rule::{routing_matcher, RoutingAction, RoutingConfig};

use crate::dns_message;

/// Sends one DNS query to one upstream server and waits for the reply, so the routing decision can be tested without
/// a real socket.
#[async_trait]
pub trait DnsUpstream: Send + Sync {
    async fn query(&self, message: &[u8], server: &str, timeout_ms: u32) -> Option<Vec<u8>>;
}

/// Receives the address a rule decided on (the `NetConfiguring.applyDynamicRule` seam).
pub trait DynamicRuleSink: Send + Sync {
    fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction);
}

pub struct DnsProxy {
    upstream: Arc<dyn DnsUpstream>,
    sink: Arc<dyn DynamicRuleSink>,
    pub timeout_ms: u32,
    pub routing: RoutingConfig,
    pub tunnel_dns_servers: Vec<String>,
    pub direct_dns_servers: Vec<String>,
}

impl DnsProxy {
    pub fn new(sink: Arc<dyn DynamicRuleSink>, upstream: Arc<dyn DnsUpstream>) -> Self {
        DnsProxy {
            upstream,
            sink,
            timeout_ms: 4000,
            routing: RoutingConfig::default(),
            tunnel_dns_servers: Vec::new(),
            direct_dns_servers: Vec::new(),
        }
    }

    /// The decision-and-forward logic for one query, with no socket involved.
    pub async fn handle(&self, query: &[u8]) -> Vec<u8> {
        // A query whose name cannot even be parsed must never be guessed at: fail closed.
        let Some(name) = dns_message::query_name(query) else { return dns_message::servfail_response(query) };
        let rule = routing_matcher::match_domain(&name, &self.routing);
        let action = rule.as_ref().map(|r| r.action);
        if action == Some(RoutingAction::Block) {
            return dns_message::blocked_response(query);
        }
        let servers =
            if action == Some(RoutingAction::Direct) { &self.direct_dns_servers } else { &self.tunnel_dns_servers };
        let Some(server) = servers.first() else { return dns_message::servfail_response(query) };
        let Some(response) = self.upstream.query(query, server, self.timeout_ms).await else {
            return dns_message::servfail_response(query);
        };
        // Only for an address a rule explicitly decided on: the structural routes (full capture, or its absence with
        // `default_action: direct`) already do the right thing for everything else.
        if let Some(action) = action {
            for ip in dns_message::resolved_ipv4_addresses(&response) {
                self.sink.apply_dynamic_rule(&ip, action);
            }
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use serde_json::Value;
    use vpngate_core::routing_rule::{RoutingRule, RoutingRuleType};
    use vpngate_testkit::golden::{load, unhex};

    use super::*;

    #[derive(Default)]
    struct Upstream {
        calls: Mutex<Vec<(String, u32, Vec<u8>)>>,
        /// A records to answer with; `None` = no answer (timeout).
        answers: Mutex<Option<Vec<String>>>,
    }

    #[async_trait]
    impl DnsUpstream for Upstream {
        async fn query(&self, message: &[u8], server: &str, timeout_ms: u32) -> Option<Vec<u8>> {
            self.calls.lock().unwrap().push((server.to_string(), timeout_ms, message.to_vec()));
            let answers = self.answers.lock().unwrap().clone()?;
            let mut p = message.to_vec();
            p[2] |= 0x80;
            p[6] = (answers.len() >> 8) as u8;
            p[7] = (answers.len() & 0xff) as u8;
            for a in &answers {
                p.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 0x3c, 0, 4]);
                p.extend(a.split('.').map(|o| o.parse::<u8>().unwrap()));
            }
            Some(p)
        }
    }

    #[derive(Default)]
    struct Sink(Mutex<Vec<(String, RoutingAction)>>);

    impl DynamicRuleSink for Sink {
        fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction) {
            self.0.lock().unwrap().push((ip.to_string(), action));
        }
    }

    fn make(
        rules: Vec<RoutingRule>,
        default_action: RoutingAction,
        tunnel: &[&str],
        direct: &[&str],
    ) -> (DnsProxy, Arc<Upstream>, Arc<Sink>) {
        let up = Arc::new(Upstream::default());
        let sink = Arc::new(Sink::default());
        let mut p = DnsProxy::new(sink.clone(), up.clone());
        p.routing = RoutingConfig { rules, default_action, bypass_private_networks: false };
        p.tunnel_dns_servers = tunnel.iter().map(|s| s.to_string()).collect();
        p.direct_dns_servers = direct.iter().map(|s| s.to_string()).collect();
        (p, up, sink)
    }

    fn std_proxy(rules: Vec<RoutingRule>, default_action: RoutingAction) -> (DnsProxy, Arc<Upstream>, Arc<Sink>) {
        make(rules, default_action, &["10.0.0.1"], &["9.9.9.9"])
    }

    fn suffix(v: &str, a: RoutingAction) -> RoutingRule {
        RoutingRule::new(RoutingRuleType::DomainSuffix, v, a)
    }

    fn answer(up: &Upstream, a: &[&str]) {
        *up.answers.lock().unwrap() = Some(a.iter().map(|s| s.to_string()).collect());
    }

    fn rcode(r: &[u8]) -> u8 {
        r[3] & 0x0f
    }

    fn servers(up: &Upstream) -> Vec<String> {
        up.calls.lock().unwrap().iter().map(|c| c.0.clone()).collect()
    }

    #[tokio::test]
    async fn blocked_domain_gets_nxdomain_without_asking_any_upstream() {
        let (p, up, _) = std_proxy(vec![suffix("ads.example", RoutingAction::Block)], RoutingAction::Proxy);
        let r = p.handle(&dns_message::a_query("ads.example", 1)).await;
        assert_eq!(rcode(&r), 3);
        assert!(servers(&up).is_empty());
    }

    #[tokio::test]
    async fn direct_domain_uses_the_direct_server_and_gets_a_direct_route() {
        let (p, up, sink) = std_proxy(vec![suffix("example.com", RoutingAction::Direct)], RoutingAction::Proxy);
        answer(&up, &["93.184.216.34"]);
        p.handle(&dns_message::a_query("example.com", 1)).await;
        assert_eq!(servers(&up), ["9.9.9.9"]);
        assert_eq!(*sink.0.lock().unwrap(), [("93.184.216.34".to_string(), RoutingAction::Direct)]);
    }

    #[tokio::test]
    async fn unmatched_domain_uses_the_tunnel_server_and_installs_no_dynamic_route() {
        let (p, up, sink) = std_proxy(vec![], RoutingAction::Proxy);
        answer(&up, &["5.6.7.8"]);
        p.handle(&dns_message::a_query("anything.example", 1)).await;
        assert_eq!(servers(&up), ["10.0.0.1"]);
        assert!(sink.0.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn proxy_rule_uses_the_tunnel_server() {
        let (p, up, sink) = std_proxy(vec![suffix("example.com", RoutingAction::Proxy)], RoutingAction::Direct);
        answer(&up, &["5.6.7.8"]);
        p.handle(&dns_message::a_query("example.com", 1)).await;
        assert_eq!(servers(&up), ["10.0.0.1"]);
        assert_eq!(*sink.0.lock().unwrap(), [("5.6.7.8".to_string(), RoutingAction::Proxy)]);
    }

    #[tokio::test]
    async fn no_direct_server_fails_closed_instead_of_leaking_to_the_tunnel() {
        let (p, up, _) =
            make(vec![suffix("example.com", RoutingAction::Direct)], RoutingAction::Proxy, &["10.0.0.1"], &[]);
        let r = p.handle(&dns_message::a_query("example.com", 1)).await;
        assert_eq!(rcode(&r), 2);
        assert!(servers(&up).is_empty());
    }

    #[tokio::test]
    async fn upstream_failure_is_servfail_not_a_fallback() {
        let (p, up, _) = std_proxy(vec![], RoutingAction::Proxy);
        let r = p.handle(&dns_message::a_query("example.com", 1)).await;
        assert_eq!(rcode(&r), 2);
        assert_eq!(servers(&up).len(), 1);
    }

    #[tokio::test]
    async fn unparsable_query_is_servfail_without_touching_any_upstream() {
        let (p, up, _) = std_proxy(vec![], RoutingAction::Proxy);
        let r = p.handle(&[0x12, 0x34]).await;
        assert_eq!(r, dns_message::servfail_response(&[0x12, 0x34]));
        assert!(servers(&up).is_empty());
    }

    #[tokio::test]
    async fn first_matching_rule_still_wins_over_the_default_action() {
        let rules = vec![RoutingRule::new(RoutingRuleType::DomainFull, "example.com", RoutingAction::Block)];
        let (p, up, _) = std_proxy(rules, RoutingAction::Direct);
        let r = p.handle(&dns_message::a_query("example.com", 1)).await;
        assert_eq!(rcode(&r), 3);
        assert!(servers(&up).is_empty());
    }

    #[tokio::test]
    async fn golden_transcripts_replay() {
        let doc = load("transcripts/dnsproxy");
        for c in doc["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let cfg = &c["config"];
            let rules: Vec<RoutingRule> = serde_json::from_value(cfg["rules"].clone()).unwrap();
            let default_action: RoutingAction = serde_json::from_value(cfg["defaultAction"].clone()).unwrap();
            fn strs(v: &Value) -> Vec<&str> {
                v.as_array().unwrap().iter().map(|s| s.as_str().unwrap()).collect()
            }
            let (mut p, up, sink) = make(rules, default_action, &strs(&cfg["tunnelDns"]), &strs(&cfg["directDns"]));
            p.timeout_ms = cfg["timeoutMs"].as_u64().unwrap() as u32;
            // The recorded upstream is deterministic: it answers with the recorded A records, or not at all.
            let calls = c["upstreamCalls"].as_array().unwrap();
            if let Some(call) = calls.first() {
                if let Some(resp) = call["responseHex"].as_str() {
                    let ips = super::super::dns_message::resolved_ipv4_addresses(&unhex(resp));
                    *up.answers.lock().unwrap() = Some(ips);
                }
            }
            let response = p.handle(&unhex(c["queryHex"].as_str().unwrap())).await;
            assert_eq!(response, unhex(c["responseHex"].as_str().unwrap()), "{name}: response");

            let got = up.calls.lock().unwrap().clone();
            assert_eq!(got.len(), calls.len(), "{name}: upstream calls");
            for (g, w) in got.iter().zip(calls) {
                assert_eq!(g.0, w["server"].as_str().unwrap(), "{name}: server");
                assert_eq!(u64::from(g.1), w["timeoutMs"].as_u64().unwrap(), "{name}: timeout");
                assert_eq!(g.2, unhex(w["queryHex"].as_str().unwrap()), "{name}: query");
            }
            let want: Vec<(String, RoutingAction)> = c["dynamicRules"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| (r["ip"].as_str().unwrap().to_string(), serde_json::from_value(r["action"].clone()).unwrap()))
                .collect();
            assert_eq!(*sink.0.lock().unwrap(), want, "{name}: dynamic rules");
        }
    }
}
