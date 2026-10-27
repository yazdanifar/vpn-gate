use std::sync::Mutex;

use vpngate_core::routing_rule::{RoutingAction, RoutingRule, RoutingRuleType};
use vpngate_platform::UnboundSocketBinder;

use super::*;
use crate::dns_message;

/// A UDP DNS server on loopback that answers every A query with 9.8.7.6 and records who asked for what.
async fn fake_dns() -> (u16, Arc<Mutex<Vec<String>>>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = socket.local_addr().unwrap().port();
    let seen: Arc<Mutex<Vec<String>>> = Arc::default();
    let log = seen.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        while let Ok((n, from)) = socket.recv_from(&mut buf).await {
            let q = &buf[..n];
            log.lock().unwrap().push(dns_message::query_name(q).unwrap_or_default());
            let mut r = q.to_vec();
            r[2] |= 0x80;
            r[7] = 1;
            r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 9, 8, 7, 6]);
            let _ = socket.send_to(&r, from).await;
        }
    });
    (port, seen)
}

#[derive(Default)]
struct Sink(Mutex<Vec<(String, RoutingAction)>>);

impl DynamicRuleSink for Sink {
    fn apply_dynamic_rule(&self, ip: &str, action: RoutingAction) {
        self.0.lock().unwrap().push((ip.to_string(), action));
    }
}

#[tokio::test]
async fn upstream_sends_one_query_and_returns_the_answer() {
    let (port, seen) = fake_dns().await;
    let up = SocketDnsUpstream::new(Arc::new(UnboundSocketBinder)).with_port(port);
    let q = dns_message::a_query("a.example", 7);
    let r = up.query(&q, "127.0.0.1", 2000).await.expect("answer");
    assert_eq!(dns_message::resolved_ipv4_addresses(&r), ["9.8.7.6"]);
    assert_eq!(*seen.lock().unwrap(), ["a.example"]);
}

#[tokio::test]
async fn upstream_gives_up_after_the_timeout_and_rejects_bad_servers() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let up = SocketDnsUpstream::new(Arc::new(UnboundSocketBinder)).with_port(silent.local_addr().unwrap().port());
    let q = dns_message::a_query("a.example", 7);
    assert!(up.query(&q, "127.0.0.1", 150).await.is_none());
    assert!(up.query(&q, "not-an-ip", 150).await.is_none());
}

#[tokio::test]
async fn listener_answers_queries_and_reports_rule_addresses() {
    let (port, seen) = fake_dns().await;
    let sink = Arc::new(Sink::default());
    let upstream = Arc::new(SocketDnsUpstream::new(Arc::new(UnboundSocketBinder)).with_port(port));
    let routing = RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::DomainSuffix, "example.com", RoutingAction::Direct)],
        ..RoutingConfig::default()
    };
    let server = DnsProxyServer::new(sink.clone(), upstream, routing, SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0));
    server.set_servers(vec!["127.0.0.1".into()], vec!["127.0.0.1".into()]);
    server.start().unwrap();
    let addr = server.local_addr().expect("bound");

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.send_to(&dns_message::a_query("www.example.com", 0x4242), addr).await.unwrap();
    let mut buf = vec![0u8; 512];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(buf[..2], [0x42, 0x42]);
    assert_eq!(dns_message::resolved_ipv4_addresses(&buf[..n]), ["9.8.7.6"]);
    assert_eq!(*seen.lock().unwrap(), ["www.example.com"]);
    assert_eq!(*sink.0.lock().unwrap(), [("9.8.7.6".to_string(), RoutingAction::Direct)]);

    // no resolver configured for a name no rule matches while the tunnel list is empty -> SERVFAIL, nothing leaks
    server.set_servers(Vec::new(), Vec::new());
    client.send_to(&dns_message::a_query("other.test", 5), addr).await.unwrap();
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), client.recv_from(&mut buf)).await.unwrap().unwrap();
    assert_eq!(buf[3] & 0x0F, 2, "SERVFAIL, got {:?}", &buf[..n]);
    server.stop();
}

#[tokio::test]
async fn a_busy_listen_address_is_a_readable_error() {
    let taken = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let Ok(SocketAddr::V4(addr)) = taken.local_addr() else { panic!("ipv4") };
    let server = DnsProxyServer::new(
        Arc::new(Sink::default()),
        Arc::new(SocketDnsUpstream::new(Arc::new(UnboundSocketBinder))),
        RoutingConfig::default(),
        addr,
    );
    assert!(server.start().unwrap_err().to_string().contains("dns proxy bind"));
}
