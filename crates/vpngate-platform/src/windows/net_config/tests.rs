use std::sync::Mutex;

use vpngate_core::routing_rule::{RoutingConfig, RoutingRule, RoutingRuleType};

use super::*;

const GW: &str = "10.233.254.254";
const TUN: u32 = 42;
const LAN: u32 = 7;

fn lease() -> Lease {
    Lease {
        ip: 0x0AE991B6,
        mask: 0xFFFF0000,
        router: 0x0AE9FEFE,
        dns: vec![0x0AE9FEFE, 0x08080808],
        seconds: 3600,
        server_id: 0x0AE9FEFE,
        mtu: None,
    }
}

/// Records every call; answers like a LAN behind 192.168.1.1 on interface 7, with the adapter at index 42.
#[derive(Default)]
struct FakeApi {
    calls: Mutex<Vec<String>>,
    fail_routes: Mutex<Vec<String>>,
    no_adapter: Mutex<bool>,
}

impl FakeApi {
    fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn has(&self, call: &str) -> bool {
        self.calls().iter().any(|c| c == call)
    }

    fn index(&self, call: &str) -> Option<usize> {
        self.calls().iter().position(|c| c == call)
    }

    fn push(&self, call: String) {
        self.calls.lock().unwrap().push(call);
    }
}

fn describe(r: &Route) -> String {
    format!("{} metric {}", r.to_args().join(" "), r.metric)
}

impl IpHelper for FakeApi {
    fn if_index(&self, name: &str) -> Option<u32> {
        (!*self.no_adapter.lock().unwrap() && name == "VPNGate").then_some(TUN)
    }

    fn add_address(&self, if_index: u32, ip: IpAddr, prefix: u8) -> Result<(), String> {
        self.push(format!("addr {ip}/{prefix} if {if_index}"));
        Ok(())
    }

    fn set_mtu(&self, if_index: u32, ipv6: bool, mtu: u32) -> Result<(), String> {
        self.push(format!("mtu {mtu} v6={ipv6} if {if_index}"));
        Ok(())
    }

    fn add_route(&self, route: &Route) -> Result<(), String> {
        let line = describe(route);
        self.push(format!("add {line}"));
        if self.fail_routes.lock().unwrap().iter().any(|f| line.starts_with(f)) {
            return Err("exists".into());
        }
        Ok(())
    }

    fn delete_route(&self, route: &Route) -> Result<(), String> {
        self.push(format!("del {}", route.to_args().join(" ")));
        Ok(())
    }

    fn best_route(&self, dest: Ipv4Addr) -> Option<BestRoute> {
        if dest == Ipv4Addr::LOCALHOST {
            return Some(BestRoute { if_index: 1, next_hop: None });
        }
        Some(BestRoute { if_index: LAN, next_hop: Some(Ipv4Addr::new(192, 168, 1, 1)) })
    }
}

#[derive(Default)]
struct FakeDns {
    set_calls: Mutex<Vec<Vec<String>>>,
    removes: Mutex<usize>,
    physical: Mutex<Vec<String>>,
}

impl DnsConfigurator for FakeDns {
    fn set(&self, servers: &[String], _iface: &str, _address: &str, _router: &str) -> bool {
        self.set_calls.lock().unwrap().push(servers.to_vec());
        true
    }

    fn remove(&self) {
        *self.removes.lock().unwrap() += 1;
    }

    fn current_servers(&self) -> Vec<String> {
        self.physical.lock().unwrap().clone()
    }
}

#[derive(Default)]
struct MemLog {
    ops: Mutex<Vec<UndoOp>>,
}

impl UndoLog for MemLog {
    fn record(&self, op: UndoOp) {
        self.ops.lock().unwrap().push(op);
    }

    fn clear(&self) {
        self.ops.lock().unwrap().clear();
    }
}

struct Fixture {
    net: WinNetConfig,
    api: Arc<FakeApi>,
    dns: Arc<FakeDns>,
    log: Arc<MemLog>,
}

fn make() -> Fixture {
    let (api, dns, log) = (Arc::new(FakeApi::default()), Arc::new(FakeDns::default()), Arc::new(MemLog::default()));
    Fixture { net: WinNetConfig::new(api.clone(), dns.clone(), log.clone()), api, dns, log }
}

fn request(bypass: &str) -> NetApply {
    NetApply {
        iface: "VPNGate".into(),
        lease: lease(),
        bypass_host: bypass.into(),
        block_ipv6: true,
        mtu_override: None,
        routing: None,
        dns_proxy_address: None,
    }
}

fn with_rules(default_action: RoutingAction, rules: &[(RoutingRuleType, &str, RoutingAction)]) -> RoutingConfig {
    RoutingConfig {
        default_action,
        rules: rules.iter().map(|(t, v, a)| RoutingRule::new(*t, v, *a)).collect(),
        ..RoutingConfig::default()
    }
}

#[test]
fn apply_makes_the_expected_changes_in_order() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    let expected = [
        "addr 10.233.145.182/32 if 42".to_string(),
        "mtu 1400 v6=false if 42".to_string(),
        "add 5.5.5.5/32 192.168.1.1 7 metric 1".to_string(),
        format!("add {GW}/32 onlink 42 metric 1"),
        format!("add 0.0.0.0/1 {GW} 42 metric 1"),
        format!("add 128.0.0.0/1 {GW} 42 metric 1"),
        "add ::/1 onlink 42 metric 1".to_string(),
        "add 8000::/1 onlink 42 metric 1".to_string(),
    ];
    let idx: Vec<usize> = expected
        .iter()
        .map(|c| f.api.index(c).unwrap_or_else(|| panic!("missing {c}; calls: {:?}", f.api.calls())))
        .collect();
    assert!(idx.windows(2).all(|w| w[0] < w[1]), "out of order: {:?}", f.api.calls());
    assert_eq!(f.dns.set_calls.lock().unwrap().clone(), vec![vec![GW.to_string(), "8.8.8.8".to_string()]]);
    assert!(f.log.ops.lock().unwrap().contains(&UndoOp::new(UNDO_DNS, &[])));
}

#[test]
fn missing_adapter_is_an_error() {
    let f = make();
    *f.api.no_adapter.lock().unwrap() = true;
    assert!(f.net.apply(&request("5.5.5.5")).is_err());
    assert!(f.api.calls().is_empty());
}

#[test]
fn mtu_override_beats_the_lease_and_invalid_values_fall_back() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.mtu_override = Some(1280);
    r.lease.mtu = Some(1350);
    f.net.apply(&r).unwrap();
    assert!(f.api.has("mtu 1280 v6=false if 42"));
    let g = make();
    let mut r = request("5.5.5.5");
    r.mtu_override = Some(100);
    r.lease.mtu = Some(1350);
    g.net.apply(&r).unwrap();
    assert!(g.api.has("mtu 1350 v6=false if 42"));
}

#[test]
fn teardown_deletes_what_apply_added_in_reverse() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    let calls = f.api.calls();
    for c in [
        format!("del 0.0.0.0/1 {GW} 42"),
        format!("del 128.0.0.0/1 {GW} 42"),
        format!("del {GW}/32 onlink 42"),
        "del 5.5.5.5/32 192.168.1.1 7".to_string(),
        "del ::/1 onlink 42".to_string(),
    ] {
        assert!(calls.contains(&c), "missing {c}");
    }
    assert!(f.api.index("del 5.5.5.5/32 192.168.1.1 7") > f.api.index(&format!("del 0.0.0.0/1 {GW} 42")));
    assert_eq!(*f.dns.removes.lock().unwrap(), 1);
    assert!(f.log.ops.lock().unwrap().is_empty(), "undo list cleared");
}

#[test]
fn a_route_that_failed_to_add_is_never_deleted() {
    let f = make();
    f.api.fail_routes.lock().unwrap().push("5.5.5.5/32".into());
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    assert!(!f.api.calls().iter().any(|c| c.starts_with("del 5.5.5.5")));
}

#[test]
fn loopback_relay_gets_no_bypass_route() {
    let f = make();
    f.net.apply(&request("127.0.0.1")).unwrap();
    assert!(!f.api.calls().iter().any(|c| c.starts_with("add 127.0.0.1")));
    assert!(f.api.has(&format!("add 0.0.0.0/1 {GW} 42 metric 1")));
}

#[test]
fn direct_default_captures_nothing_and_proxy_rules_route_into_the_tunnel() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing =
        Some(with_rules(RoutingAction::Direct, &[(RoutingRuleType::Cidr, "203.0.113.0/24", RoutingAction::Proxy)]));
    f.net.apply(&r).unwrap();
    assert!(!f.api.calls().iter().any(|c| c.starts_with("add 0.0.0.0/1")));
    assert!(f.api.has(&format!("add 203.0.113.0/24 {GW} 42 metric 1")));
}

#[test]
fn direct_and_block_rules_carve_exceptions_out_of_a_full_tunnel() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(with_rules(
        RoutingAction::Proxy,
        &[
            (RoutingRuleType::Cidr, "10.0.0.0/8", RoutingAction::Direct),
            (RoutingRuleType::Ip, "198.51.100.9", RoutingAction::Block),
        ],
    ));
    f.net.apply(&r).unwrap();
    assert!(f.api.has("add 10.0.0.0/8 192.168.1.1 7 metric 1"));
    assert!(f.api.has("add 198.51.100.9/32 onlink 1 metric 1"), "block goes out the loopback interface");
}

#[test]
fn routing_captures_the_physical_dns_and_bypasses_it() {
    let f = make();
    *f.dns.physical.lock().unwrap() = vec!["192.168.1.1".into(), "fe80::1".into(), "127.0.0.1".into()];
    let mut r = request("5.5.5.5");
    r.routing =
        Some(with_rules(RoutingAction::Proxy, &[(RoutingRuleType::DomainSuffix, "a.com", RoutingAction::Direct)]));
    f.net.apply(&r).unwrap();
    assert_eq!(f.net.direct_dns_servers(), vec!["192.168.1.1".to_string(), "127.0.0.1".to_string()]);
    assert!(f.api.has("add 192.168.1.1/32 192.168.1.1 7 metric 1"));
    assert!(!f.api.calls().iter().any(|c| c.starts_with("add 127.0.0.1/32")));
}

#[test]
fn dns_proxy_address_is_published_instead_of_the_lease_dns() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.dns_proxy_address = Some("10.233.145.182".into());
    f.net.apply(&r).unwrap();
    assert_eq!(f.dns.set_calls.lock().unwrap().clone(), vec![vec!["10.233.145.182".to_string()]]);
}

#[test]
fn add_bypass_validates_and_dedupes() {
    let f = make();
    f.net.add_bypass("9.9.9.9"); // before apply: ignored
    assert!(f.api.calls().is_empty());
    f.net.apply(&request("5.5.5.5")).unwrap();
    let before = f.api.calls().len();
    for bad in ["5.5.5.5", "127.0.0.1", "not-an-ip", "1.2.3.4 -x"] {
        f.net.add_bypass(bad);
    }
    assert_eq!(f.api.calls().len(), before);
    f.net.add_bypass("9.9.9.9");
    assert!(f.api.has("add 9.9.9.9/32 192.168.1.1 7 metric 1"));
}

#[test]
fn ipv6_address_filters() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    let before = f.api.calls().len();
    for (a, p) in [("fe80::1", 64), ("::", 64), ("ff02::1", 64), ("2001:db8::5", 0), ("2001:db8::5", 129)] {
        f.net.configure_ipv6(a.parse().unwrap(), p);
    }
    assert_eq!(f.api.calls().len(), before);
    f.net.configure_ipv6("2001:db8::5".parse().unwrap(), 64);
    assert!(f.api.has("addr 2001:db8::5/64 if 42"));
}

#[test]
fn dynamic_rules_route_single_addresses_and_ignore_garbage() {
    let f = make();
    f.net.apply_dynamic_rule("203.0.113.5", RoutingAction::Direct); // before apply
    assert!(f.api.calls().is_empty());
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.apply_dynamic_rule("203.0.113.5", RoutingAction::Direct);
    f.net.apply_dynamic_rule("2001:db8::1", RoutingAction::Proxy);
    f.net.apply_dynamic_rule("evil; rm", RoutingAction::Direct);
    assert!(f.api.has("add 203.0.113.5/32 192.168.1.1 7 metric 1"));
    assert!(f.api.has("add 2001:db8::1/128 onlink 42 metric 1"));
    assert!(!f.api.calls().iter().any(|c| c.contains("evil")));
}

#[test]
fn socks_mode_adds_no_global_capture() {
    let f = make();
    f.net.apply_socks("VPNGate", &lease(), None).unwrap();
    assert!(f.api.has(&format!("add 0.0.0.0/0 {GW} 42 metric 9000")));
    assert!(!f.api.calls().iter().any(|c| c.contains("0.0.0.0/1") || c.contains("::/1")));
    assert!(f.dns.set_calls.lock().unwrap().is_empty());
    f.net.teardown();
    assert!(f.api.has(&format!("del 0.0.0.0/0 {GW} 42")));
}

#[test]
fn undoer_replays_a_persisted_list_without_the_original_process() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    let persisted = f.log.ops.lock().unwrap().clone();
    let json = serde_json::to_string(&persisted).unwrap();
    let restored: Vec<UndoOp> = serde_json::from_str(&json).unwrap();
    let (api, dns) = (Arc::new(FakeApi::default()), Arc::new(FakeDns::default()));
    let undoer = WinUndoer::new(api.clone(), dns.clone());
    for op in restored.iter().rev() {
        undoer.undo(op);
    }
    assert!(api.has("del 5.5.5.5/32 192.168.1.1 7"));
    assert!(api.has(&format!("del 0.0.0.0/1 {GW} 42")));
    assert_eq!(*dns.removes.lock().unwrap(), 1);
}

#[test]
fn route_args_round_trip_and_reject_garbage() {
    let r = Route { dest: "10.0.0.0".parse().unwrap(), prefix: 8, next_hop: None, if_index: 3, metric: 5 };
    let back = Route::from_args(&r.to_args()).unwrap();
    assert_eq!((back.dest, back.prefix, back.next_hop, back.if_index), (r.dest, 8, None, 3));
    assert!(Route::from_args(&["x".into()]).is_none());
    assert!(Route::from_args(&["1.2.3.4/99x".into(), "onlink".into(), "1".into()]).is_none());
}
