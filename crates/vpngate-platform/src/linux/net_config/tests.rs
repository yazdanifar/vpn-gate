use std::sync::Mutex;

use vpngate_core::routing_rule::{RoutingConfig, RoutingRule, RoutingRuleType};

use super::*;
use crate::CommandOutput;

const GW: &str = "10.233.254.254";
const DEFAULT: &str = "default via 192.168.1.1 dev eth0 proto dhcp metric 100\n";

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

struct Rule {
    contains: &'static str,
    status: i32,
}

/// Records every command line; answers `ip -4 route show default` like a LAN with a gateway unless told otherwise.
struct RecordingRunner {
    log: Mutex<Vec<String>>,
    rules: Mutex<Vec<Rule>>,
    default_route: &'static str,
}

impl RecordingRunner {
    fn with(default_route: &'static str, rules: Vec<Rule>) -> Arc<Self> {
        Arc::new(RecordingRunner { log: Mutex::default(), rules: Mutex::new(rules), default_route })
    }

    fn log(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }

    fn has(&self, line: &str) -> bool {
        self.log().iter().any(|l| l == line)
    }

    fn any(&self, part: &str) -> bool {
        self.log().iter().any(|l| l.contains(part))
    }

    fn index(&self, line: &str) -> Option<usize> {
        self.log().iter().position(|l| l == line)
    }
}

impl CommandRunner for RecordingRunner {
    fn run(&self, program: &str, args: &[&str]) -> CommandOutput {
        let line = format!("{program} {}", args.join(" "));
        self.log.lock().unwrap().push(line.clone());
        if let Some(r) = self.rules.lock().unwrap().iter().find(|r| line.contains(r.contains)) {
            return CommandOutput { status: r.status, output: String::new() };
        }
        if line.ends_with("route show default") {
            return CommandOutput { status: 0, output: self.default_route.into() };
        }
        CommandOutput { status: 0, output: String::new() }
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
    net: LinuxNetConfig,
    runner: Arc<RecordingRunner>,
    dns: Arc<FakeDns>,
    log: Arc<MemLog>,
}

fn make_with(runner: Arc<RecordingRunner>) -> Fixture {
    let (dns, log) = (Arc::new(FakeDns::default()), Arc::new(MemLog::default()));
    Fixture { net: LinuxNetConfig::new(runner.clone(), dns.clone(), log.clone()), runner, dns, log }
}

fn make() -> Fixture {
    make_with(RecordingRunner::with(DEFAULT, vec![]))
}

fn request(bypass: &str) -> NetApply {
    NetApply {
        iface: "vpngate0".into(),
        lease: lease(),
        bypass_host: bypass.into(),
        block_ipv6: true,
        mtu_override: None,
        routing: None,
        dns_proxy_address: None,
    }
}

fn routed(rule_type: RoutingRuleType, value: &str, action: RoutingAction) -> Option<RoutingConfig> {
    Some(RoutingConfig { rules: vec![RoutingRule::new(rule_type, value, action)], ..RoutingConfig::default() })
}

#[test]
fn apply_runs_the_expected_commands_in_order() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    let expected = [
        "/usr/sbin/ip -4 route show default".to_string(),
        "/usr/sbin/ip link set dev vpngate0 mtu 1400 up".to_string(),
        "/usr/sbin/ip addr add 10.233.145.182 peer 10.233.254.254/32 dev vpngate0".to_string(),
        "/usr/sbin/ip route add 5.5.5.5/32 via 192.168.1.1 dev eth0".to_string(),
        format!("/usr/sbin/ip route add 0.0.0.0/1 via {GW} dev vpngate0"),
        format!("/usr/sbin/ip route add 128.0.0.0/1 via {GW} dev vpngate0"),
        "/usr/sbin/ip -6 route add ::/1 dev vpngate0".to_string(),
        "/usr/sbin/ip -6 route add 8000::/1 dev vpngate0".to_string(),
    ];
    assert_eq!(f.runner.log(), expected);
    assert_eq!(*f.dns.set_calls.lock().unwrap(), vec![vec![GW.to_string(), "8.8.8.8".to_string()]]);
}

#[test]
fn teardown_removes_what_apply_added_in_reverse() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    let log = f.runner.log();
    let tail: Vec<&String> = log.iter().skip(8).collect();
    assert_eq!(
        tail,
        [
            "/usr/sbin/ip -6 route del 8000::/1",
            "/usr/sbin/ip -6 route del ::/1",
            "/usr/sbin/ip route del 128.0.0.0/1",
            "/usr/sbin/ip route del 0.0.0.0/1",
            "/usr/sbin/ip route del 5.5.5.5/32",
        ]
    );
    assert_eq!(*f.dns.removes.lock().unwrap(), 1);
    assert!(f.log.ops.lock().unwrap().is_empty(), "undo list cleared after a clean teardown");
}

#[test]
fn routes_that_failed_are_never_deleted() {
    let f = make_with(RecordingRunner::with(DEFAULT, vec![Rule { contains: "route add 0.0.0.0/1", status: 2 }]));
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    assert!(!f.runner.any("route del 0.0.0.0/1"));
    assert!(f.runner.has("/usr/sbin/ip route del 128.0.0.0/1"));
}

#[test]
fn loopback_proxy_gets_no_bypass_route() {
    let f = make();
    f.net.apply(&request("127.0.0.1")).unwrap();
    assert!(!f.runner.any("127.0.0.1/32"));
}

#[test]
fn lease_dns_is_replaced_by_the_proxy_address_and_absent_dns_changes_nothing() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.dns_proxy_address = Some("10.255.255.53".into());
    f.net.apply(&r).unwrap();
    assert_eq!(*f.dns.set_calls.lock().unwrap(), vec![vec!["10.255.255.53".to_string()]]);

    let g = make();
    let mut r = request("5.5.5.5");
    r.lease.dns.clear();
    g.net.apply(&r).unwrap();
    assert!(g.dns.set_calls.lock().unwrap().is_empty());
    g.net.teardown();
    assert_eq!(*g.dns.removes.lock().unwrap(), 0);
}

#[test]
fn mtu_comes_from_the_account_then_the_lease_within_576_to_1500() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.lease.mtu = Some(1280);
    f.net.apply(&r).unwrap();
    assert!(f.runner.has("/usr/sbin/ip link set dev vpngate0 mtu 1280 up"));

    let g = make();
    let mut r = request("5.5.5.5");
    r.lease.mtu = Some(1280);
    r.mtu_override = Some(1350);
    g.net.apply(&r).unwrap();
    assert!(g.runner.has("/usr/sbin/ip link set dev vpngate0 mtu 1350 up"));

    let h = make();
    let mut r = request("5.5.5.5");
    r.lease.mtu = Some(9000);
    r.mtu_override = Some(100);
    h.net.apply(&r).unwrap();
    assert!(h.runner.has("/usr/sbin/ip link set dev vpngate0 mtu 1400 up"));
}

#[test]
fn slaac_address_is_configured_but_never_link_local_or_unspecified() {
    let f = make();
    f.net.configure_ipv6("2001:db8::5".parse().unwrap(), 64);
    assert!(!f.runner.any("addr add 2001"), "no-op before apply");
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.configure_ipv6("fe80::1".parse().unwrap(), 64);
    f.net.configure_ipv6("::".parse().unwrap(), 64);
    f.net.configure_ipv6("2001:db8::5".parse().unwrap(), 0);
    assert!(!f.runner.any("-6 addr add"));
    f.net.configure_ipv6("2001:db8::5".parse().unwrap(), 64);
    assert!(f.runner.has("/usr/sbin/ip -6 addr add 2001:db8::5/64 dev vpngate0"));
}

#[test]
fn further_peers_get_bypass_routes_that_teardown_removes() {
    let f = make();
    f.net.add_bypass("6.6.6.6");
    assert!(!f.runner.any("6.6.6.6"), "no-op before apply");
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.add_bypass("6.6.6.6");
    f.net.add_bypass("5.5.5.5"); // the main peer already has one
    f.net.add_bypass("127.0.0.1");
    f.net.add_bypass("-1.2.3.4");
    f.net.add_bypass("evil.example");
    assert_eq!(f.runner.log().iter().filter(|l| l.contains("6.6.6.6/32 via")).count(), 1);
    assert_eq!(f.runner.log().iter().filter(|l| l.contains("5.5.5.5/32 via")).count(), 1);
    assert!(!f.runner.any("127.0.0.1/32") && !f.runner.any("evil"));
    f.net.teardown();
    assert!(f.runner.has("/usr/sbin/ip route del 6.6.6.6/32"));
}

#[test]
fn bypass_uses_the_device_when_the_default_route_has_no_gateway() {
    let f = make_with(RecordingRunner::with("default dev wg0 scope link\n", vec![]));
    f.net.apply(&request("5.5.5.5")).unwrap();
    assert!(f.runner.has("/usr/sbin/ip route add 5.5.5.5/32 dev wg0"), "{:?}", f.runner.log());
}

#[test]
fn no_default_route_means_nothing_to_bypass_through() {
    let f = make_with(RecordingRunner::with("", vec![]));
    f.net.apply(&request("5.5.5.5")).unwrap();
    assert!(!f.runner.any("5.5.5.5"));
    assert!(f.runner.any("0.0.0.0/1"), "the capture still happens");
}

#[test]
fn undo_list_replays_after_a_crash_in_a_fresh_process() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    let ops = f.log.ops.lock().unwrap().clone();
    assert_eq!(ops.len(), 6, "five routes and the resolver: {ops:?}");
    let (runner, dns) = (RecordingRunner::with(DEFAULT, vec![]), Arc::new(FakeDns::default()));
    let undoer = LinuxUndoer::new(runner.clone(), dns.clone());
    for op in ops.iter().rev() {
        undoer.undo(op);
    }
    undoer.undo(&UndoOp::new("something-else", &["x"]));
    assert_eq!(runner.log().len(), 5);
    assert!(runner.has("/usr/sbin/ip route del 5.5.5.5/32") && runner.has("/usr/sbin/ip -6 route del ::/1"));
    assert_eq!(*dns.removes.lock().unwrap(), 1);
}

#[test]
fn direct_cidr_rule_carves_an_exception_out_of_the_full_capture() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = routed(RoutingRuleType::Cidr, "93.184.216.0/24", RoutingAction::Direct);
    f.net.apply(&r).unwrap();
    assert!(f.runner.any("route add 0.0.0.0/1"), "still captures by default");
    assert!(f.runner.has("/usr/sbin/ip route add 93.184.216.0/24 via 192.168.1.1 dev eth0"), "{:?}", f.runner.log());
    f.net.teardown();
    assert!(f.runner.has("/usr/sbin/ip route del 93.184.216.0/24"));
}

#[test]
fn block_rules_add_blackhole_routes_for_both_families() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = routed(RoutingRuleType::Ip, "1.2.3.4", RoutingAction::Block);
    f.net.apply(&r).unwrap();
    assert!(f.runner.has("/usr/sbin/ip route add blackhole 1.2.3.4/32"), "{:?}", f.runner.log());
    f.net.teardown();
    assert!(f.runner.has("/usr/sbin/ip route del blackhole 1.2.3.4/32"));

    let g = make();
    g.net.apply(&request("5.5.5.5")).unwrap();
    g.net.apply_dynamic_rule("2001:db8::1", RoutingAction::Block);
    assert!(g.runner.has("/usr/sbin/ip -6 route add blackhole 2001:db8::1/128"));
}

#[test]
fn default_action_direct_skips_the_full_capture_and_routes_only_proxy_rules() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(RoutingConfig {
        default_action: RoutingAction::Direct,
        rules: vec![
            RoutingRule::new(RoutingRuleType::Cidr, "8.8.8.0/24", RoutingAction::Proxy),
            RoutingRule::new(RoutingRuleType::Ip, "9.9.9.9", RoutingAction::Direct),
        ],
        ..RoutingConfig::default()
    });
    f.net.apply(&r).unwrap();
    assert!(!f.runner.any("0.0.0.0/1") && !f.runner.any("128.0.0.0/1"));
    assert!(f.runner.has(&format!("/usr/sbin/ip route add 8.8.8.0/24 via {GW} dev vpngate0")));
    assert!(!f.runner.any("9.9.9.9"));
}

#[test]
fn ipv6_rules_route_through_the_device() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = routed(RoutingRuleType::Cidr, "2001:db8::/32", RoutingAction::Direct);
    f.net.apply(&r).unwrap();
    assert!(f.runner.has("/usr/sbin/ip -6 route add 2001:db8::/32 dev eth0"), "{:?}", f.runner.log());
}

#[test]
fn option_looking_rule_values_never_reach_ip() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = routed(RoutingRuleType::Ip, "-batch", RoutingAction::Block);
    f.net.apply(&r).unwrap();
    assert!(!f.runner.any("-batch"));
}

#[test]
fn dynamic_rules_need_an_applied_tunnel_and_a_bare_ip() {
    let f = make();
    f.net.apply_dynamic_rule("1.2.3.4", RoutingAction::Proxy);
    assert!(!f.runner.any("1.2.3.4"));
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.apply_dynamic_rule("1.2.3.4", RoutingAction::Proxy);
    f.net.apply_dynamic_rule("1.2.3.4; reboot", RoutingAction::Proxy);
    assert!(f.runner.has(&format!("/usr/sbin/ip route add 1.2.3.4/32 via {GW} dev vpngate0")));
    assert!(!f.runner.any("reboot"));
}

#[test]
fn physical_dns_is_captured_and_bypassed_only_when_routing_rules_exist() {
    let f = make();
    *f.dns.physical.lock().unwrap() = vec!["192.168.1.1".into(), "127.0.0.53".into(), "fe80::1".into()];
    f.net.apply(&request("5.5.5.5")).unwrap();
    assert!(f.net.direct_dns_servers().is_empty());

    let g = make();
    *g.dns.physical.lock().unwrap() = vec!["192.168.1.1".into(), "127.0.0.53".into(), "fe80::1".into()];
    let mut r = request("5.5.5.5");
    r.routing = routed(RoutingRuleType::DomainSuffix, "example.com", RoutingAction::Direct);
    g.net.apply(&r).unwrap();
    assert_eq!(g.net.direct_dns_servers(), vec!["192.168.1.1".to_string(), "127.0.0.53".to_string()]);
    assert!(g.runner.has("/usr/sbin/ip route add 192.168.1.1/32 via 192.168.1.1 dev eth0"));
    assert!(!g.runner.any("127.0.0.53/32"));
}

#[test]
fn socks_mode_uses_a_policy_rule_and_touches_nothing_global() {
    let f = make();
    f.net.apply_socks("vpngate0", &lease(), None).unwrap();
    assert!(f.runner.has(&format!("/usr/sbin/ip route add default via {GW} dev vpngate0 table {SOCKS_TABLE}")));
    assert!(f.runner.has(&format!("/usr/sbin/ip rule add oif vpngate0 lookup {SOCKS_TABLE}")));
    assert!(!f.runner.any("0.0.0.0/1") && !f.runner.any("::/1"));
    assert!(f.dns.set_calls.lock().unwrap().is_empty());
    assert!(f.runner.index("/usr/sbin/ip addr add 10.233.145.182 peer 10.233.254.254/32 dev vpngate0").is_some());
    f.net.teardown();
    assert!(f.runner.has(&format!("/usr/sbin/ip rule del oif vpngate0 lookup {SOCKS_TABLE}")));
    assert!(f.runner.has(&format!("/usr/sbin/ip route del default via {GW} dev vpngate0 table {SOCKS_TABLE}")));
}

#[test]
fn default_route_parsing() {
    let p = parse_default_route;
    assert_eq!(
        p("default via 192.168.1.1 dev eth0 proto dhcp metric 100\ndefault via 10.0.0.1 dev wlan0 metric 600\n"),
        Some(DefaultRoute { gateway: Some("192.168.1.1".into()), iface: "eth0".into() })
    );
    assert_eq!(p("default dev ppp0 scope link"), Some(DefaultRoute { gateway: None, iface: "ppp0".into() }));
    assert_eq!(p("10.0.0.0/8 dev eth1 scope link"), None);
    assert_eq!(p(""), None);
}
