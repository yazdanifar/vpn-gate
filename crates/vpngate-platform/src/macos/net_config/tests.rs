use std::sync::Mutex;

use vpngate_core::routing_rule::{RoutingConfig, RoutingRule, RoutingRuleType};

use super::*;
use crate::CommandOutput;

const GW: &str = "10.233.254.254";

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
    out: &'static str,
}

/// Records every command line; answers `route -n get default` like a LAN with a gateway unless a rule says otherwise.
#[derive(Default)]
struct RecordingRunner {
    log: Mutex<Vec<String>>,
    rules: Mutex<Vec<Rule>>,
}

impl RecordingRunner {
    fn with(rules: Vec<Rule>) -> Arc<Self> {
        Arc::new(RecordingRunner { rules: Mutex::new(rules), ..Default::default() })
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
            return CommandOutput { status: r.status, output: r.out.to_string() };
        }
        if line.contains("get default") {
            return CommandOutput {
                status: 0,
                output: "   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n".into(),
            };
        }
        CommandOutput { status: 0, output: String::new() }
    }
}

#[derive(Default)]
struct FakeDns {
    set_calls: Mutex<Vec<Vec<String>>>,
    set_interfaces: Mutex<Vec<String>>,
    removes: Mutex<usize>,
    physical: Mutex<Vec<String>>,
}

impl FakeDns {
    fn set_calls(&self) -> Vec<Vec<String>> {
        self.set_calls.lock().unwrap().clone()
    }

    fn removes(&self) -> usize {
        *self.removes.lock().unwrap()
    }
}

impl DnsConfigurator for FakeDns {
    fn set(&self, servers: &[String], iface: &str, _address: &str, _router: &str) -> bool {
        self.set_calls.lock().unwrap().push(servers.to_vec());
        self.set_interfaces.lock().unwrap().push(iface.to_string());
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

impl MemLog {
    fn ops(&self) -> Vec<UndoOp> {
        self.ops.lock().unwrap().clone()
    }
}

struct Fixture {
    net: MacNetConfig,
    runner: Arc<RecordingRunner>,
    dns: Arc<FakeDns>,
    log: Arc<MemLog>,
}

fn make_with(runner: Arc<RecordingRunner>, dns: Arc<FakeDns>) -> Fixture {
    let log = Arc::new(MemLog::default());
    let net = MacNetConfig::new(runner.clone(), dns.clone(), log.clone());
    Fixture { net, runner, dns, log }
}

fn make() -> Fixture {
    make_with(Arc::new(RecordingRunner::default()), Arc::new(FakeDns::default()))
}

fn request(bypass: &str) -> NetApply {
    NetApply {
        iface: "utun7".into(),
        lease: lease(),
        bypass_host: bypass.into(),
        block_ipv6: true,
        mtu_override: None,
        routing: None,
        dns_proxy_address: None,
    }
}

fn domain_routing() -> RoutingConfig {
    RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::DomainSuffix, "example.com", RoutingAction::Direct)],
        ..RoutingConfig::default()
    }
}

#[test]
fn apply_runs_the_expected_commands_in_order() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    let expected = [
        "/sbin/route -n get default".to_string(),
        "/sbin/ifconfig utun7 inet 10.233.145.182 10.233.254.254 netmask 255.255.255.255 mtu 1400 up".to_string(),
        "/sbin/route -n add -host 5.5.5.5 192.168.1.1".to_string(),
        format!("/sbin/route -n add -host {GW} -interface utun7"),
        format!("/sbin/route -n add -net 0.0.0.0/1 {GW}"),
        format!("/sbin/route -n add -net 128.0.0.0/1 {GW}"),
    ];
    let idx: Vec<usize> = expected
        .iter()
        .map(|c| f.runner.index(c).unwrap_or_else(|| panic!("missing {c}; log: {:?}", f.runner.log())))
        .collect();
    assert!(idx.windows(2).all(|w| w[0] < w[1]), "commands out of order: {:?}", f.runner.log());
    assert_eq!(f.dns.set_calls(), vec![vec![GW.to_string(), "8.8.8.8".to_string()]]);
    assert_eq!(*f.dns.set_interfaces.lock().unwrap(), vec!["utun7".to_string()]);
    assert!(f.log.ops().contains(&UndoOp::new(UNDO_DNS, &[])), "undo list persisted for crash recovery");
}

#[test]
fn teardown_removes_what_apply_added() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    for c in [
        format!("/sbin/route -n delete -net 0.0.0.0/1 {GW}"),
        format!("/sbin/route -n delete -net 128.0.0.0/1 {GW}"),
        format!("/sbin/route -n delete -host {GW}"),
        "/sbin/route -n delete -host 5.5.5.5".to_string(),
    ] {
        assert!(f.runner.has(&c), "missing {c}");
    }
    assert_eq!(f.dns.removes(), 1);
    assert!(f.log.ops().is_empty(), "undo list cleared after a clean teardown");
    f.net.teardown(); // a second teardown is a no-op
    assert_eq!(f.dns.removes(), 1);
}

#[test]
fn no_dns_servers_means_no_dns_changes() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.lease.dns.clear();
    f.net.apply(&r).unwrap();
    f.net.teardown();
    assert!(f.dns.set_calls().is_empty());
    assert_eq!(f.dns.removes(), 0);
}

#[test]
fn dns_proxy_address_is_published_instead_of_the_lease_dns() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.dns_proxy_address = Some("127.0.0.1".into());
    f.net.apply(&r).unwrap();
    assert_eq!(f.dns.set_calls(), vec![vec!["127.0.0.1".to_string()]]);
}

#[test]
fn loopback_proxy_gets_no_bypass_route_and_is_never_deleted() {
    let f = make();
    f.net.apply(&request("127.0.0.1")).unwrap();
    f.net.teardown();
    assert!(!f.runner.any("-host 127.0.0.1"), "touched the loopback host route: {:?}", f.runner.log());
}

#[test]
fn teardown_leaves_routes_it_did_not_create() {
    let f = make_with(
        RecordingRunner::with(vec![Rule { contains: "add -host 5.5.5.5", status: 1, out: "File exists" }]),
        Arc::default(),
    );
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    assert!(!f.runner.any("delete -host 5.5.5.5"), "deleted a pre-existing route: {:?}", f.runner.log());
    assert!(f.runner.any("delete -net 0.0.0.0/1"), "still removes its own routes");
}

#[test]
fn failed_default_capture_is_not_deleted_either() {
    let f = make_with(
        RecordingRunner::with(vec![Rule { contains: "add -net 128.0.0.0/1", status: 1, out: "File exists" }]),
        Arc::default(),
    );
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.teardown();
    assert!(!f.runner.any("delete -net 128.0.0.0/1"), "deleted a route it never added");
}

#[test]
fn blocks_ipv6_through_the_tunnel() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    assert!(f.runner.has("/sbin/route -n add -inet6 ::/1 -interface utun7"), "{:?}", f.runner.log());
    assert!(f.runner.has("/sbin/route -n add -inet6 8000::/1 -interface utun7"));
    assert!(
        !f.runner.any("inet6 ::1") && !f.runner.log().iter().any(|l| l.contains("ifconfig") && l.contains("inet6"))
    );
    f.net.teardown();
    assert!(f.runner.has("/sbin/route -n delete -inet6 ::/1 -interface utun7"));
    assert!(f.runner.has("/sbin/route -n delete -inet6 8000::/1 -interface utun7"));
}

#[test]
fn ipv6_enabled_still_captures_the_v6_space_but_adds_no_address_until_slaac() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.block_ipv6 = false;
    f.net.apply(&r).unwrap();
    assert!(
        f.runner.has("/sbin/route -n add -inet6 ::/1 -interface utun7"),
        "native IPv6 would leak around the tunnel"
    );
    assert!(f.runner.has("/sbin/route -n add -inet6 8000::/1 -interface utun7"));
    assert!(!f.runner.log().iter().any(|l| l.contains("ifconfig") && l.contains("inet6")));
}

#[test]
fn slaac_address_is_configured_on_the_utun() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.configure_ipv6("2001:db8:1:2:5c00:11ff:fe22:3344".parse().unwrap(), 64);
    assert_eq!(
        f.runner.log().last().unwrap(),
        "/sbin/ifconfig utun7 inet6 2001:db8:1:2:5c00:11ff:fe22:3344 prefixlen 64"
    );
    let before = f.runner.log().len();
    for bad in ["::", "ff02::1", "fe80::1"] {
        f.net.configure_ipv6(bad.parse().unwrap(), 64);
    }
    f.net.configure_ipv6("2001:db8::1".parse().unwrap(), 0);
    f.net.configure_ipv6("2001:db8::1".parse().unwrap(), 129);
    assert_eq!(f.runner.log().len(), before, "unusable addresses must not reach ifconfig");
    f.net.teardown();
    let g = make();
    g.net.configure_ipv6("2001:db8::1".parse().unwrap(), 64); // before apply / after teardown
    assert!(g.runner.log().is_empty(), "no interface to configure");
}

#[test]
fn dhcp_mtu_is_used_only_within_576_to_1500() {
    for (mtu, want) in [
        (Some(1280u16), "1280"),
        (Some(576), "576"),
        (Some(1500), "1500"),
        (Some(575), "1400"),
        (Some(1501), "1400"),
        (Some(9000), "1400"),
        (Some(0), "1400"),
        (None, "1400"),
    ] {
        let f = make();
        let mut r = request("5.5.5.5");
        r.lease.mtu = mtu;
        f.net.apply(&r).unwrap();
        assert!(
            f.runner
                .log()
                .iter()
                .any(|l| l.starts_with("/sbin/ifconfig utun7 inet ") && l.ends_with(&format!("mtu {want} up"))),
            "mtu {mtu:?}: {:?}",
            f.runner.log()
        );
    }
}

#[test]
fn account_mtu_wins_over_the_lease() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.lease.mtu = Some(1300);
    r.mtu_override = Some(1200);
    f.net.apply(&r).unwrap();
    assert!(f.runner.any("mtu 1200 up"), "{:?}", f.runner.log());
}

#[test]
fn further_peers_get_bypass_routes_that_teardown_removes() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.add_bypass("6.6.6.6");
    f.net.add_bypass("7.7.7.7");
    let capture = f.runner.index(&format!("/sbin/route -n add -net 128.0.0.0/1 {GW}")).unwrap();
    let i6 = f.runner.index("/sbin/route -n add -host 6.6.6.6 192.168.1.1").unwrap();
    let i7 = f.runner.index("/sbin/route -n add -host 7.7.7.7 192.168.1.1").unwrap();
    assert!(i6 > capture && i7 > i6, "added after apply, in call order");
    f.net.teardown();
    let log = f.runner.log();
    let last = |c: &str| log.iter().rposition(|l| l == c).unwrap();
    assert!(last("/sbin/route -n delete -host 7.7.7.7") < last("/sbin/route -n delete -host 6.6.6.6"), "reverse order");
}

#[test]
fn bypass_route_uses_the_interface_when_the_default_route_has_no_gateway() {
    let f = make_with(
        RecordingRunner::with(vec![Rule {
            contains: "get default",
            status: 0,
            out: "    gateway: link#14\n  interface: en0\n",
        }]),
        Arc::default(),
    );
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.add_bypass("6.6.6.6");
    assert!(f.runner.has("/sbin/route -n add -host 6.6.6.6 -interface en0"), "{:?}", f.runner.log());
    assert!(f.runner.has("/sbin/route -n add -host 5.5.5.5 -interface en0"));
}

#[test]
fn no_default_route_means_nothing_to_bypass_through() {
    let f = make_with(
        RecordingRunner::with(vec![Rule { contains: "get default", status: 1, out: "route: not in table" }]),
        Arc::default(),
    );
    f.net.apply(&request("5.5.5.5")).unwrap();
    assert!(!f.runner.any("add -host 5.5.5.5"));
}

#[test]
fn bypass_hosts_survive_a_crash_via_the_undo_log() {
    let f = make();
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.add_bypass("6.6.6.6");
    let ops = f.log.ops();
    assert!(ops.contains(&UndoOp::new(UNDO_ROUTE, &["-host", "6.6.6.6"])), "{ops:?}");
    // the daemon was killed with -9: the next start replays the persisted list, newest first
    let runner = Arc::new(RecordingRunner::default());
    let undoer = MacUndoer::new(runner.clone(), Arc::new(FakeDns::default()));
    for op in ops.iter().rev() {
        undoer.undo(op);
    }
    assert!(runner.has("/sbin/route -n delete -host 6.6.6.6"), "{:?}", runner.log());
}

#[test]
fn bypass_route_that_failed_or_pre_existed_is_not_deleted() {
    let f = make_with(
        RecordingRunner::with(vec![Rule { contains: "add -host 6.6.6.6", status: 1, out: "File exists" }]),
        Arc::default(),
    );
    f.net.apply(&request("5.5.5.5")).unwrap();
    f.net.add_bypass("6.6.6.6");
    f.net.teardown();
    assert!(!f.runner.any("delete -host 6.6.6.6"));
}

#[test]
fn bypass_rejects_anything_but_a_public_ipv4_literal() {
    let f = make();
    f.net.add_bypass("6.6.6.6"); // before apply: no tunnel, no state
    assert!(f.runner.log().is_empty(), "nothing to bypass before apply");
    f.net.apply(&request("5.5.5.5")).unwrap();
    let before = f.runner.log().len();
    for bad in [
        "",
        "example.com",
        "6.6.6.6; reboot",
        "6.6.6.6 -interface lo0",
        "-net",
        "::1",
        "2001:db8::1",
        "300.1.1.1",
        "1.2.3",
        "1.2.3.4.5",
        "127.0.0.1",
        "169.254.1.1",
        "0.0.0.0",
        "5.5.5.5",
        " 6.6.6.6",
        "6.6.6.6\n",
    ] {
        f.net.add_bypass(bad);
    }
    assert_eq!(f.runner.log().len(), before, "route was invoked for a rejected host: {:?}", &f.runner.log()[before..]);
    f.net.teardown();
    f.net.add_bypass("8.8.8.8"); // after teardown
    assert!(!f.runner.any("8.8.8.8"));
}

#[test]
fn undo_list_has_only_routes_that_were_added_and_replays_after_a_crash() {
    let f = make_with(
        RecordingRunner::with(vec![Rule { contains: "add -host 5.5.5.5", status: 1, out: "File exists" }]),
        Arc::default(),
    );
    f.net.apply(&request("5.5.5.5")).unwrap();
    let ops = f.log.ops();
    assert!(!ops.contains(&UndoOp::new(UNDO_ROUTE, &["-host", "5.5.5.5"])));
    assert!(ops.contains(&UndoOp::new(UNDO_ROUTE, &["-net", "0.0.0.0/1", GW])));
    let runner = Arc::new(RecordingRunner::default());
    let dns = Arc::new(FakeDns::default());
    let undoer = MacUndoer::new(runner.clone(), dns.clone());
    for op in ops.iter().rev() {
        undoer.undo(op);
    }
    assert!(!runner.any("delete -host 5.5.5.5"));
    assert!(runner.any("delete -net 0.0.0.0/1"));
    assert_eq!(dns.removes(), 1);
}

#[test]
fn unknown_undo_kinds_are_ignored() {
    let runner = Arc::new(RecordingRunner::default());
    MacUndoer::new(runner.clone(), Arc::new(FakeDns::default())).undo(&UndoOp::new("made-up", &["x"]));
    assert!(runner.log().is_empty());
}

#[test]
fn direct_cidr_rule_carves_an_exception_out_of_the_full_capture() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::Cidr, "93.184.216.0/24", RoutingAction::Direct)],
        ..RoutingConfig::default()
    });
    f.net.apply(&r).unwrap();
    assert!(f.runner.has(&format!("/sbin/route -n add -net 0.0.0.0/1 {GW}")), "still captures by default");
    assert!(f.runner.has("/sbin/route -n add -net 93.184.216.0/24 192.168.1.1"), "{:?}", f.runner.log());
    f.net.teardown();
    assert!(f.runner.has("/sbin/route -n delete -net 93.184.216.0/24"));
}

#[test]
fn block_ip_rule_adds_a_blackhole_route() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::Ip, "1.2.3.4", RoutingAction::Block)],
        ..RoutingConfig::default()
    });
    f.net.apply(&r).unwrap();
    assert!(f.runner.has("/sbin/route -n add -host 1.2.3.4 -blackhole"), "{:?}", f.runner.log());
}

#[test]
fn default_action_direct_skips_the_full_capture_and_routes_only_proxy_rules() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(RoutingConfig {
        rules: vec![RoutingRule::new(RoutingRuleType::Cidr, "10.20.0.0/16", RoutingAction::Proxy)],
        default_action: RoutingAction::Direct,
        bypass_private_networks: false,
    });
    f.net.apply(&r).unwrap();
    assert!(!f.runner.any("-net 0.0.0.0/1") && !f.runner.any("-net 128.0.0.0/1"), "must not capture everything");
    assert!(f.runner.has(&format!("/sbin/route -n add -net 10.20.0.0/16 {GW}")), "{:?}", f.runner.log());
}

#[test]
fn ipv6_rules_route_through_the_interface() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(RoutingConfig {
        rules: vec![
            RoutingRule::new(RoutingRuleType::Cidr, "2001:db8::/32", RoutingAction::Direct),
            RoutingRule::new(RoutingRuleType::Ip, "2001:db8:1::1", RoutingAction::Block),
        ],
        ..RoutingConfig::default()
    });
    f.net.apply(&r).unwrap();
    assert!(f.runner.has("/sbin/route -n add -inet6 -net 2001:db8::/32 -interface en0"), "{:?}", f.runner.log());
    assert!(f.runner.has("/sbin/route -n add -inet6 -host 2001:db8:1::1 -blackhole"));
}

#[test]
fn empty_routing_config_behaves_exactly_like_no_routing_at_all() {
    let (a, b) = (make(), make());
    a.net.apply(&request("5.5.5.5")).unwrap();
    let mut r = request("5.5.5.5");
    r.routing = Some(RoutingConfig::default());
    b.net.apply(&r).unwrap();
    assert_eq!(a.runner.log(), b.runner.log());
}

#[test]
fn dynamic_rule_adds_a_route_for_a_resolved_address_after_apply() {
    let f = make();
    let mut r = request("5.5.5.5");
    r.routing = Some(domain_routing());
    f.net.apply(&r).unwrap();
    f.net.apply_dynamic_rule("93.184.216.34", RoutingAction::Direct);
    assert!(f.runner.has("/sbin/route -n add -host 93.184.216.34 192.168.1.1"), "{:?}", f.runner.log());
    f.net.teardown();
    assert!(f.runner.has("/sbin/route -n delete -host 93.184.216.34"), "dynamic route must be cleaned up too");
}

#[test]
fn dynamic_rule_rejects_anything_that_is_not_a_bare_ip_literal_and_is_a_no_op_before_apply() {
    let f = make();
    f.net.apply_dynamic_rule("93.184.216.34", RoutingAction::Direct); // before apply
    assert!(f.runner.log().is_empty());
    f.net.apply(&request("5.5.5.5")).unwrap();
    let before = f.runner.log().len();
    for bad in ["", "not-an-ip", "93.184.216.0/24", "93.184.216.34; reboot"] {
        f.net.apply_dynamic_rule(bad, RoutingAction::Direct);
    }
    assert_eq!(f.runner.log().len(), before, "{:?}", &f.runner.log()[before..]);
}

#[test]
fn physical_dns_is_captured_and_bypassed_only_when_routing_rules_are_configured() {
    let dns = Arc::new(FakeDns::default());
    *dns.physical.lock().unwrap() = vec!["9.9.9.9".into(), "fe80::1".into()];
    let f = make_with(Arc::new(RecordingRunner::default()), dns);
    let mut r = request("5.5.5.5");
    r.routing = Some(domain_routing());
    f.net.apply(&r).unwrap();
    assert_eq!(f.net.direct_dns_servers(), vec!["9.9.9.9".to_string()], "IPv4 literals only");
    assert!(f.runner.has("/sbin/route -n add -host 9.9.9.9 192.168.1.1"), "{:?}", f.runner.log());

    let dns = Arc::new(FakeDns::default());
    *dns.physical.lock().unwrap() = vec!["9.9.9.9".into()];
    let g = make_with(Arc::new(RecordingRunner::default()), dns);
    g.net.apply(&request("5.5.5.5")).unwrap(); // no routing configured
    assert!(g.net.direct_dns_servers().is_empty());
    assert!(!g.runner.any("9.9.9.9"), "must not touch an address nothing needs");
}

#[test]
fn socks_mode_installs_only_interface_scoped_routes() {
    let f = make();
    f.net.apply_socks("utun7", &lease(), Some(1300)).unwrap();
    assert!(f.runner.any("mtu 1300 up"));
    assert!(f.runner.has(&format!("/sbin/route -n add -ifscope utun7 -host {GW} -interface utun7")));
    assert!(f.runner.has(&format!("/sbin/route -n add -ifscope utun7 default {GW}")));
    assert!(!f.runner.any("0.0.0.0/1") && !f.runner.any("inet6") && f.dns.set_calls().is_empty());
    f.net.teardown();
    assert!(f.runner.has(&format!("/sbin/route -n delete -ifscope utun7 default {GW}")));
}

#[test]
fn default_route_parsing() {
    assert_eq!(
        parse_default_route("   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n"),
        Some(DefaultRoute { gateway: Some("192.168.1.1".into()), iface: "en0".into() })
    );
    assert_eq!(
        parse_default_route("gateway: link#14\ninterface: en0"),
        Some(DefaultRoute { gateway: None, iface: "en0".into() })
    );
    assert_eq!(parse_default_route("route: not in table"), None);
}
