use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::time::Instant;
use vpngate_testkit::golden::{load, unhex};

use super::*;
use crate::testing::fake_network::FakeNetworkServer;
use crate::testing::replay_entropy::ReplayEntropy;

const GW: u32 = 0x0AE9_FEFE;
const MY_IP: u32 = 0x0AE9_91B6;
const V6_MAC: Mac = [0x5E, 0x00, 0x11, 0x22, 0x33, 0x44];
const PEER_MAC: Mac = [0x02, 0, 0, 0, 0, 0x01];
const SLAAC: &str = "20010db8000100025c0011fffe223344";

type Frames = Arc<Mutex<Vec<Vec<u8>>>>;

fn hex6(s: &str) -> Ipv6Addr {
    s.parse::<std::net::Ipv6Addr>().unwrap().octets()
}

fn bytes(s: &str) -> Vec<u8> {
    unhex(s)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn frames() -> Frames {
    Arc::new(Mutex::new(Vec::new()))
}

fn take(f: &Frames) -> Vec<Vec<u8>> {
    std::mem::take(&mut *f.lock().unwrap())
}

fn count(f: &Frames) -> usize {
    f.lock().unwrap().len()
}

fn dhcp_options(p: &[u8]) -> HashMap<u8, Vec<u8>> {
    let mut out = HashMap::new();
    let mut i = 240;
    while i < p.len() && p[i] != 255 {
        if p[i] == 0 {
            i += 1;
            continue;
        }
        let l = usize::from(p[i + 1]);
        out.insert(p[i], p[i + 2..i + 2 + l].to_vec());
        i += 2 + l;
    }
    out
}

fn timing(dhcp_timeout: f64, dhcp_retries: u32) -> BridgeTiming {
    BridgeTiming { dhcp_timeout, dhcp_retries, ..BridgeTiming::default() }
}

/// A bridge wired to the fake hub: its frames go to `net`, the replies come straight back.
fn make_bridge(net: &Arc<FakeNetworkServer>, timeout: f64, retries: u32) -> Arc<EthernetBridge> {
    let b = EthernetBridge::new(timing(timeout, retries));
    wire(&b, net);
    b
}

fn wire(b: &Arc<EthernetBridge>, net: &Arc<FakeNetworkServer>) {
    let (weak, net): (Weak<EthernetBridge>, _) = (Arc::downgrade(b), net.clone());
    b.set_send_frame(move |f| {
        for r in net.handle(&f) {
            if let Some(b) = weak.upgrade() {
                b.from_hub(&r);
            }
        }
    });
}

fn host_packet(dst: u32, payload: [u8; 4]) -> Vec<u8> {
    ipv4_packet(6, MY_IP, dst, &payload)
}

fn ipv4_frame(dst_mac: Mac, dst: u32) -> Vec<u8> {
    ethernet_frame(dst_mac, [0, 1, 2, 3, 4, 5], 0x0800, &ipv4_packet(6, 1, dst, &[1, 2, 3, 4]))
}

fn controlled_clock(b: &EthernetBridge, start: f64) -> Arc<Mutex<f64>> {
    let t = Arc::new(Mutex::new(start));
    let c = t.clone();
    b.set_clock(move || *c.lock().unwrap());
    t
}

fn advance(t: &Arc<Mutex<f64>>, by: f64) {
    *t.lock().unwrap() += by;
}

fn arp_reply_from_gateway(net: &FakeNetworkServer, b: &EthernetBridge) -> Vec<u8> {
    let r =
        ArpPacket { op: 2, sender_mac: net.config().gateway_mac, sender_ip: GW, target_mac: b.mac(), target_ip: MY_IP };
    ethernet_frame(b.mac(), net.config().gateway_mac, 0x0806, &r.encode())
}

// MARK: IPv4

#[tokio::test]
async fn dhcp_discover_offer_request_ack() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    let l = b.acquire_lease().await.unwrap();
    assert_eq!((l.ip, l.router, l.mask), (MY_IP, GW, 0xFFFF_0000));
    assert_eq!(l.dns, [GW, 0x0808_0808]);
    assert_eq!((l.seconds, l.server_id), (3600, GW));
    assert_eq!((net.count(DhcpType::Discover), net.count(DhcpType::Request)), (1, 1));
    // REQUEST selects the offered address from the offering server
    let req = net.dhcp_messages().into_iter().find(|m| m.0 == DhcpType::Request).unwrap().1;
    let o = dhcp_options(&req);
    assert_eq!(o[&50], be32(MY_IP));
    assert_eq!(o[&54], be32(GW));
}

#[tokio::test]
async fn dhcp_fails_when_nobody_answers() {
    let net = Arc::new(FakeNetworkServer::new());
    net.configure(|c| c.silent = true);
    let b = make_bridge(&net, 0.1, 2);
    assert!(matches!(b.acquire_lease().await, Err(StreamError::Protocol(_))));
    assert_eq!(net.count(DhcpType::Discover), 2);
}

#[tokio::test]
async fn dhcp_ignores_replies_with_foreign_xid() {
    let b = EthernetBridge::new(timing(0.3, 1));
    let real = FakeNetworkServer::new();
    let weak = Arc::downgrade(&b);
    b.set_send_frame(move |f| {
        for mut r in real.handle(&f) {
            r[14 + 20 + 8 + 4] ^= 0xFF; // corrupt xid inside the BOOTP header
            weak.upgrade().unwrap().from_hub(&r);
        }
    });
    assert!(b.acquire_lease().await.is_err());
}

#[tokio::test]
async fn dhcp_nak_restarts_immediately() {
    let net = Arc::new(FakeNetworkServer::new());
    net.configure(|c| c.nak_count = 1);
    let b = make_bridge(&net, 2.0, 3);
    let start = Instant::now();
    assert_eq!(b.acquire_lease().await.unwrap().ip, MY_IP);
    assert!(start.elapsed() < Duration::from_secs(1), "NAK should trigger an immediate new DISCOVER");
    assert_eq!(net.count(DhcpType::Discover), 2);
}

#[tokio::test]
async fn renew_uses_ciaddr_not_selecting_options() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    b.renew().await;
    let renew = net.dhcp_messages().into_iter().rfind(|m| m.0 == DhcpType::Request).unwrap().1;
    assert_eq!(renew[12..16], be32(MY_IP), "ciaddr");
    let o = dhcp_options(&renew);
    assert!(!o.contains_key(&50) && !o.contains_key(&54), "renewing requests carry no requested-ip/server-id");
}

#[tokio::test]
async fn renew_with_new_address_reports_change() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let changed = Arc::new(Mutex::new(None::<Lease>));
    let c = changed.clone();
    b.set_on_lease_changed(move |l| *c.lock().unwrap() = Some(l));
    net.configure(|c| c.renew_ip = Some(0x0AE9_9999));
    b.renew().await;
    assert_eq!(changed.lock().unwrap().as_ref().map(|l| l.ip), Some(0x0AE9_9999));
    assert_eq!(b.lease().unwrap().ip, 0x0AE9_9999);
}

#[tokio::test]
async fn renew_silence_or_nak_reports_lease_lost() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.2, 3);
    b.acquire_lease().await.unwrap();
    let lost = Arc::new(Mutex::new(0));
    let l = lost.clone();
    b.set_on_lease_lost(move || *l.lock().unwrap() += 1);
    net.configure(|c| c.nak_count = 1);
    b.renew().await;
    assert_eq!(*lost.lock().unwrap(), 1, "NAK on renew");
    net.configure(|c| c.silent = true);
    b.renew().await;
    assert_eq!(*lost.lock().unwrap(), 2, "no answer to renew");
}

#[tokio::test]
async fn arp_for_unresolved_next_hop_is_rate_limited() {
    let net = Arc::new(FakeNetworkServer::new());
    net.configure(|c| c.answer_arp = false);
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let t = controlled_clock(&b, 1000.0);
    let asks = || net.arp_request_targets().iter().filter(|&&x| x == GW).count();
    for _ in 0..50 {
        b.from_host(&host_packet(0x0808_0808, [9; 4]));
    }
    assert_eq!(asks(), 1, "ARP requests for the gateway within one second");
    advance(&t, 1.1);
    b.from_host(&host_packet(0x0808_0808, [9; 4]));
    assert_eq!(asks(), 2, "retry after the interval");
}

#[tokio::test]
async fn queued_packets_flush_in_order_after_arp_reply() {
    let net = Arc::new(FakeNetworkServer::new());
    net.configure(|c| c.answer_arp = false);
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let pkts: Vec<_> = (1..=3).map(|i| host_packet(0x0808_0808, [i, 0, 0, 0])).collect();
    for p in &pkts {
        b.from_host(p);
    }
    assert!(net.ipv4_packets().is_empty());
    b.from_hub(&arp_reply_from_gateway(&net, &b));
    assert_eq!(net.ipv4_packets(), pkts);
}

#[tokio::test]
async fn stale_queued_packets_are_dropped() {
    let net = Arc::new(FakeNetworkServer::new());
    net.configure(|c| c.answer_arp = false);
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let t = controlled_clock(&b, 1000.0);
    b.from_host(&host_packet(0x0808_0808, [9; 4]));
    b.from_host(&host_packet(0x0808_0808, [9; 4]));
    advance(&t, 4.0);
    b.from_hub(&arp_reply_from_gateway(&net, &b));
    assert!(net.ipv4_packets().is_empty(), "packets queued 4s ago must not be sent late");
}

#[tokio::test]
async fn arp_cache_entries_expire() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let t = controlled_clock(&b, 1000.0);
    let asks = || net.arp_request_targets().iter().filter(|&&x| x == GW).count();
    b.from_host(&host_packet(0x0808_0808, [9; 4]));
    assert_eq!(asks(), 1);
    b.from_host(&host_packet(0x0808_0808, [9; 4]));
    assert_eq!(asks(), 1, "cached");
    advance(&t, 61.0);
    b.from_host(&host_packet(0x0808_0808, [9; 4]));
    assert_eq!(asks(), 2, "re-resolved after the entry aged out");
    assert_eq!(net.ipv4_packets().len(), 3, "no packet lost while re-resolving");
}

#[tokio::test]
async fn answers_arp_only_for_own_address() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let out = frames();
    let o = out.clone();
    b.set_send_frame(move |f| o.lock().unwrap().push(f));
    let ask = |target: u32| {
        let a = ArpPacket {
            op: 1,
            sender_mac: net.config().gateway_mac,
            sender_ip: GW,
            target_mac: ZERO_MAC,
            target_ip: target,
        };
        b.from_hub(&ethernet_frame(BROADCAST_MAC, net.config().gateway_mac, 0x0806, &a.encode()));
    };
    ask(0x0A0A_0A0A);
    assert_eq!(count(&out), 0);
    ask(MY_IP);
    let sent = take(&out);
    assert_eq!(sent.len(), 1);
    let r = ArpPacket::parse(&sent[0][14..]).unwrap();
    assert_eq!((r.op, r.sender_ip, r.sender_mac), (2, MY_IP, b.mac()));
}

#[tokio::test]
async fn delivers_ipv4_for_us_and_drops_the_rest() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    let got = Arc::new(Mutex::new(0));
    let g = got.clone();
    b.set_deliver_ipv4(move |_| *g.lock().unwrap() += 1);
    b.from_hub(&ipv4_frame(b.mac(), MY_IP));
    assert_eq!(*got.lock().unwrap(), 1, "unicast to us");
    b.from_hub(&ipv4_frame(BROADCAST_MAC, 0xFFFF_FFFF));
    assert_eq!(*got.lock().unwrap(), 2, "broadcast");
    b.from_hub(&ipv4_frame([0x02, 9, 9, 9, 9, 9], MY_IP));
    assert_eq!(*got.lock().unwrap(), 2, "foreign unicast");
    b.from_hub(&ethernet_frame(b.mac(), [1, 2, 3, 4, 5, 6], 0x86DD, &[0; 40]));
    assert_eq!(*got.lock().unwrap(), 2, "IPv6 payload without an RA is not an IPv4 delivery");
    b.from_hub(&[1, 2, 3]); // runt frame
}

#[tokio::test]
async fn nothing_is_delivered_before_a_lease() {
    let b = EthernetBridge::new(BridgeTiming::default());
    let got = Arc::new(Mutex::new(0));
    let g = got.clone();
    b.set_deliver_ipv4(move |_| *g.lock().unwrap() += 1);
    let s = got.clone();
    b.set_send_frame(move |_| *s.lock().unwrap() += 100);
    b.from_hub(&ipv4_frame(b.mac(), 2));
    b.from_host(&host_packet(5, [9; 4]));
    assert_eq!(*got.lock().unwrap(), 0);
}

#[tokio::test]
async fn host_packets_on_link_broadcast_and_offlink() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    b.from_host(&host_packet(0x0AE9_0101, [9; 4]));
    assert!(net.arp_request_targets().contains(&0x0AE9_0101), "on-link destination is resolved directly");
    let before = net.arp_request_targets().len();
    b.from_host(&host_packet(0xFFFF_FFFF, [9; 4]));
    assert_eq!(net.arp_request_targets().len(), before, "broadcast needs no ARP");
    b.from_host(&host_packet(0x0101_0101, [9; 4]));
    assert!(net.arp_request_targets().contains(&GW), "off-link destination goes via the router");
}

#[tokio::test]
async fn gratuitous_arp_announces_our_address() {
    let net = Arc::new(FakeNetworkServer::new());
    let b = make_bridge(&net, 0.5, 3);
    b.acquire_lease().await.unwrap();
    b.gratuitous_arp();
    assert!(net.arp_request_targets().contains(&MY_IP));
}

#[test]
fn mac_is_unicast_and_prefixed() {
    for _ in 0..50 {
        let m = EthernetBridge::new(BridgeTiming::default()).mac();
        assert_eq!(m[0], 0x5E);
        assert_eq!(m[0] & 1, 0, "unicast");
    }
}

// MARK: IPv6

fn v6_bridge(timing: BridgeTiming) -> (Arc<EthernetBridge>, Frames) {
    let b = EthernetBridge::with(timing, Some(V6_MAC), Box::new(SystemEntropy));
    let out = frames();
    let o = out.clone();
    b.set_send_frame(move |f| o.lock().unwrap().push(f));
    (b, out)
}

fn v6_local() -> Ipv6Addr {
    hex6("fe80::5c00:11ff:fe22:3344")
}

/// Ethernet frame carrying an ICMPv6 message; the checksum is filled in unless `corrupt` flips it afterwards.
fn icmp6_frame(
    dst_mac: Mac,
    src_mac: Mac,
    src: Ipv6Addr,
    dst: Ipv6Addr,
    icmp: &[u8],
    hop: u8,
    corrupt: bool,
) -> Vec<u8> {
    let mut m = icmp.to_vec();
    m[2] = 0;
    m[3] = 0;
    let c = icmpv6_checksum(&src, &dst, &m);
    m[2] = (c >> 8) as u8;
    m[3] = (c & 0xff) as u8 ^ u8::from(corrupt);
    let mut ip = ipv6_header(&src, &dst, 58, m.len() as u16, hop);
    ip.extend(m);
    ethernet_frame(dst_mac, src_mac, 0x86DD, &ip)
}

struct Ns {
    target: Ipv6Addr,
    src: Ipv6Addr,
    dst: Option<Ipv6Addr>,
    hop: u8,
    corrupt: bool,
}

fn ns(target: Ipv6Addr) -> Ns {
    Ns { target, src: hex6("fe80::1"), dst: None, hop: 255, corrupt: false }
}

fn ns_frame(n: Ns) -> Vec<u8> {
    let dst = n.dst.unwrap_or_else(|| ipv6_solicited_node_multicast(&n.target));
    let icmp = icmpv6_neighbor_solicitation(&n.target, &PEER_MAC, &n.src, &dst);
    icmp6_frame(V6_MAC, PEER_MAC, n.src, dst, &icmp, n.hop, n.corrupt)
}

struct Ra {
    prefix: &'static str,
    flags: u8,
    valid: u32,
    preferred: u32,
    router_lifetime: u16,
    src: Ipv6Addr,
    hop: u8,
    prefix_len: u8,
}

fn ra() -> Ra {
    Ra {
        prefix: "2001:db8:1:2::",
        flags: 0xC0,
        valid: 86400,
        preferred: 14400,
        router_lifetime: 1800,
        src: hex6("fe80::1"),
        hop: 255,
        prefix_len: 64,
    }
}

fn ra_frame(r: Ra) -> Vec<u8> {
    let mut icmp = vec![134, 0, 0, 0, 64, 0];
    icmp.extend(be16(r.router_lifetime));
    icmp.extend([0; 8]);
    icmp.extend([1, 1]);
    icmp.extend(PEER_MAC);
    icmp.extend([3, 4, r.prefix_len, r.flags]);
    icmp.extend(be32(r.valid));
    icmp.extend(be32(r.preferred));
    icmp.extend([0; 4]);
    icmp.extend(hex6(r.prefix));
    icmp6_frame(ipv6_multicast_mac(&ALL_NODES), PEER_MAC, r.src, ALL_NODES, &icmp, r.hop, false)
}

fn icmp_type(frame: &[u8]) -> u8 {
    frame[14 + 40]
}

fn v6_data_packet(dst: &str) -> Vec<u8> {
    let mut p = ipv6_header(&hex6("2001:db8:1:2:5c00:11ff:fe22:3344"), &hex6(dst), 17, 4, 64);
    p.extend([1, 2, 3, 4]);
    p
}

#[test]
fn ns_is_answered_to_the_askers_mac_with_hop_limit_255() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    // The NS frame goes to our solicited-node multicast MAC; the NA must NOT be sent there.
    b.from_hub(&ns_frame(ns(v6_local())));
    // Exact frame from an independent encoder: dst = asker's MAC, hop limit ff, S+O flags, TLLA = our MAC.
    assert_eq!(
        take(&out),
        [bytes(concat!(
            "0200000000015e001122334486dd6000000000203afffe800000000000005c0011fffe223344",
            "fe800000000000000000000000000001880038ec60000000fe800000000000005c0011fffe22334402015e0011223344"
        ))]
    );
}

#[test]
fn dad_probe_is_answered_to_all_nodes_with_solicited_clear() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    b.from_hub(&ns_frame(Ns { src: hex6("::"), ..ns(v6_local()) }));
    assert_eq!(
        take(&out),
        [bytes(concat!(
            "3333000000015e001122334486dd6000000000203afffe800000000000005c0011fffe223344",
            "ff0200000000000000000000000000018800786a20000000fe800000000000005c0011fffe22334402015e0011223344"
        ))]
    );
}

#[test]
fn invalid_or_foreign_solicitations_are_ignored() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    b.from_hub(&ns_frame(ns(hex6("fe80::9")))); // not our address
    b.from_hub(&ns_frame(Ns { hop: 64, ..ns(v6_local()) })); // crossed a router
    b.from_hub(&ns_frame(Ns { corrupt: true, ..ns(v6_local()) })); // bad checksum
    b.from_hub(&ns_frame(Ns { dst: Some(hex6("ff02::1:ff00:7")), ..ns(v6_local()) })); // wrong group
    assert_eq!(count(&out), 0);
    b.set_handle_ipv6(false);
    b.from_hub(&ns_frame(ns(v6_local())));
    assert_eq!(count(&out), 0, "IPv6 disabled");
}

#[tokio::test]
async fn ra_yields_a_slaac_address_and_is_not_passed_to_the_kernel() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    let addr = Arc::new(Mutex::new(Vec::new()));
    let delivered = Arc::new(Mutex::new(0));
    let d = delivered.clone();
    b.set_deliver_ipv6(move |_| *d.lock().unwrap() += 1);
    let a = addr.clone();
    b.start_ipv6(move |ip, len| a.lock().unwrap().push((ip, len)));
    b.from_hub(&ra_frame(ra()));
    b.from_hub(&ra_frame(ra())); // refresh: reported only once
    assert_eq!(*addr.lock().unwrap(), [(bytes(SLAAC).try_into().unwrap(), 64)]);
    assert_eq!(b.router_ipv6(), Some(hex6("fe80::1")));
    assert_eq!(b.ipv6_address(), Some(bytes(SLAAC).try_into().unwrap()));
    assert_eq!(*delivered.lock().unwrap(), 0, "NDP is consumed by the bridge");
    // we now own the SLAAC address and answer for it
    take(&out);
    b.from_hub(&ns_frame(ns(bytes(SLAAC).try_into().unwrap())));
    assert_eq!(take(&out).iter().filter(|f| icmp_type(f) == 136).count(), 1, "NA for the SLAAC address");
}

#[tokio::test]
async fn address_is_reported_to_a_late_observer() {
    let (b, _) = v6_bridge(BridgeTiming::default());
    b.from_hub(&ra_frame(ra())); // RA arrives before the netconfig exists
    let n = Arc::new(Mutex::new(0));
    let c = n.clone();
    b.start_ipv6(move |_, _| *c.lock().unwrap() += 1);
    assert_eq!(*n.lock().unwrap(), 1);
}

#[test]
fn prefix_rules_a_flag_lifetimes_length_and_source() {
    let address = |r: Ra| {
        let (b, _) = v6_bridge(BridgeTiming::default());
        b.from_hub(&ra_frame(r));
        b.ipv6_address()
    };
    assert!(address(ra()).is_some());
    assert!(address(Ra { flags: 0x80, ..ra() }).is_none(), "no A flag: on-link only");
    assert!(address(Ra { valid: 0, preferred: 0, ..ra() }).is_none(), "valid lifetime 0");
    assert!(address(Ra { valid: 100, preferred: 200, ..ra() }).is_none(), "preferred > valid");
    assert!(address(Ra { prefix_len: 48, ..ra() }).is_none(), "only /64 prefixes");
    assert!(address(Ra { prefix: "fe80::", ..ra() }).is_none(), "link-local prefix");
    assert!(address(Ra { src: hex6("2001:db8::1"), ..ra() }).is_none(), "RA must come from a link-local address");
    assert!(address(Ra { hop: 64, ..ra() }).is_none(), "RA that crossed a router");
    assert!(address(Ra { valid: u32::MAX, preferred: u32::MAX, ..ra() }).is_some(), "infinite lifetimes");
}

#[test]
fn valid_lifetime_expiry_stops_the_address_and_router() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    let t = controlled_clock(&b, 1000.0);
    b.from_hub(&ra_frame(Ra { valid: 100, preferred: 50, router_lifetime: 30, ..ra() }));
    assert!(b.ipv6_address().is_some());
    advance(&t, 101.0);
    assert!(b.ipv6_address().is_none(), "expired");
    take(&out);
    b.from_hub(&ns_frame(ns(bytes(SLAAC).try_into().unwrap())));
    assert_eq!(count(&out), 0, "no NA for an expired address");
    b.from_host(&v6_data_packet("2001:db8:ffff::1"));
    assert_eq!(count(&out), 0, "router lifetime ran out: nothing to forward to");
}

#[tokio::test(start_paused = true)]
async fn router_solicitations_repeat_with_backoff_until_an_advertisement_arrives() {
    let t = BridgeTiming { rs_interval: 0.05, rs_max_interval: 1.0, rs_retries: 4, ..BridgeTiming::default() };
    let (b, _) = v6_bridge(t);
    let stamps = Arc::new(Mutex::new(Vec::<(Instant, Vec<u8>)>::new()));
    let s = stamps.clone();
    b.set_send_frame(move |f| {
        if icmp_type(&f) == 133 {
            s.lock().unwrap().push((Instant::now(), f));
        }
    });
    b.start_ipv6(|_, _| {});
    tokio::time::sleep(Duration::from_secs(3)).await;
    let got = stamps.lock().unwrap().clone();
    assert_eq!(got.len(), 4, "stops after the retry budget");
    // 0.05 + 0.10 + 0.20 s between the four attempts
    assert!(got[3].0 - got[0].0 >= Duration::from_millis(350), "no backoff");
    let rs = &got[0].1;
    assert_eq!(rs[..6], [0x33, 0x33, 0, 0, 0, 2]);
    assert_eq!(rs[14 + 7], 255, "hop limit");
    assert_eq!(rs[14 + 8..14 + 24], v6_local());

    let t2 = BridgeTiming { rs_interval: 0.2, rs_max_interval: 1.0, rs_retries: 5, ..BridgeTiming::default() };
    let (b2, _) = v6_bridge(t2);
    let n = Arc::new(Mutex::new(0));
    let c = n.clone();
    b2.set_send_frame(move |f| {
        if icmp_type(&f) == 133 {
            *c.lock().unwrap() += 1;
        }
    });
    b2.start_ipv6(|_, _| {});
    b2.from_hub(&ra_frame(ra()));
    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(*n.lock().unwrap(), 1, "no more solicitations once a router answered");
}

#[tokio::test]
async fn outbound_packets_are_resolved_with_neighbor_discovery_not_broadcast() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    let t = controlled_clock(&b, 1000.0);
    b.from_hub(&ra_frame(ra()));
    advance(&t, 61.0); // the RA's neighbour entry aged out
    let pkt = v6_data_packet("2606:4700::1111"); // off-link: next hop is the router
    b.from_host(&pkt);
    // exact NS to the router's solicited-node group (independent encoder)
    assert_eq!(
        take(&out).last().unwrap(),
        &bytes(concat!(
            "3333ff0000015e001122334486dd6000000000203afffe800000000000005c0011fffe223344",
            "ff0200000000000000000001ff00000187003ace00000000fe80000000000000000000000000000101015e0011223344"
        ))
    );
    b.from_hub(&ra_frame(ra())); // the RA's SLLA resolves the router again (and flushes the queued packet)
    take(&out);
    b.from_host(&pkt);
    assert_eq!(take(&out), [ethernet_frame(PEER_MAC, V6_MAC, 0x86DD, &pkt)]);
}

#[test]
fn queued_v6_packets_flush_after_the_advertisement_and_are_not_flooded() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    let t = controlled_clock(&b, 1000.0);
    let peer = hex6("fe80::1");
    b.from_hub(&ra_frame(ra()));
    advance(&t, 61.0);
    take(&out);
    let pkts: Vec<_> = (1..=3).map(|i| v6_data_packet(&format!("2606:4700::{i}"))).collect();
    for p in &pkts {
        b.from_host(p);
    }
    let sent = take(&out);
    assert_eq!(sent.iter().filter(|f| icmp_type(f) == 135).count(), 1, "one NS, rate limited");
    assert_eq!(
        sent.iter().filter(|f| f[..6] == BROADCAST_MAC).count(),
        0,
        "IPv6 is never flooded to the broadcast MAC"
    );
    // the router answers from a different MAC than the RA claimed
    let new_mac: Mac = [0x02, 0, 0, 0, 0, 0x77];
    let na = icmpv6_neighbor_advertisement(&peer, &new_mac, &peer, &v6_local(), true);
    b.from_hub(&icmp6_frame(V6_MAC, new_mac, peer, v6_local(), &na, 255, false));
    let want: Vec<_> = pkts.iter().map(|p| ethernet_frame(new_mac, V6_MAC, 0x86DD, p)).collect();
    assert_eq!(take(&out), want);
    // unsolicited advertisements for strangers do not create entries
    let stranger = hex6("fe80::66");
    let evil = icmpv6_neighbor_advertisement(&stranger, &new_mac, &stranger, &v6_local(), true);
    b.from_hub(&icmp6_frame(V6_MAC, PEER_MAC, stranger, v6_local(), &evil, 255, false));
    b.from_host(&v6_data_packet("fe80::66"));
    assert_eq!(take(&out).iter().filter(|f| icmp_type(f) == 135).count(), 1, "stranger still has to be resolved");
}

#[test]
fn on_link_destinations_are_resolved_directly_and_unrouted_ones_dropped() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    b.from_host(&v6_data_packet("2606:4700::1"));
    assert_eq!(count(&out), 0, "no router yet");
    b.from_hub(&ra_frame(ra())); // L flag set: 2001:db8:1:2::/64 is on-link
    take(&out);
    b.from_host(&v6_data_packet("2001:db8:1:2::99"));
    let sent = take(&out);
    let n = sent.last().unwrap();
    assert_eq!(icmp_type(n), 135);
    assert_eq!(n[14 + 48..14 + 64], hex6("2001:db8:1:2::99"), "target is the destination itself");
    b.from_host(&ipv6_header(&v6_local(), &hex6("ff02::2"), 58, 0, 64));
    assert_eq!(take(&out)[0][..6], [0x33, 0x33, 0, 0, 0, 2], "multicast keeps its group MAC");
}

#[tokio::test]
async fn blocked_bridge_sends_and_delivers_nothing() {
    let (b, out) = v6_bridge(BridgeTiming::default());
    b.set_handle_ipv6(false);
    let got = Arc::new(Mutex::new(0));
    let g = got.clone();
    b.set_deliver_ipv6(move |_| *g.lock().unwrap() += 1);
    let a = got.clone();
    b.start_ipv6(move |_, _| *a.lock().unwrap() += 100);
    b.from_hub(&ra_frame(ra()));
    b.from_host(&v6_data_packet("2606:4700::1"));
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(count(&out), 0);
    assert_eq!(*got.lock().unwrap(), 0);
}

#[test]
fn non_ndp_ipv6_from_the_hub_reaches_the_tun() {
    let (b, _) = v6_bridge(BridgeTiming::default());
    let got = Arc::new(Mutex::new(Vec::new()));
    let g = got.clone();
    b.set_deliver_ipv6(move |p| g.lock().unwrap().push(p));
    let mut pkt = ipv6_header(&hex6("2606:4700::1"), &hex6("2001:db8:1:2:5c00:11ff:fe22:3344"), 17, 4, 64);
    pkt.extend([1, 2, 3, 4]);
    b.from_hub(&ethernet_frame(V6_MAC, PEER_MAC, 0x86DD, &pkt));
    assert_eq!(*got.lock().unwrap(), [pkt]);
}

// MARK: golden transcripts

/// Lets the test read `exhausted()` after the bridge took ownership of the entropy.
struct Shared(Arc<Mutex<ReplayEntropy>>);

impl Entropy for Shared {
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        self.0.lock().unwrap().bytes(n)
    }

    fn below(&mut self, n: usize) -> usize {
        self.0.lock().unwrap().below(n)
    }
}

type Tape = Arc<Mutex<Vec<Value>>>;

fn add(tape: &Tape, dir: &str, b: &[u8]) {
    tape.lock().unwrap().push(json!({"dir": dir, "hex": hex(b)}));
}

fn note(tape: &Tape, step: &str) {
    tape.lock().unwrap().push(json!({"dir": "note", "step": step}));
}

fn lease_json(l: &Lease) -> Value {
    json!({
        "ip": ip_string(l.ip), "mask": ip_string(l.mask), "router": ip_string(l.router),
        "dns": l.dns.iter().map(|d| ip_string(*d)).collect::<Vec<_>>(), "seconds": l.seconds,
        "serverId": ip_string(l.server_id), "mtu": l.mtu,
    })
}

fn ip_u32(v: &Value) -> u32 {
    let b: Vec<u8> = v.as_str().unwrap().split('.').map(|o| o.parse().unwrap()).collect();
    u32::from_be_bytes(b.try_into().unwrap())
}

fn hub_from_config(cfg: &Value) -> Arc<FakeNetworkServer> {
    let hub = &cfg["hub"];
    let net = Arc::new(FakeNetworkServer::new());
    net.configure(|c| {
        c.offered_ip = ip_u32(&hub["offeredIp"]);
        c.mask = ip_u32(&hub["mask"]);
        c.router = ip_u32(&hub["router"]);
        c.dns = hub["dns"].as_array().unwrap().iter().map(ip_u32).collect();
        c.lease_seconds = hub["leaseSeconds"].as_u64().unwrap() as u32;
        c.server_id = ip_u32(&hub["serverId"]);
        c.gateway_mac = bytes(hub["gatewayMac"].as_str().unwrap()).try_into().unwrap();
        c.nak_count = cfg["nakCount"].as_u64().unwrap_or(0) as u32;
        c.renew_ip = None;
    });
    net
}

/// Bridge driven by the recorded entropy and a fixed clock; `c2h` / `h2c` / `host4` / `host6` go on the tape.
fn replay_bridge(
    c: &Value,
    net: Option<Arc<FakeNetworkServer>>,
    tape: &Tape,
    timing: BridgeTiming,
) -> (Arc<EthernetBridge>, Arc<Mutex<ReplayEntropy>>) {
    let entropy = Arc::new(Mutex::new(ReplayEntropy::new(&c["entropy"])));
    let fixed = c["config"]["fixedMac"].as_str().map(|m| Mac::try_from(bytes(m)).unwrap());
    let b = EthernetBridge::with(timing, fixed, Box::new(Shared(entropy.clone())));
    b.set_clock(|| 1_700_000_000.0);
    let (weak, t) = (Arc::downgrade(&b), tape.clone());
    b.set_send_frame(move |f| {
        add(&t, "c2h", &f);
        let Some(net) = &net else { return };
        for r in net.handle(&f) {
            add(&t, "h2c", &r);
            if let Some(b) = weak.upgrade() {
                b.from_hub(&r);
            }
        }
    });
    let t = tape.clone();
    b.set_deliver_ipv4(move |p| add(&t, "host4", &p));
    let t = tape.clone();
    b.set_deliver_ipv6(move |p| add(&t, "host6", &p));
    (b, entropy)
}

async fn run_bridge_case(c: &Value, tape: &Tape) -> (Arc<EthernetBridge>, Arc<Mutex<ReplayEntropy>>, Value) {
    let name = c["name"].as_str().unwrap();
    let mut result = json!({});
    if name == "ipv6-slaac-nd" {
        let t = BridgeTiming { rs_retries: 1, ..BridgeTiming::default() };
        let (b, ent) = replay_bridge(c, None, tape, t);
        let announced = Arc::new(Mutex::new(Vec::new()));
        let a = announced.clone();
        b.start_ipv6(move |ip, len| a.lock().unwrap().push(json!({"addressHex": hex(&ip), "prefixLength": len})));
        let (router_ll, all_nodes) = (hex6("fe80::1"), ALL_NODES);
        let mut ra = vec![134, 0, 0, 0, 64, 0];
        ra.extend(be16(1800));
        ra.extend([0; 8]);
        ra.extend([1, 1]);
        ra.extend(PEER_MAC);
        ra.extend([3, 4, 64, 0xC0]);
        ra.extend(be32(86400));
        ra.extend(be32(14400));
        ra.extend([0; 4]);
        ra.extend(hex6("2001:db8:1:2::"));
        note(tape, "router advertisement");
        b.from_hub(&icmp6_frame(ipv6_multicast_mac(&all_nodes), PEER_MAC, router_ll, all_nodes, &ra, 255, false));
        let mine = ipv6_link_local(&b.mac());
        let sn = ipv6_solicited_node_multicast(&mine);
        let ns = icmpv6_neighbor_solicitation(&mine, &PEER_MAC, &router_ll, &sn);
        note(tape, "neighbour solicitation for our link-local address");
        b.from_hub(&icmp6_frame(ipv6_multicast_mac(&sn), PEER_MAC, router_ll, sn, &ns, 255, false));
        note(tape, "host sends to 2001:db8:ffff::1");
        let mut host_pkt = ipv6_header(&b.ipv6_address().unwrap_or_default(), &hex6("2001:db8:ffff::1"), 17, 4, 64);
        host_pkt.extend([1, 2, 3, 4]);
        b.from_host(&host_pkt);
        let hx = |o: Option<Ipv6Addr>| o.map_or(Value::Null, |a| json!(hex(&a)));
        result = json!({
            "announced": *announced.lock().unwrap(), "prefixHex": hx(b.ipv6_prefix()),
            "routerHex": hx(b.router_ipv6()), "addressHex": hx(b.ipv6_address()), "hostPacketHex": hex(&host_pkt),
        });
        return (b, ent, result);
    }

    let cfg = &c["config"];
    let net = hub_from_config(cfg);
    let (b, ent) = replay_bridge(c, Some(net.clone()), tape, timing(2.0, 3));
    let lease = b.acquire_lease().await;
    result["lease"] = lease.as_ref().map_or(Value::Null, lease_json);
    match name {
        "dhcp-lease-and-gratuitous-arp" => b.gratuitous_arp(),
        "dhcp-nak-restarts" => {}
        "dhcp-renew-new-address" => {
            net.configure(|c| c.renew_ip = Some(ip_u32(&cfg["renewIp"])));
            let changed = Arc::new(Mutex::new(None::<Lease>));
            let ch = changed.clone();
            b.set_on_lease_changed(move |l| *ch.lock().unwrap() = Some(l));
            note(tape, "renew");
            b.renew().await;
            result = json!({
                "leaseChanged": changed.lock().unwrap().as_ref().map_or(Value::Null, lease_json),
                "lease": b.lease().as_ref().map_or(Value::Null, lease_json),
            });
        }
        "arp-resolve-and-inbound" => {
            note(tape, "host sends to 93.184.216.34 (needs ARP for the router)");
            let pkt = ipv4_packet(6, 0x0AE9_91B6, 0x5DB8_D822, &[9, 9, 9, 9]);
            b.from_host(&pkt);
            note(tape, "hub sends 10.233.145.182 an IPv4 packet");
            let inbound = ipv4_packet(6, 0x5DB8_D822, 0x0AE9_91B6, &[1, 2, 3, 4]);
            b.from_hub(&ethernet_frame(b.mac(), net.config().gateway_mac, 0x0800, &inbound));
            note(tape, "ARP request for our address from a neighbour");
            let who = ArpPacket {
                op: 1,
                sender_mac: PEER_MAC,
                sender_ip: 0x0AE9_0001,
                target_mac: ZERO_MAC,
                target_ip: 0x0AE9_91B6,
            };
            b.from_hub(&ethernet_frame(BROADCAST_MAC, PEER_MAC, 0x0806, &who.encode()));
            result = json!({"hostPacketHex": hex(&pkt)});
        }
        other => panic!("unknown transcript case {other}"),
    }
    (b, ent, result)
}

#[tokio::test]
async fn golden_bridge_transcripts_replay() {
    let doc = load("transcripts/bridge");
    for c in doc["cases"].as_array().unwrap() {
        let name = c["name"].as_str().unwrap();
        let tape: Tape = Arc::new(Mutex::new(Vec::new()));
        let (b, ent, result) = run_bridge_case(c, &tape).await;
        assert_eq!(hex(&b.mac()), c["mac"].as_str().unwrap(), "{name}: mac");
        assert!(ent.lock().unwrap().exhausted(), "{name}: every recorded random draw was used");
        let got = Value::Array(tape.lock().unwrap().clone());
        assert_eq!(got, c["events"], "{name}: frames");
        assert!(vpngate_testkit::golden::json_eq(&result, &c["result"]), "{name}: result {result} vs {}", c["result"]);
    }
}

// MARK: Fuzz (port of `fuzz/bridge-survives-random-frames`)

mod fuzz {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(300))]

        #[test]
        fn bridge_survives_random_frames(
            frames in proptest::collection::vec(
                (proptest::collection::vec(any::<u8>(), 0..120), 0usize..4, proptest::collection::vec(any::<u8>(), 0..80)),
                1..40,
            ),
        ) {
            let rt = tokio::runtime::Builder::new_current_thread().enable_time().build().unwrap();
            rt.block_on(async {
                let net = Arc::new(FakeNetworkServer::new());
                let b = make_bridge(&net, 0.5, 1);
                b.acquire_lease().await.unwrap();
                b.set_deliver_ipv4(|_| {});
                b.set_send_frame(|_| {});
                for (mut f, kind, host) in frames {
                    if kind < 3 && f.len() >= 14 {
                        f[12] = [0x08, 0x08, 0x86][kind];
                        f[13] = [0x00, 0x06, 0xDD][kind];
                    }
                    b.from_hub(&f);
                    b.from_host(&host);
                }
            });
        }
    }
}
