//! Userspace L2 stack: lets an L3 tun device talk to SoftEther's L2 virtual hub. Implements a DHCP client, an ARP
//! responder/resolver, IPv4 framing and the IPv6 neighbour-discovery / SLAAC side.
//!
//! Frames go in through [`EthernetBridge::from_hub`] and [`EthernetBridge::from_host`] and come out through the
//! callbacks. No callback runs while the internal lock is held, so a callback may feed frames straight back in (the
//! tests' fake hub does).

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::Instant;
use vpngate_core::packets::*;

use crate::entropy::{Entropy, SystemEntropy};
use crate::stream::StreamError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub ip: u32,
    pub mask: u32,
    pub router: u32,
    pub dns: Vec<u32>,
    pub seconds: u32,
    pub server_id: u32,
    pub mtu: Option<u16>,
}

/// All durations are in seconds.
#[derive(Debug, Clone)]
pub struct BridgeTiming {
    pub dhcp_timeout: f64,
    pub dhcp_retries: u32,
    /// ARP cache entries older than this are re-resolved.
    pub arp_ttl: f64,
    /// Minimum spacing between ARP requests for the same next hop.
    pub arp_retry_interval: f64,
    /// Packets waiting for ARP longer than this are dropped instead of being sent late.
    pub arp_queue_max_age: f64,
    pub arp_max_queued: usize,
    /// Router Solicitations are repeated (interval doubling up to `rs_max_interval`) until a Router Advertisement
    /// arrives.
    pub rs_interval: f64,
    pub rs_max_interval: f64,
    pub rs_retries: u32,
}

impl Default for BridgeTiming {
    fn default() -> Self {
        BridgeTiming {
            dhcp_timeout: 4.0,
            dhcp_retries: 6,
            arp_ttl: 60.0,
            arp_retry_interval: 1.0,
            arp_queue_max_age: 3.0,
            arp_max_queued: 64,
            rs_interval: 4.0,
            rs_max_interval: 64.0,
            rs_retries: 8,
        }
    }
}

type FrameFn = Arc<dyn Fn(Vec<u8>) + Send + Sync>;
type LeaseFn = Arc<dyn Fn(Lease) + Send + Sync>;
type LostFn = Arc<dyn Fn() + Send + Sync>;
type AddressFn = Arc<dyn Fn(Ipv6Addr, usize) + Send + Sync>;
/// Seconds on any monotonic or wall scale; only differences matter.
type ClockFn = Arc<dyn Fn() -> f64 + Send + Sync>;

struct ArpEntry {
    mac: Mac,
    at: f64,
}

struct V6Prefix {
    prefix: Ipv6Addr,
    on_link: bool,
    autonomous: bool,
    valid_until: f64,
}

struct V6Router {
    address: Ipv6Addr,
    until: f64,
}

#[derive(Default)]
struct Pending {
    packets: Vec<(Vec<u8>, f64)>,
    last_request: Option<f64>,
}

#[derive(Default)]
struct State {
    lease: Option<Lease>,
    arp_cache: HashMap<u32, ArpEntry>,
    waiting: HashMap<u32, Pending>,
    last_dhcp: Option<DhcpMessage>,
    xid: u32,
    v6_prefix: Option<V6Prefix>,
    v6_router: Option<V6Router>,
    ra_seen: bool,
    announced_v6: Option<Ipv6Addr>,
    on_ipv6_address: Option<AddressFn>,
    nd6_cache: HashMap<Ipv6Addr, ArpEntry>,
    waiting6: HashMap<Ipv6Addr, Pending>,
}

#[derive(Default)]
struct Callbacks {
    send_frame: Option<FrameFn>,
    deliver_ipv4: Option<FrameFn>,
    deliver_ipv6: Option<FrameFn>,
    on_lease_changed: Option<LeaseFn>,
    on_lease_lost: Option<LostFn>,
}

pub struct EthernetBridge {
    mac: Mac,
    timing: BridgeTiming,
    entropy: Mutex<Box<dyn Entropy>>,
    state: Mutex<State>,
    callbacks: Mutex<Callbacks>,
    clock: Mutex<ClockFn>,
    handle_ipv6: AtomicBool,
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

fn system_clock() -> ClockFn {
    let start = Instant::now();
    Arc::new(move || start.elapsed().as_secs_f64())
}

fn until(t: f64, seconds: u32) -> f64 {
    if seconds == 0xffff_ffff {
        f64::INFINITY
    } else {
        t + f64::from(seconds)
    }
}

const ALL_ROUTERS: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
const ALL_NODES: Ipv6Addr = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
const ZERO_MAC: Mac = [0; 6];

impl EthernetBridge {
    pub fn new(timing: BridgeTiming) -> Arc<Self> {
        Self::with(timing, None, Box::new(SystemEntropy))
    }

    /// `fixed_mac` skips the random MAC draw.
    pub fn with(timing: BridgeTiming, fixed_mac: Option<Mac>, mut entropy: Box<dyn Entropy>) -> Arc<Self> {
        let mac = fixed_mac.unwrap_or_else(|| {
            let mut m: Mac = entropy.bytes(6).try_into().expect("entropy returned 6 bytes");
            // Locally administered-style prefix like SoftEther (5E:xx), unicast.
            m[0] = 0x5E;
            m[1] &= 0xFE;
            m
        });
        Arc::new(EthernetBridge {
            mac,
            timing,
            entropy: Mutex::new(entropy),
            state: Mutex::new(State::default()),
            callbacks: Mutex::new(Callbacks::default()),
            clock: Mutex::new(system_clock()),
            handle_ipv6: AtomicBool::new(true),
        })
    }

    pub fn mac(&self) -> Mac {
        self.mac
    }

    /// To the hub.
    pub fn set_send_frame(&self, f: impl Fn(Vec<u8>) + Send + Sync + 'static) {
        lock(&self.callbacks).send_frame = Some(Arc::new(f));
    }

    /// To the tun device.
    pub fn set_deliver_ipv4(&self, f: impl Fn(Vec<u8>) + Send + Sync + 'static) {
        lock(&self.callbacks).deliver_ipv4 = Some(Arc::new(f));
    }

    /// To the tun device.
    pub fn set_deliver_ipv6(&self, f: impl Fn(Vec<u8>) + Send + Sync + 'static) {
        lock(&self.callbacks).deliver_ipv6 = Some(Arc::new(f));
    }

    /// A renew returned a different address, router or mask.
    pub fn set_on_lease_changed(&self, f: impl Fn(Lease) + Send + Sync + 'static) {
        lock(&self.callbacks).on_lease_changed = Some(Arc::new(f));
    }

    /// A renew got no answer or a NAK.
    pub fn set_on_lease_lost(&self, f: impl Fn() + Send + Sync + 'static) {
        lock(&self.callbacks).on_lease_lost = Some(Arc::new(f));
    }

    pub fn set_clock(&self, f: impl Fn() -> f64 + Send + Sync + 'static) {
        *lock(&self.clock) = Arc::new(f);
    }

    pub fn set_handle_ipv6(&self, on: bool) {
        self.handle_ipv6.store(on, Ordering::SeqCst);
    }

    pub fn lease(&self) -> Option<Lease> {
        lock(&self.state).lease.clone()
    }

    /// The /64 learned from a Router Advertisement (valid lifetime not yet checked).
    pub fn ipv6_prefix(&self) -> Option<Ipv6Addr> {
        lock(&self.state).v6_prefix.as_ref().map(|p| p.prefix)
    }

    pub fn router_ipv6(&self) -> Option<Ipv6Addr> {
        lock(&self.state).v6_router.as_ref().map(|r| r.address)
    }

    /// Our SLAAC address while its valid lifetime has not run out.
    pub fn ipv6_address(&self) -> Option<Ipv6Addr> {
        let t = self.now();
        self.slaac_address(&lock(&self.state), t)
    }

    fn now(&self) -> f64 {
        let c = lock(&self.clock).clone();
        c()
    }

    fn ipv6_enabled(&self) -> bool {
        self.handle_ipv6.load(Ordering::SeqCst)
    }

    fn send(&self, frame: Vec<u8>) {
        let f = lock(&self.callbacks).send_frame.clone();
        if let Some(f) = f {
            f(frame);
        }
    }

    // MARK: DHCP

    fn new_xid(&self) -> u32 {
        let x = 1 + lock(&self.entropy).below(u32::MAX as usize) as u32;
        let mut s = lock(&self.state);
        s.xid = x;
        s.last_dhcp = None;
        x
    }

    pub async fn acquire_lease(&self) -> Result<Lease, StreamError> {
        for _ in 0..self.timing.dhcp_retries {
            let x = self.new_xid();
            self.send_dhcp(&DhcpMessage::new(DhcpType::Discover, x, self.mac));
            let Some(offer) = self.wait_dhcp(&[DhcpType::Offer]).await else { continue };
            let mut req = DhcpMessage::new(DhcpType::Request, x, self.mac);
            req.requested_ip = Some(offer.yiaddr);
            req.server_id = offer.server_id;
            lock(&self.state).last_dhcp = None;
            self.send_dhcp(&req);
            let Some(reply) = self.wait_dhcp(&[DhcpType::Ack, DhcpType::Nak]).await else { continue };
            if reply.kind == DhcpType::Nak {
                continue; // start over immediately
            }
            let l = Lease {
                ip: reply.yiaddr,
                mask: reply.subnet_mask.unwrap_or(0xffff_ff00),
                router: reply.router.or(offer.router).unwrap_or(0),
                dns: if reply.dns.is_empty() { offer.dns.clone() } else { reply.dns.clone() },
                seconds: reply.lease_seconds.unwrap_or(3600),
                server_id: reply.server_id.or(offer.server_id).unwrap_or(0),
                mtu: reply.mtu.or(offer.mtu),
            };
            lock(&self.state).lease = Some(l.clone());
            return Ok(l);
        }
        Err(StreamError::Protocol("DHCP failed: no lease from the VPN server".into()))
    }

    /// Renews the current lease (RFC 2131 §4.3.2 RENEWING: ciaddr set, no requested-ip/server-id options). Reports
    /// `on_lease_changed` if the server hands out different parameters, `on_lease_lost` on NAK/silence.
    pub async fn renew(&self) {
        let Some(l) = self.lease() else { return };
        let x = self.new_xid();
        let mut req = DhcpMessage::new(DhcpType::Request, x, self.mac);
        req.ciaddr = l.ip;
        self.send_dhcp(&req);
        let reply = self.wait_dhcp(&[DhcpType::Ack, DhcpType::Nak]).await;
        let Some(reply) = reply.filter(|r| r.kind == DhcpType::Ack) else {
            let f = lock(&self.callbacks).on_lease_lost.clone();
            if let Some(f) = f {
                f();
            }
            return;
        };
        let mut n = l.clone();
        n.ip = reply.yiaddr;
        n.mask = reply.subnet_mask.unwrap_or(l.mask);
        n.router = reply.router.unwrap_or(l.router);
        n.seconds = reply.lease_seconds.unwrap_or(l.seconds);
        if !reply.dns.is_empty() {
            n.dns = reply.dns.clone();
        }
        let changed = n.ip != l.ip || n.router != l.router || n.mask != l.mask;
        lock(&self.state).lease = Some(n.clone());
        if changed {
            let f = lock(&self.callbacks).on_lease_changed.clone();
            if let Some(f) = f {
                f(n);
            }
        }
    }

    async fn wait_dhcp(&self, types: &[DhcpType]) -> Option<DhcpMessage> {
        let end = Instant::now() + Duration::from_secs_f64(self.timing.dhcp_timeout);
        while Instant::now() < end {
            if let Some(m) = lock(&self.state).last_dhcp.clone().filter(|m| types.contains(&m.kind)) {
                return Some(m);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        None
    }

    fn send_dhcp(&self, m: &DhcpMessage) {
        let udp = udp_datagram(m.ciaddr, 0xffff_ffff, 68, 67, &m.encode());
        let ip = ipv4_packet(17, m.ciaddr, 0xffff_ffff, &udp);
        self.send(ethernet_frame(BROADCAST_MAC, self.mac, 0x0800, &ip));
    }

    // MARK: hub -> host

    pub fn from_hub(&self, f: &[u8]) {
        if f.len() < 14 {
            return;
        }
        let dst: Mac = f[0..6].try_into().expect("6 bytes");
        let ethertype = rd16(f, 12);
        let payload = &f[14..];
        let for_us = dst == self.mac || dst == BROADCAST_MAC || dst[0] & 1 == 1;
        match ethertype {
            0x0806 => {
                let Some(a) = ArpPacket::parse(payload) else { return };
                let t = self.now();
                let (queued, my_ip) = {
                    let mut s = lock(&self.state);
                    let mut queued = Vec::new();
                    if a.sender_ip != 0 {
                        s.arp_cache.insert(a.sender_ip, ArpEntry { mac: a.sender_mac, at: t });
                        queued = s.waiting.remove(&a.sender_ip).map(|p| p.packets).unwrap_or_default();
                    }
                    (queued, s.lease.as_ref().map(|l| l.ip))
                };
                if let (1, Some(my_ip)) = (a.op, my_ip) {
                    if a.target_ip == my_ip {
                        let r = ArpPacket {
                            op: 2,
                            sender_mac: self.mac,
                            sender_ip: my_ip,
                            target_mac: a.sender_mac,
                            target_ip: a.sender_ip,
                        };
                        self.send(ethernet_frame(a.sender_mac, self.mac, 0x0806, &r.encode()));
                    }
                }
                // Flush in order, but never send packets that have been waiting too long.
                for (pkt, at) in queued {
                    if t - at <= self.timing.arp_queue_max_age {
                        self.from_host(&pkt);
                    }
                }
            }
            0x0800 => {
                if !for_us {
                    return;
                }
                let Some(ip) = ipv4_parse(payload) else { return };
                if ip.proto == 17 {
                    if let Some(u) = udp_parse(&ip.payload).filter(|u| u.dport == 68) {
                        if let Some(m) = DhcpMessage::parse(&u.payload) {
                            let mut s = lock(&self.state);
                            if m.xid == s.xid {
                                s.last_dhcp = Some(m);
                            }
                            return;
                        }
                    }
                }
                let have = lock(&self.state).lease.is_some();
                if have {
                    let f = lock(&self.callbacks).deliver_ipv4.clone();
                    if let Some(f) = f {
                        f(payload.to_vec());
                    }
                }
            }
            0x86DD => {
                if !self.ipv6_enabled() || !for_us {
                    return;
                }
                let Some(v6) = ipv6_parse(payload) else { return };
                if v6.next_header == 58 && v6.payload.len() >= 4 && (133..=137).contains(&v6.payload[0]) {
                    // Neighbour Discovery is answered here, never handed to the kernel (which would otherwise act on
                    // RAs and configure the tun a second time).
                    let src_mac: Mac = f[6..12].try_into().expect("6 bytes");
                    self.handle_ndp(&v6, payload[7], src_mac);
                    return;
                }
                let f = lock(&self.callbacks).deliver_ipv6.clone();
                if let Some(f) = f {
                    f(payload.to_vec());
                }
            }
            _ => {}
        }
    }

    // MARK: host -> hub

    pub fn from_host(&self, pkt: &[u8]) {
        let Some(&first) = pkt.first() else { return };
        if first >> 4 == 6 {
            self.send_host_ipv6(pkt);
            return;
        }
        if pkt.len() < 20 {
            return;
        }
        let t = self.now();
        let (target, send_request, my_ip, next_hop) = {
            let mut s = lock(&self.state);
            let Some(l) = s.lease.clone() else { return };
            let dst = rd32(pkt, 16);
            let on_link = dst & l.mask == l.ip & l.mask;
            let next_hop = if on_link { dst } else { l.router };
            let is_broadcast = dst == 0xffff_ffff || (on_link && (dst | !l.mask) == dst) || dst >> 28 == 0xE;
            let mut target = None;
            if is_broadcast {
                target = Some(BROADCAST_MAC);
            } else if let Some(e) = s.arp_cache.get(&next_hop) {
                if t - e.at <= self.timing.arp_ttl {
                    target = Some(e.mac);
                } else {
                    s.arp_cache.remove(&next_hop);
                }
            }
            let mut send_request = false;
            if target.is_none() {
                let p = s.waiting.entry(next_hop).or_default();
                queue_packet(p, pkt, t, &self.timing, &mut send_request);
            }
            (target, send_request, l.ip, next_hop)
        };

        if let Some(tm) = target {
            self.send(ethernet_frame(tm, self.mac, 0x0800, pkt));
        } else if send_request {
            let req =
                ArpPacket { op: 1, sender_mac: self.mac, sender_ip: my_ip, target_mac: ZERO_MAC, target_ip: next_hop };
            self.send(ethernet_frame(BROADCAST_MAC, self.mac, 0x0806, &req.encode()));
        }
    }

    fn send_host_ipv6(&self, pkt: &[u8]) {
        if !self.ipv6_enabled() || pkt.len() < 40 {
            return;
        }
        let Some(v6) = ipv6_parse(pkt) else { return };
        if v6.dst[0] == 0xff {
            // multicast
            self.send(ethernet_frame(ipv6_multicast_mac(&v6.dst), self.mac, 0x86DD, pkt));
            return;
        }
        let t = self.now();
        let (target, send_request, next_hop) = {
            let mut s = lock(&self.state);
            // Link-local and on-link destinations are resolved directly; everything else goes to the router.
            let mut next_hop = v6.dst;
            let on_link = ipv6_is_link_local(&v6.dst)
                || s.v6_prefix.as_ref().is_some_and(|p| p.on_link && t < p.valid_until && v6.dst[..8] == p.prefix[..8]);
            if !on_link {
                // no IPv6 router: nothing to send to
                match &s.v6_router {
                    Some(r) if t < r.until => next_hop = r.address,
                    _ => return,
                }
            }
            let mut target = None;
            if let Some(e) = s.nd6_cache.get(&next_hop) {
                if t - e.at <= self.timing.arp_ttl {
                    target = Some(e.mac);
                } else {
                    s.nd6_cache.remove(&next_hop);
                }
            }
            let mut send_request = false;
            if target.is_none() {
                if !s.waiting6.contains_key(&next_hop) && s.waiting6.len() >= self.timing.arp_max_queued {
                    return;
                }
                let p = s.waiting6.entry(next_hop).or_default();
                queue_packet(p, pkt, t, &self.timing, &mut send_request);
            }
            (target, send_request, next_hop)
        };

        if let Some(tm) = target {
            self.send(ethernet_frame(tm, self.mac, 0x86DD, pkt));
        } else if send_request {
            let src = ipv6_link_local(&self.mac);
            let dst = ipv6_solicited_node_multicast(&next_hop);
            let ns = icmpv6_neighbor_solicitation(&next_hop, &self.mac, &src, &dst);
            self.send(ethernet_frame(ipv6_multicast_mac(&dst), self.mac, 0x86DD, &ipv6_ndp_packet(&src, &dst, &ns)));
        }
    }

    // MARK: IPv6 neighbour discovery

    /// Starts IPv6 on the link: reports the SLAAC address (once, as soon as a Router Advertisement provides a usable
    /// prefix) and sends Router Solicitations with backoff until some router answers. Needs a Tokio runtime.
    pub fn start_ipv6(self: &Arc<Self>, on_address: impl Fn(Ipv6Addr, usize) + Send + Sync + 'static) {
        if !self.ipv6_enabled() {
            return;
        }
        let on_address: AddressFn = Arc::new(on_address);
        let known = {
            let mut s = lock(&self.state);
            s.on_ipv6_address = Some(on_address.clone());
            s.announced_v6
        };
        if let Some(a) = known {
            on_address(a, 64);
        }
        let (first, cap, tries) = (self.timing.rs_interval, self.timing.rs_max_interval, self.timing.rs_retries);
        // The first solicitation goes out synchronously so an immediate advertisement can't race the task start.
        if tries == 0 || !self.solicit_router_if_needed() {
            return;
        }
        let weak = Arc::downgrade(self);
        tokio::spawn(async move {
            let mut wait = first;
            for _ in 1..tries {
                tokio::time::sleep(Duration::from_secs_f64(wait)).await;
                wait = (wait * 2.0).min(cap);
                match weak.upgrade() {
                    Some(b) if b.solicit_router_if_needed() => {}
                    _ => return,
                }
            }
        });
    }

    fn solicit_router_if_needed(&self) -> bool {
        if lock(&self.state).ra_seen || !self.ipv6_enabled() {
            return false;
        }
        let src = ipv6_link_local(&self.mac);
        let rs = icmpv6_router_solicitation(&self.mac, &src);
        self.send(ethernet_frame(
            ipv6_multicast_mac(&ALL_ROUTERS),
            self.mac,
            0x86DD,
            &ipv6_ndp_packet(&src, &ALL_ROUTERS, &rs),
        ));
        true
    }

    fn slaac_address(&self, s: &State, t: f64) -> Option<Ipv6Addr> {
        let p = s.v6_prefix.as_ref()?;
        (p.autonomous && t < p.valid_until).then(|| ipv6_slaac(&p.prefix, &self.mac))
    }

    /// Returns the packets that were waiting for `ip`.
    fn learn6(s: &mut State, ip: Ipv6Addr, m: Mac, t: f64) -> Vec<(Vec<u8>, f64)> {
        s.nd6_cache.insert(ip, ArpEntry { mac: m, at: t });
        s.waiting6.remove(&ip).map(|p| p.packets).unwrap_or_default()
    }

    fn flush6(&self, queued: Vec<(Vec<u8>, f64)>, t: f64) {
        for (pkt, at) in queued {
            if t - at <= self.timing.arp_queue_max_age {
                self.send_host_ipv6(&pkt);
            }
        }
    }

    fn handle_ndp(&self, v6: &Ipv6Parsed, hop_limit: u8, src_mac: Mac) {
        let icmp = &v6.payload;
        // RFC 4861 §7.1/§6.1: hop limit 255 (never forwarded by a router), code 0, valid checksum.
        if hop_limit != 255 || icmp[1] != 0 || !icmpv6_is_checksum_valid(&v6.src, &v6.dst, icmp) {
            return;
        }
        let t = self.now();
        match icmp[0] {
            135 if icmp.len() >= 24 => {
                // Neighbor Solicitation
                let target: Ipv6Addr = icmp[8..24].try_into().expect("16 bytes");
                if target[0] == 0xff {
                    return;
                }
                let probe = v6.src.iter().all(|&b| b == 0); // DAD probe from ::
                if !(v6.dst == ipv6_solicited_node_multicast(&target) || (!probe && v6.dst == target)) {
                    return;
                }
                let slla = if probe { None } else { ndp_option(icmp, 24, 1) };
                let (queued, own) = {
                    let mut s = lock(&self.state);
                    let queued = match slla.as_deref().and_then(|m| Mac::try_from(m).ok()) {
                        Some(m) => Self::learn6(&mut s, v6.src, m, t),
                        None => Vec::new(),
                    };
                    let mut own = vec![ipv6_link_local(&self.mac)];
                    own.extend(self.slaac_address(&s, t));
                    (queued, own)
                };
                self.flush6(queued, t);
                if !own.contains(&target) {
                    return;
                }
                // Answer from the solicited address to the asker's own MAC (not to the multicast MAC it was sent to);
                // a DAD probe has no one to unicast to, so the answer goes to all nodes with S clear.
                let dst_ip = if probe { ALL_NODES } else { v6.src };
                let na = icmpv6_neighbor_advertisement(&target, &self.mac, &target, &dst_ip, !probe);
                let dst_mac = if probe { ipv6_multicast_mac(&ALL_NODES) } else { src_mac };
                self.send(ethernet_frame(dst_mac, self.mac, 0x86DD, &ipv6_ndp_packet(&target, &dst_ip, &na)));
            }
            136 if icmp.len() >= 24 => {
                // Neighbor Advertisement
                let target: Ipv6Addr = icmp[8..24].try_into().expect("16 bytes");
                if target[0] == 0xff {
                    return;
                }
                let m = ndp_option(icmp, 24, 2).and_then(|m| Mac::try_from(m.as_slice()).ok()).unwrap_or(src_mac);
                let queued = {
                    let mut s = lock(&self.state);
                    // Only resolutions we asked for (or refreshes of known entries) are accepted.
                    if s.waiting6.contains_key(&target) || s.nd6_cache.contains_key(&target) {
                        Self::learn6(&mut s, target, m, t)
                    } else {
                        Vec::new()
                    }
                };
                self.flush6(queued, t);
            }
            134 if icmp.len() >= 16 && ipv6_is_link_local(&v6.src) => {
                // Router Advertisement
                self.handle_router_advertisement(v6.src, icmp, src_mac, t);
            }
            _ => {} // RS (we are not a router) and Redirect
        }
    }

    fn handle_router_advertisement(&self, router: Ipv6Addr, icmp: &[u8], src_mac: Mac, t: f64) {
        let router_lifetime = u32::from(rd16(icmp, 6));
        let slla = ndp_option(icmp, 16, 1);
        let mut candidate: Option<V6Prefix> = None;
        let mut i = 16;
        while i + 8 <= icmp.len() {
            let len = usize::from(icmp[i + 1]) * 8;
            if len == 0 || i + len > icmp.len() {
                break;
            }
            if icmp[i] == 3 && len >= 32 && candidate.is_none() && icmp[i + 2] == 64 {
                // Prefix Information, /64 only
                let flags = icmp[i + 3];
                let (valid, preferred) = (rd32(icmp, i + 4), rd32(icmp, i + 8));
                let prefix: Ipv6Addr = icmp[i + 16..i + 32].try_into().expect("16 bytes");
                // RFC 4862 §5.5.3: preferred must not exceed valid; link-local prefixes are ignored.
                if valid > 0
                    && preferred <= valid
                    && !ipv6_is_link_local(&prefix)
                    && prefix[0] != 0xff
                    && flags & 0xc0 != 0
                {
                    candidate = Some(V6Prefix {
                        prefix,
                        on_link: flags & 0x80 != 0,
                        autonomous: flags & 0x40 != 0,
                        valid_until: until(t, valid),
                    });
                }
            }
            i += len;
        }
        let (queued, announce) = {
            let mut s = lock(&self.state);
            s.ra_seen = true;
            let mut queued = Vec::new();
            if router_lifetime == 0 {
                if s.v6_router.as_ref().is_some_and(|r| r.address == router) {
                    s.v6_router = None;
                }
            } else {
                s.v6_router = Some(V6Router { address: router, until: until(t, router_lifetime) });
                let m = slla.as_deref().and_then(|m| Mac::try_from(m).ok()).unwrap_or(src_mac);
                queued = Self::learn6(&mut s, router, m, t);
            }
            // One prefix per link: later RAs refresh it; a different prefix replaces it only after it has expired.
            if let Some(c) = candidate {
                let replace = match &s.v6_prefix {
                    None => true,
                    Some(p) => p.prefix[..8] == c.prefix[..8] || t >= p.valid_until,
                };
                if replace {
                    s.v6_prefix = Some(c);
                }
            }
            let mut announce = None;
            if let Some(a) = self.slaac_address(&s, t) {
                if s.announced_v6 != Some(a) {
                    s.announced_v6 = Some(a);
                    announce = Some((a, s.on_ipv6_address.clone()));
                }
            }
            (queued, announce)
        };
        self.flush6(queued, t);
        if let Some((a, Some(handler))) = announce {
            handler(a, 64);
        }
    }

    /// Announce ourselves so the hub learns our MAC/IP.
    pub fn gratuitous_arp(&self) {
        let Some(l) = self.lease() else { return };
        let a = ArpPacket { op: 1, sender_mac: self.mac, sender_ip: l.ip, target_mac: ZERO_MAC, target_ip: l.ip };
        self.send(ethernet_frame(BROADCAST_MAC, self.mac, 0x0806, &a.encode()));
    }
}

/// Queues `pkt` behind an unresolved next hop and says whether an ARP/NS request is due.
fn queue_packet(p: &mut Pending, pkt: &[u8], t: f64, timing: &BridgeTiming, send_request: &mut bool) {
    p.packets.retain(|(_, at)| t - at <= timing.arp_queue_max_age);
    if p.packets.len() < timing.arp_max_queued {
        p.packets.push((pkt.to_vec(), t));
    }
    if p.last_request.is_none_or(|last| t - last >= timing.arp_retry_interval) {
        p.last_request = Some(t);
        *send_request = true;
    }
}

/// Option of `kind` (RFC 4861 §4.6) in an ICMPv6 NDP message whose options start at `from`; `None` if absent or malformed.
fn ndp_option(icmp: &[u8], from: usize, kind: u8) -> Option<Vec<u8>> {
    let mut i = from;
    while i + 8 <= icmp.len() {
        let len = usize::from(icmp[i + 1]) * 8;
        if len == 0 || i + len > icmp.len() {
            return None;
        }
        if icmp[i] == kind {
            return Some(icmp[i + 2..i + len].to_vec());
        }
        i += len;
    }
    None
}

#[cfg(test)]
mod tests;
