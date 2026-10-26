//! Ethernet, ARP, IPv4, UDP, DHCP, IPv6 and ICMPv6 (neighbour discovery) encoders and parsers for the bridge.

pub type Mac = [u8; 6];
pub type Ipv6Addr = [u8; 16];

pub const BROADCAST_MAC: Mac = [0xff; 6];

/// Internet checksum (RFC 1071), already complemented.
pub fn checksum(b: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = b.chunks_exact(2);
    for c in &mut chunks {
        sum += u32::from(c[0]) << 8 | u32::from(c[1]);
    }
    if let [last] = chunks.remainder() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn be16(v: u16) -> [u8; 2] {
    v.to_be_bytes()
}

pub fn be32(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Dotted quad of a network-order integer (DHCP/ARP fields).
pub fn ip_string(ip: u32) -> String {
    let b = be32(ip);
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// IPv4 as SoftEther's `PackAddIp` carries it in a pack integer: the first octet is the LOW byte (little-endian reading).
pub fn pack_ip_string(v: u32) -> String {
    let b = v.to_le_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

/// Inverse of [`pack_ip_string`] for a dotted IPv4 literal given as four octets.
pub fn pack_ip_value(ip: [u8; 4]) -> u32 {
    u32::from_le_bytes(ip)
}

pub fn ethernet_frame(dst: Mac, src: Mac, ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&be16(ethertype));
    f.extend_from_slice(payload);
    f
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpPacket {
    pub op: u16,
    pub sender_mac: Mac,
    pub sender_ip: u32,
    pub target_mac: Mac,
    pub target_ip: u32,
}

impl ArpPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = vec![0, 1, 8, 0, 6, 4];
        out.extend_from_slice(&be16(self.op));
        out.extend_from_slice(&self.sender_mac);
        out.extend_from_slice(&be32(self.sender_ip));
        out.extend_from_slice(&self.target_mac);
        out.extend_from_slice(&be32(self.target_ip));
        out
    }

    pub fn parse(p: &[u8]) -> Option<ArpPacket> {
        if p.len() < 28 || rd16(p, 0) != 1 || rd16(p, 2) != 0x0800 {
            return None;
        }
        Some(ArpPacket {
            op: rd16(p, 6),
            sender_mac: p[8..14].try_into().ok()?,
            sender_ip: rd32(p, 14),
            target_mac: p[18..24].try_into().ok()?,
            target_ip: rd32(p, 24),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Parsed {
    pub proto: u8,
    pub src: u32,
    pub dst: u32,
    pub payload: Vec<u8>,
}

pub fn ipv4_packet(proto: u8, src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
    let mut h = vec![0x45, 0];
    h.extend_from_slice(&be16((20 + payload.len()) as u16));
    h.extend_from_slice(&[0, 0, 0, 0, 64, proto, 0, 0]);
    h.extend_from_slice(&be32(src));
    h.extend_from_slice(&be32(dst));
    let c = checksum(&h);
    h[10..12].copy_from_slice(&be16(c));
    h.extend_from_slice(payload);
    h
}

/// Parses a well-formed IPv4 packet; a total length beyond the data is clamped, Ethernet padding is dropped.
pub fn ipv4_parse(p: &[u8]) -> Option<Ipv4Parsed> {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = usize::from(p[0] & 0xf) * 4;
    let total = usize::from(rd16(p, 2)).min(p.len());
    if ihl < 20 || total < ihl {
        return None;
    }
    Some(Ipv4Parsed { proto: p[9], src: rd32(p, 12), dst: rd32(p, 16), payload: p[ihl..total].to_vec() })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DhcpType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
    Nak = 6,
}

impl DhcpType {
    pub fn from_raw(v: u8) -> Option<DhcpType> {
        Some(match v {
            1 => DhcpType::Discover,
            2 => DhcpType::Offer,
            3 => DhcpType::Request,
            5 => DhcpType::Ack,
            6 => DhcpType::Nak,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpMessage {
    pub kind: DhcpType,
    pub xid: u32,
    pub yiaddr: u32,
    pub ciaddr: u32,
    pub mac: Mac,
    pub server_id: Option<u32>,
    pub requested_ip: Option<u32>,
    pub subnet_mask: Option<u32>,
    pub router: Option<u32>,
    pub dns: Vec<u32>,
    pub lease_seconds: Option<u32>,
    pub mtu: Option<u16>,
}

impl DhcpMessage {
    pub fn new(kind: DhcpType, xid: u32, mac: Mac) -> Self {
        DhcpMessage {
            kind,
            xid,
            yiaddr: 0,
            ciaddr: 0,
            mac,
            server_id: None,
            requested_ip: None,
            subnet_mask: None,
            router: None,
            dns: Vec::new(),
            lease_seconds: None,
            mtu: None,
        }
    }

    /// BOOTP/DHCP payload (carried in UDP 68 -> 67).
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![1, 1, 6, 0];
        b.extend_from_slice(&be32(self.xid));
        b.extend_from_slice(&[0, 0, 0x80, 0]); // broadcast flag
        b.extend_from_slice(&be32(self.ciaddr));
        b.extend_from_slice(&[0; 12]); // yiaddr siaddr giaddr
        b.extend_from_slice(&self.mac);
        b.extend_from_slice(&[0; 10]);
        b.extend_from_slice(&[0; 192]); // sname + file
        b.extend_from_slice(&[99, 130, 83, 99]);
        b.extend_from_slice(&[53, 1, self.kind as u8]);
        if let Some(r) = self.requested_ip {
            b.extend_from_slice(&[50, 4]);
            b.extend_from_slice(&be32(r));
        }
        if let Some(s) = self.server_id {
            b.extend_from_slice(&[54, 4]);
            b.extend_from_slice(&be32(s));
        }
        b.extend_from_slice(&[55, 5, 1, 3, 6, 51, 26]); // parameter request list includes option 26 (MTU)
        b.push(255);
        b
    }

    pub fn parse(p: &[u8]) -> Option<DhcpMessage> {
        if p.len() < 240 || p[0] != 2 || rd32(p, 236) != 0x6382_5363 {
            return None;
        }
        let mut m = DhcpMessage::new(DhcpType::Discover, rd32(p, 4), p[28..34].try_into().ok()?);
        m.yiaddr = rd32(p, 16);
        let mut kind = None;
        let mut i = 240;
        while i < p.len() {
            let c = p[i];
            if c == 255 {
                break;
            }
            if c == 0 {
                i += 1;
                continue;
            }
            if i + 1 >= p.len() {
                break;
            }
            let l = usize::from(p[i + 1]);
            let s = i + 2;
            if s + l > p.len() {
                break;
            }
            match c {
                53 if l == 1 => kind = DhcpType::from_raw(p[s]),
                54 if l == 4 => m.server_id = Some(rd32(p, s)),
                1 if l == 4 => m.subnet_mask = Some(rd32(p, s)),
                3 if l >= 4 => m.router = Some(rd32(p, s)),
                6 if l >= 4 => m.dns = (0..l - 3).step_by(4).map(|o| rd32(p, s + o)).collect(),
                51 if l == 4 => m.lease_seconds = Some(rd32(p, s)),
                26 if l == 2 => {
                    // An MTU outside 576...1500 is bogus (or would not fit the 1500-byte hub frames): ignore it.
                    let v = rd16(p, s);
                    if (576..=1500).contains(&v) {
                        m.mtu = Some(v);
                    }
                }
                _ => {}
            }
            i = s + l;
        }
        m.kind = kind?;
        Some(m)
    }
}

pub fn udp_datagram(src: u32, dst: u32, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&be16(sport));
    u.extend_from_slice(&be16(dport));
    u.extend_from_slice(&be16((8 + payload.len()) as u16));
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    let mut pseudo = Vec::with_capacity(12 + u.len());
    pseudo.extend_from_slice(&be32(src));
    pseudo.extend_from_slice(&be32(dst));
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&be16(u.len() as u16));
    pseudo.extend_from_slice(&u);
    let mut c = checksum(&pseudo);
    if c == 0 {
        c = 0xffff;
    }
    u[6..8].copy_from_slice(&be16(c));
    u
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpParsed {
    pub sport: u16,
    pub dport: u16,
    pub payload: Vec<u8>,
}

pub fn udp_parse(p: &[u8]) -> Option<UdpParsed> {
    if p.len() < 8 {
        return None;
    }
    let len = usize::from(rd16(p, 4)).min(p.len());
    if len < 8 {
        return None;
    }
    Some(UdpParsed { sport: rd16(p, 0), dport: rd16(p, 2), payload: p[8..len].to_vec() })
}

// MARK: IPv6 and neighbour discovery

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv6Parsed {
    pub next_header: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
    pub payload: Vec<u8>,
}

pub fn ipv6_header(src: &Ipv6Addr, dst: &Ipv6Addr, next_header: u8, payload_len: u16, hop_limit: u8) -> Vec<u8> {
    let mut h = Vec::with_capacity(40);
    h.extend_from_slice(&[0x60, 0, 0, 0]);
    h.extend_from_slice(&be16(payload_len));
    h.push(next_header);
    h.push(hop_limit);
    h.extend_from_slice(src);
    h.extend_from_slice(dst);
    h
}

pub fn ipv6_parse(p: &[u8]) -> Option<Ipv6Parsed> {
    if p.len() < 40 || p[0] >> 4 != 6 {
        return None;
    }
    let len = usize::from(rd16(p, 4)).min(p.len() - 40);
    Some(Ipv6Parsed {
        next_header: p[6],
        src: p[8..24].try_into().ok()?,
        dst: p[24..40].try_into().ok()?,
        payload: p[40..40 + len].to_vec(),
    })
}

/// EUI-64 link-local address from a 48-bit MAC (`fe80::` + MAC with the universal/local bit flipped). All zeros if
/// `mac` is not 6 bytes.
pub fn ipv6_link_local(mac: &[u8]) -> Ipv6Addr {
    let Ok(m) = <[u8; 6]>::try_from(mac) else { return [0; 16] };
    [0xfe, 0x80, 0, 0, 0, 0, 0, 0, m[0] ^ 0x02, m[1], m[2], 0xff, 0xfe, m[3], m[4], m[5]]
}

/// fe80::/10
pub fn ipv6_is_link_local(ip: &[u8]) -> bool {
    ip.len() == 16 && ip[0] == 0xfe && ip[1] & 0xc0 == 0x80
}

/// SLAAC address: the /64 prefix then the modified EUI-64 interface identifier of `mac` (RFC 4862 §5.5.3).
pub fn ipv6_slaac(prefix: &[u8], mac: &[u8]) -> Ipv6Addr {
    if prefix.len() < 8 || mac.len() != 6 {
        return [0; 16];
    }
    let ll = ipv6_link_local(mac);
    let mut out = [0u8; 16];
    out[..8].copy_from_slice(&prefix[..8]);
    out[8..].copy_from_slice(&ll[8..]);
    out
}

/// Uncompressed colon-hex text (`2001:db8:0:0:...`); empty for anything but 16 bytes.
pub fn ipv6_string(ip: &[u8]) -> String {
    if ip.len() != 16 {
        return String::new();
    }
    (0..16).step_by(2).map(|o| format!("{:x}", rd16(ip, o))).collect::<Vec<_>>().join(":")
}

/// Neighbour Discovery messages leave with hop limit 255 (RFC 4861 §6.1.1).
pub fn ipv6_ndp_packet(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> Vec<u8> {
    let mut p = ipv6_header(src, dst, 58, icmp.len() as u16, 255);
    p.extend_from_slice(icmp);
    p
}

/// Solicited-node multicast address ff02::1:ffXX:XXXX; all zeros if `ip` is not 16 bytes.
pub fn ipv6_solicited_node_multicast(ip: &[u8]) -> Ipv6Addr {
    if ip.len() != 16 {
        return [0; 16];
    }
    [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, ip[13], ip[14], ip[15]]
}

/// Ethernet multicast MAC 33:33:XX:XX:XX:XX (zeros for a malformed address).
pub fn ipv6_multicast_mac(ip: &[u8]) -> Mac {
    if ip.len() != 16 {
        return [0x33, 0x33, 0, 0, 0, 0];
    }
    [0x33, 0x33, ip[12], ip[13], ip[14], ip[15]]
}

pub fn icmpv6_checksum(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(src);
    pseudo.extend_from_slice(dst);
    pseudo.extend_from_slice(&[0, 0]);
    pseudo.extend_from_slice(&be16(icmp.len() as u16));
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    checksum(&pseudo)
}

/// True if the checksum in `icmp` (bytes 2-3) is correct for the pseudo-header of `src`/`dst`.
pub fn icmpv6_is_checksum_valid(src: &Ipv6Addr, dst: &Ipv6Addr, icmp: &[u8]) -> bool {
    icmp.len() >= 4 && icmpv6_checksum(src, dst, icmp) == 0
}

fn seal_icmpv6(src: &Ipv6Addr, dst: &Ipv6Addr, mut icmp: Vec<u8>) -> Vec<u8> {
    let c = icmpv6_checksum(src, dst, &icmp);
    icmp[2..4].copy_from_slice(&be16(c));
    icmp
}

/// Router Solicitation (type 133) to all-routers.
pub fn icmpv6_router_solicitation(src_mac: &Mac, src_ip: &Ipv6Addr) -> Vec<u8> {
    let mut icmp = vec![133, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(&[1, 1]);
    icmp.extend_from_slice(src_mac);
    let dst = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
    seal_icmpv6(src_ip, &dst, icmp)
}

/// Neighbor Solicitation (type 135); the source link-layer option is left out for the unspecified source (DAD).
pub fn icmpv6_neighbor_solicitation(
    target_ip: &Ipv6Addr,
    src_mac: &Mac,
    src_ip: &Ipv6Addr,
    dst_ip: &Ipv6Addr,
) -> Vec<u8> {
    let mut icmp = vec![135, 0, 0, 0, 0, 0, 0, 0];
    icmp.extend_from_slice(target_ip);
    if src_ip.iter().any(|&b| b != 0) {
        icmp.extend_from_slice(&[1, 1]);
        icmp.extend_from_slice(src_mac);
    }
    seal_icmpv6(src_ip, dst_ip, icmp)
}

/// Neighbor Advertisement (type 136); `solicited` is clear for the answer to a DAD probe (RFC 4861 §7.2.4).
pub fn icmpv6_neighbor_advertisement(
    target_ip: &Ipv6Addr,
    target_mac: &Mac,
    src_ip: &Ipv6Addr,
    dst_ip: &Ipv6Addr,
    solicited: bool,
) -> Vec<u8> {
    let mut icmp = vec![136, 0, 0, 0, if solicited { 0x60 } else { 0x20 }, 0, 0, 0];
    icmp.extend_from_slice(target_ip);
    icmp.extend_from_slice(&[2, 1]);
    icmp.extend_from_slice(target_mac);
    seal_icmpv6(src_ip, dst_ip, icmp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vpngate_testkit::golden::{load, unhex};

    fn h(v: &Value) -> Vec<u8> {
        unhex(v.as_str().unwrap())
    }
    fn mac(v: &Value) -> Mac {
        h(v).try_into().unwrap()
    }
    fn ip6(v: &Value) -> Ipv6Addr {
        h(v).try_into().unwrap()
    }
    fn u(v: &Value) -> u32 {
        v.as_u64().unwrap() as u32
    }
    fn case<'a>(cases: &'a [Value], name: &str) -> &'a Value {
        cases.iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no case {name}"))
    }

    fn arp_json(a: &ArpPacket) -> Value {
        serde_json::json!({"op": a.op, "senderIP": a.sender_ip, "senderMAC": hex(&a.sender_mac),
            "targetIP": a.target_ip, "targetMAC": hex(&a.target_mac)})
    }
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn golden() {
        let v = load("packets");
        let cases = v["cases"].as_array().unwrap();
        for c in cases {
            let name = c["name"].as_str().unwrap();
            match name {
                "checksum" => {
                    for k in c["cases"].as_array().unwrap() {
                        assert_eq!(u32::from(checksum(&h(&k["input"]))), u(&k["result"]), "{k}");
                    }
                }
                "helpers" => {
                    for k in c["be16"].as_array().unwrap() {
                        assert_eq!(hex(&be16(k["v"].as_u64().unwrap() as u16)), k["hex"].as_str().unwrap());
                    }
                    for k in c["be32"].as_array().unwrap() {
                        assert_eq!(hex(&be32(u(&k["v"]))), k["hex"].as_str().unwrap());
                    }
                    for k in c["ipString"].as_array().unwrap() {
                        assert_eq!(ip_string(u(&k["v"])), k["text"].as_str().unwrap());
                    }
                    for k in c["packIP"].as_array().unwrap() {
                        let text = k["text"].as_str().unwrap();
                        assert_eq!(pack_ip_string(u(&k["v"])), text);
                        // The exporter feeds the octets reversed, so `back` is the byte-swapped value.
                        let o: Vec<u8> = text.split('.').rev().map(|x| x.parse().unwrap()).collect();
                        assert_eq!(pack_ip_value(o.try_into().unwrap()), u(&k["back"]));
                    }
                }
                "ethernet" => {
                    let f = ethernet_frame(
                        [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff],
                        [2, 0x11, 0x22, 0x33, 0x44, 0x55],
                        0x0806,
                        &[1, 2, 3],
                    );
                    assert_eq!(hex(&f), c["hex"].as_str().unwrap());
                }
                "arp-encode" | "arp-encode-reply" => {
                    let a = ArpPacket {
                        op: c["op"].as_u64().unwrap() as u16,
                        sender_mac: mac(&c["senderMAC"]),
                        sender_ip: u(&c["senderIP"]),
                        target_mac: mac(&c["targetMAC"]),
                        target_ip: u(&c["targetIP"]),
                    };
                    assert_eq!(a.encode(), h(&c["hex"]), "{name}");
                }
                n if n.starts_with("arp-parse") => {
                    let got = ArpPacket::parse(&h(&c["hex"])).map(|a| arp_json(&a)).unwrap_or(Value::Null);
                    assert_eq!(got, c["parsed"], "{name}");
                }
                n if n.starts_with("ipv4-build") => {
                    let p =
                        ipv4_packet(c["proto"].as_u64().unwrap() as u8, u(&c["src"]), u(&c["dst"]), &h(&c["payload"]));
                    assert_eq!(p, h(&c["hex"]), "{name}");
                }
                n if n.starts_with("ipv4-parse") => {
                    let got = ipv4_parse(&h(&c["hex"])).map(|p| {
                        serde_json::json!({"dst": p.dst, "payload": hex(&p.payload), "proto": p.proto, "src": p.src})
                    });
                    assert_eq!(got.unwrap_or(Value::Null), c["parsed"], "{name}");
                }
                n if n.starts_with("udp-build") => {
                    let d = udp_datagram(
                        u(&c["src"]),
                        u(&c["dst"]),
                        c["sport"].as_u64().unwrap() as u16,
                        c["dport"].as_u64().unwrap() as u16,
                        &h(&c["payload"]),
                    );
                    assert_eq!(d, h(&c["hex"]), "{name}");
                }
                n if n.starts_with("udp-parse") => {
                    let got = udp_parse(&h(&c["hex"]))
                        .map(|p| serde_json::json!({"dport": p.dport, "payload": hex(&p.payload), "sport": p.sport}));
                    assert_eq!(got.unwrap_or(Value::Null), c["parsed"], "{name}");
                }
                n if n.starts_with("dhcp-encode") => {
                    let mut m = DhcpMessage::new(
                        DhcpType::from_raw(c["type"].as_u64().unwrap() as u8).unwrap(),
                        u(&c["xid"]),
                        mac(&c["mac"]),
                    );
                    m.ciaddr = u(&c["ciaddr"]);
                    m.requested_ip = c["requestedIP"].as_u64().map(|x| x as u32);
                    m.server_id = c["serverID"].as_u64().map(|x| x as u32);
                    assert_eq!(m.encode(), h(&c["hex"]), "{name}");
                }
                n if n.starts_with("dhcp-parse") => {
                    let got = DhcpMessage::parse(&h(&c["hex"])).map(|m| {
                        serde_json::json!({"dns": m.dns, "leaseSeconds": m.lease_seconds, "mac": hex(&m.mac), "mtu": m.mtu,
                            "router": m.router, "serverID": m.server_id, "subnetMask": m.subnet_mask,
                            "type": m.kind as u8, "xid": m.xid, "yiaddr": m.yiaddr})
                    });
                    assert_eq!(got.unwrap_or(Value::Null), c["parsed"], "{name}");
                }
                "ipv6-header" => {
                    let (s, d) = (ip6(&c["src"]), ip6(&c["dst"]));
                    let hdr = ipv6_header(
                        &s,
                        &d,
                        c["nextHeader"].as_u64().unwrap() as u8,
                        c["payloadLen"].as_u64().unwrap() as u16,
                        64,
                    );
                    assert_eq!(hdr, h(&c["hex"]));
                    let mut ndp = ipv6_ndp_packet(&s, &d, &[1, 2, 3]);
                    assert_eq!(ndp, h(&c["ndpHex"]));
                    ndp.clear();
                }
                n if n.starts_with("ipv6-parse") => {
                    let got = ipv6_parse(&h(&c["hex"])).map(|p| {
                        serde_json::json!({"dst": hex(&p.dst), "nextHeader": p.next_header, "payload": hex(&p.payload),
                            "src": hex(&p.src)})
                    });
                    assert_eq!(got.unwrap_or(Value::Null), c["parsed"], "{name}");
                }
                "ipv6-eui64" => {
                    let prefix = unhex("20010db800010002");
                    for k in c["cases"].as_array().unwrap() {
                        let m = h(&k["mac"]);
                        assert_eq!(hex(&ipv6_link_local(&m)), k["linkLocal"].as_str().unwrap());
                        assert_eq!(hex(&ipv6_slaac(&prefix, &m)), k["slaac"].as_str().unwrap());
                        assert_eq!(hex(&ipv6_slaac(&prefix[..4], &m)), k["slaacShortPrefix"].as_str().unwrap());
                    }
                }
                "ipv6-address-helpers" => {
                    for k in c["cases"].as_array().unwrap() {
                        let a = h(&k["addr"]);
                        assert_eq!(ipv6_is_link_local(&a), k["isLinkLocal"].as_bool().unwrap(), "{k}");
                        assert_eq!(hex(&ipv6_multicast_mac(&a)), k["multicastMAC"].as_str().unwrap(), "{k}");
                        assert_eq!(
                            hex(&ipv6_solicited_node_multicast(&a)),
                            k["solicitedNodeMulticast"].as_str().unwrap(),
                            "{k}"
                        );
                        assert_eq!(ipv6_string(&a), k["string"].as_str().unwrap(), "{k}");
                    }
                }
                "icmpv6-build" => {
                    let target = ip6(&c["neighborAdvertisement"]["srcIP"]);
                    let tmac = mac(&c["neighborAdvertisement"]["targetMAC"]);
                    let na = &c["neighborAdvertisement"];
                    let (na_dst, na_src) = (ip6(&na["dstIP"]), ip6(&na["srcIP"]));
                    let pkt = icmpv6_neighbor_advertisement(&target, &tmac, &na_src, &na_dst, true);
                    assert_eq!(pkt, h(&na["hex"]));
                    assert!(icmpv6_is_checksum_valid(&na_src, &na_dst, &pkt));
                    let dad = &c["neighborAdvertisementDAD"];
                    let dad_dst = ip6(&dad["dstIP"]);
                    let pkt = icmpv6_neighbor_advertisement(&target, &tmac, &na_src, &dad_dst, false);
                    assert_eq!(pkt, h(&dad["hex"]));

                    let ns = &c["neighborSolicitation"];
                    let (ns_src, ns_dst) = (ip6(&ns["srcIP"]), ip6(&ns["dstIP"]));
                    let pkt =
                        icmpv6_neighbor_solicitation(&ip6(&ns["targetIP"]), &mac(&ns["srcMAC"]), &ns_src, &ns_dst);
                    assert_eq!(pkt, h(&ns["hex"]));
                    assert!(icmpv6_is_checksum_valid(&ns_src, &ns_dst, &pkt));
                    let nsd = &c["neighborSolicitationDAD"];
                    let unspecified = ip6(&nsd["srcIP"]);
                    let pkt = icmpv6_neighbor_solicitation(
                        &ip6(&ns["targetIP"]),
                        &mac(&ns["srcMAC"]),
                        &unspecified,
                        &ip6(&nsd["dstIP"]),
                    );
                    assert_eq!(pkt, h(&nsd["hex"]));

                    let rs = &c["routerSolicitation"];
                    let rs_src = ip6(&rs["srcIP"]);
                    let pkt = icmpv6_router_solicitation(&mac(&rs["srcMAC"]), &rs_src);
                    assert_eq!(pkt, h(&rs["hex"]));
                    let all_routers = ip6(&serde_json::json!("ff020000000000000000000000000002"));
                    assert!(icmpv6_is_checksum_valid(&rs_src, &all_routers, &pkt));
                }
                "icmpv6-checksum" => {
                    for k in c["cases"].as_array().unwrap() {
                        let (s, d, icmp) = (ip6(&k["src"]), ip6(&k["dst"]), h(&k["icmp"]));
                        assert_eq!(u32::from(icmpv6_checksum(&s, &d, &icmp)), u(&k["checksum"]), "{k}");
                        assert_eq!(icmpv6_is_checksum_valid(&s, &d, &icmp), k["valid"].as_bool().unwrap(), "{k}");
                    }
                }
                other => panic!("unhandled packets vector {other}"),
            }
        }
        assert!(case(cases, "ethernet")["hex"].is_string());
    }
}
