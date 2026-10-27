//! The "VPN side" of the L2 hub: answers DHCP and ARP like a SoftEther virtual router would.

use std::sync::Mutex;

use vpngate_core::packets::*;

#[derive(Clone)]
pub struct FakeNetworkConfig {
    pub offered_ip: u32,
    pub mask: u32,
    pub router: u32,
    pub dns: Vec<u32>,
    pub lease_seconds: u32,
    pub server_id: u32,
    pub gateway_mac: Mac,
    pub answer_arp: bool,
    /// Ignore DHCP entirely.
    pub silent: bool,
    /// Number of upcoming REQUESTs to answer with NAK.
    pub nak_count: u32,
    /// IP handed out for REQUESTs with ciaddr set (renewals); `None` = same as offered.
    pub renew_ip: Option<u32>,
}

impl Default for FakeNetworkConfig {
    fn default() -> Self {
        FakeNetworkConfig {
            offered_ip: 0x0AE9_91B6, // 10.233.145.182
            mask: 0xFFFF_0000,
            router: 0x0AE9_FEFE, // 10.233.254.254
            dns: vec![0x0AE9_FEFE, 0x0808_0808],
            lease_seconds: 3600,
            server_id: 0x0AE9_FEFE,
            gateway_mac: [0x00, 0xAC, 0x11, 0x22, 0x33, 0x44],
            answer_arp: true,
            silent: false,
            nak_count: 0,
            renew_ip: None,
        }
    }
}

#[derive(Default)]
struct Recorded {
    dhcp: Vec<(DhcpType, Vec<u8>)>,
    arp_targets: Vec<u32>,
    ipv4: Vec<Vec<u8>>,
}

#[derive(Default)]
pub struct FakeNetworkServer {
    config: Mutex<FakeNetworkConfig>,
    recorded: Mutex<Recorded>,
}

impl FakeNetworkServer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn configure(&self, f: impl FnOnce(&mut FakeNetworkConfig)) {
        f(&mut self.config.lock().unwrap());
    }

    pub fn config(&self) -> FakeNetworkConfig {
        self.config.lock().unwrap().clone()
    }

    /// Every client DHCP message seen, with its BOOTP payload.
    pub fn dhcp_messages(&self) -> Vec<(DhcpType, Vec<u8>)> {
        self.recorded.lock().unwrap().dhcp.clone()
    }

    pub fn arp_request_targets(&self) -> Vec<u32> {
        self.recorded.lock().unwrap().arp_targets.clone()
    }

    /// IPv4 packets that reached the hub (not DHCP).
    pub fn ipv4_packets(&self) -> Vec<Vec<u8>> {
        self.recorded.lock().unwrap().ipv4.clone()
    }

    pub fn count(&self, t: DhcpType) -> usize {
        self.dhcp_messages().iter().filter(|m| m.0 == t).count()
    }

    /// The frames the hub sends back for a frame from the client.
    pub fn handle(&self, f: &[u8]) -> Vec<Vec<u8>> {
        if f.len() < 14 {
            return Vec::new();
        }
        let ethertype = u16::from_be_bytes([f[12], f[13]]);
        let payload = &f[14..];
        let src_mac: Mac = f[6..12].try_into().unwrap();
        let cfg = self.config();
        if ethertype == 0x0806 {
            if let Some(a) = ArpPacket::parse(payload).filter(|a| a.op == 1) {
                self.recorded.lock().unwrap().arp_targets.push(a.target_ip);
                if !cfg.answer_arp || a.target_ip != cfg.router {
                    return Vec::new();
                }
                let r = ArpPacket {
                    op: 2,
                    sender_mac: cfg.gateway_mac,
                    sender_ip: cfg.router,
                    target_mac: a.sender_mac,
                    target_ip: a.sender_ip,
                };
                return vec![ethernet_frame(src_mac, cfg.gateway_mac, 0x0806, &r.encode())];
            }
        }
        if ethertype != 0x0800 {
            return Vec::new();
        }
        let Some(ip) = ipv4_parse(payload) else { return Vec::new() };
        if ip.proto == 17 {
            if let Some(u) = udp_parse(&ip.payload).filter(|u| u.dport == 67) {
                if let Some(t) = Self::client_message_type(&u.payload) {
                    self.recorded.lock().unwrap().dhcp.push((t, u.payload.clone()));
                    return if cfg.silent { Vec::new() } else { self.dhcp_reply(&cfg, &u.payload, t) };
                }
            }
        }
        self.recorded.lock().unwrap().ipv4.push(payload.to_vec());
        Vec::new()
    }

    /// Message type of a client-to-server BOOTP packet (op 1), from option 53.
    pub fn client_message_type(p: &[u8]) -> Option<DhcpType> {
        if p.len() < 241 || p[0] != 1 || p[236..240] != [99, 130, 83, 99] {
            return None;
        }
        let mut i = 240;
        while i + 1 < p.len() && p[i] != 255 {
            if p[i] == 0 {
                i += 1;
                continue;
            }
            if p[i] == 53 && p[i + 1] == 1 && i + 2 < p.len() {
                return DhcpType::from_raw(p[i + 2]);
            }
            i += 2 + usize::from(p[i + 1]);
        }
        None
    }

    fn dhcp_reply(&self, cfg: &FakeNetworkConfig, req: &[u8], mtype: DhcpType) -> Vec<Vec<u8>> {
        let mut yi = cfg.offered_ip;
        let rtype = match mtype {
            DhcpType::Discover => DhcpType::Offer,
            DhcpType::Request => {
                let mut c = self.config.lock().unwrap();
                let nak = c.nak_count > 0;
                if nak {
                    c.nak_count -= 1;
                }
                drop(c);
                let rtype = if nak { DhcpType::Nak } else { DhcpType::Ack };
                if rtype == DhcpType::Ack && req[12..16] != [0; 4] {
                    if let Some(r) = cfg.renew_ip {
                        yi = r;
                    }
                }
                rtype
            }
            _ => return Vec::new(),
        };
        let mut b = req[..236].to_vec();
        b[0] = 2;
        b[16..20].copy_from_slice(&be32(if rtype == DhcpType::Nak { 0 } else { yi }));
        b.extend_from_slice(&[99, 130, 83, 99, 53, 1, rtype as u8, 54, 4]);
        b.extend_from_slice(&be32(cfg.server_id));
        if rtype != DhcpType::Nak {
            b.extend_from_slice(&[1, 4]);
            b.extend_from_slice(&be32(cfg.mask));
            b.extend_from_slice(&[3, 4]);
            b.extend_from_slice(&be32(cfg.router));
            b.extend_from_slice(&[6, (cfg.dns.len() * 4) as u8]);
            for d in &cfg.dns {
                b.extend_from_slice(&be32(*d));
            }
            b.extend_from_slice(&[51, 4]);
            b.extend_from_slice(&be32(cfg.lease_seconds));
        }
        b.push(255);
        let udp = udp_datagram(cfg.router, 0xffff_ffff, 67, 68, &b);
        let ip = ipv4_packet(17, cfg.router, 0xffff_ffff, &udp);
        vec![ethernet_frame(BROADCAST_MAC, cfg.gateway_mac, 0x0800, &ip)]
    }
}
