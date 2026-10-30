//! The fake relay shared by the hermetic tunnel tests (macOS and Windows).
#![allow(dead_code)]

use std::sync::Mutex;
use std::time::Duration;

use async_trait::async_trait;
use vpngate_core::packets::{checksum, ethernet_frame, ipv4_packet, ipv4_parse};
use vpngate_net::connection_pool::{CloseFn, FrameFn};
use vpngate_net::session::VpnTransport;
use vpngate_net::softether_client::Welcome;
use vpngate_net::stream::StreamError;
use vpngate_net::testing::fake_network::FakeNetworkServer;

/// A relay that answers DHCP/ARP like the testkit hub and echoes ICMP pings sent to 192.0.2.0/24.
pub struct EchoRelay {
    pub network: FakeNetworkServer,
    pub on_frame: Mutex<Option<FrameFn>>,
    pub echo_requests: Mutex<usize>,
    /// One line per frame the client sent: ethertype, and for IPv4 the protocol and destination.
    pub seen: Mutex<Vec<String>>,
    pub delivered: Mutex<usize>,
}

impl EchoRelay {
    pub fn new() -> Self {
        EchoRelay {
            network: FakeNetworkServer::new(),
            on_frame: Mutex::new(None),
            echo_requests: Mutex::new(0),
            seen: Mutex::default(),
            delivered: Mutex::new(0),
        }
    }
}

impl Default for EchoRelay {
    fn default() -> Self {
        Self::new()
    }
}

impl EchoRelay {
    fn echo_reply(&self, frame: &[u8]) -> Option<Vec<u8>> {
        let ip = ipv4_parse(frame.get(14..)?).filter(|ip| ip.proto == 1 && ip.dst >> 8 == 0x00C0_0002)?;
        if ip.payload.first() != Some(&8) {
            return None;
        }
        let mut icmp = ip.payload.clone();
        icmp[0] = 0;
        icmp[2..4].fill(0);
        let sum = checksum(&icmp).to_be_bytes();
        icmp[2..4].copy_from_slice(&sum);
        let packet = ipv4_packet(1, ip.dst, ip.src, &icmp);
        let (client, gateway) = (frame[6..12].try_into().ok()?, self.network.config().gateway_mac);
        Some(ethernet_frame(client, gateway, 0x0800, &packet))
    }
}

#[async_trait]
impl VpnTransport for EchoRelay {
    fn set_on_frame(&self, f: Option<FrameFn>) {
        *self.on_frame.lock().unwrap() = f;
    }
    fn set_on_close(&self, _f: Option<CloseFn>) {}
    fn bytes_in(&self) -> u64 {
        0
    }
    fn bytes_out(&self) -> u64 {
        0
    }
    async fn connect(&self, _log: &mut (dyn for<'a> FnMut(&'a str) + Send)) -> Result<Welcome, StreamError> {
        Ok(Welcome {
            session_name: "SID-HERMETIC".into(),
            connection_name: "CID".into(),
            timeout_ms: 20000,
            message: None,
            session_key: None,
            max_connection: 1,
            use_compress: false,
            use_encrypt: true,
            half_connection: false,
            qos: false,
            enable_udp_recovery: false,
            use_udp_acceleration: false,
            udp_accel_version: 0,
            udp_server_ip: None,
            udp_server_port: None,
            udp_server_cookie: None,
            udp_client_cookie: None,
            udp_server_key: None,
            udp_fast_disconnect: false,
            udp_plaintext: false,
        })
    }
    fn send_frame(&self, frame: Vec<u8>) {
        let summary = match frame.get(12..14) {
            Some([0x08, 0x00]) => ipv4_parse(&frame[14..])
                .map_or("ipv4 unparsable".into(), |ip| format!("ipv4 proto {} dst {:08x}", ip.proto, ip.dst)),
            Some(t) => format!("ethertype {:02x}{:02x}", t[0], t[1]),
            None => "runt".into(),
        };
        self.seen.lock().unwrap().push(summary);
        let replies = self.network.handle(&frame);
        let echo = self.echo_reply(&frame);
        *self.delivered.lock().unwrap() += replies.len() + usize::from(echo.is_some());
        let on_frame = self.on_frame.lock().unwrap().clone();
        let Some(f) = on_frame else { return };
        replies.into_iter().for_each(|r| f(r));
        if let Some(r) = echo {
            // A real relay answers from its own thread, never from inside the bridge's send path.
            *self.echo_requests.lock().unwrap() += 1;
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(20));
                f(r);
            });
        }
    }
    fn close(&self, _error: Option<StreamError>) {}
}
