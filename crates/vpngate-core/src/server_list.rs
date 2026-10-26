//! VPN Gate server list: the `VPNServer` record and its tolerant JSON cache format, the CSV parser, port priority and
//! the list-table text. Mirrors `ServerList.swift`. Fetching is left to the network layer.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Serialize};

use crate::validation::{is_ipv4_literal, is_valid_port};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VpnServer {
    /// The DDNS host name is the only unique key: the same IP can appear several times on different ports.
    pub host_name: String,
    pub ip: String,
    pub score: i64,
    pub ping: i64,
    /// Bits per second.
    pub speed: i64,
    pub country_long: String,
    pub country_short: String,
    pub sessions: i64,
    pub uptime_ms: i64,
    pub total_users: i64,
    /// Bytes.
    pub total_traffic: i64,
    pub log_type: String,
    pub operator_name: String,
    pub message: String,
    /// Port from the server's OpenVPN config (tcp or udp); 0 if unknown.
    pub listed_port: i64,
    pub listed_proto: String,
    pub fqdn: String,
    pub ssl_ports: Vec<u16>,
    pub udp_port: Option<u16>,
    pub open_vpn_udp_ports: Vec<u16>,
    pub l2tp: bool,
    pub os: Option<String>,
    pub soft: Option<String>,
    pub build: Option<i64>,
    pub owner: Option<String>,
    pub abuse: Option<String>,
    pub num_login: Option<i64>,
    pub no_log: bool,
    pub log_permanent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub ping_to_google: i64,
    pub send_size: u64,
    pub recv_size: u64,
    #[serde(rename = "isKernelModeNAT")]
    pub is_kernel_mode_nat: bool,
    /// Not stored or sent anywhere: the "Test from this device" result as a sort key.
    #[serde(skip)]
    pub test_rank: i64,
}

impl VpnServer {
    /// A server with every field at its default; `host_name` and `fqdn` fall back to each other like the Swift init.
    pub fn new(host_name: &str, ip: &str) -> Self {
        let mut s = VpnServer { host_name: host_name.into(), ip: ip.into(), ..Default::default() };
        s.fqdn_fallback();
        s
    }

    fn fqdn_fallback(&mut self) {
        if self.host_name.is_empty() {
            self.host_name = self.fqdn.clone();
        }
        if self.fqdn.is_empty() {
            self.fqdn = self.host_name.clone();
        }
    }

    pub fn id(&self) -> &str {
        &self.host_name
    }

    /// The Windows client's port order (client_exe.c FUN_004117c0): 443, 992, 995, 465, 585, 993, 22.
    pub const PREFERRED_PORTS: [u16; 7] = [443, 992, 995, 465, 585, 993, 22];

    /// The preferred ports the host offers, then its other ports in their original order (duplicates dropped).
    pub fn port_priority(ports: &[u16]) -> Vec<u16> {
        let mut out: Vec<u16> = Self::PREFERRED_PORTS.iter().copied().filter(|p| ports.contains(p)).collect();
        for &p in ports {
            if !out.contains(&p) {
                out.push(p);
            }
        }
        out
    }

    pub fn prioritized_ssl_ports(&self) -> Vec<u16> {
        Self::port_priority(&self.ssl_ports)
    }

    /// Port to try first when connecting: the first SSL port in priority order, then `listed_port`.
    pub fn connect_port(&self) -> Option<i64> {
        if let Some(&first) = self.prioritized_ssl_ports().first() {
            if is_valid_port(Some(i64::from(first))) {
                return Some(i64::from(first));
            }
        }
        is_valid_port(Some(self.listed_port)).then_some(self.listed_port)
    }

    /// Regional-indicator flag emoji of `country_short`.
    pub fn flag(&self) -> String {
        self.country_short.to_uppercase().chars().filter_map(|c| char::from_u32(127_397 + c as u32)).collect()
    }
}

/// Caches written by older versions must still load: only `ip` is required, `tcpPort` is the old name of `listedPort`.
impl<'de> Deserialize<'de> for VpnServer {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            host_name: Option<String>,
            ip: String,
            score: Option<i64>,
            ping: Option<i64>,
            speed: Option<i64>,
            country_long: Option<String>,
            country_short: Option<String>,
            sessions: Option<i64>,
            uptime_ms: Option<i64>,
            total_users: Option<i64>,
            total_traffic: Option<i64>,
            log_type: Option<String>,
            operator_name: Option<String>,
            message: Option<String>,
            listed_port: Option<i64>,
            tcp_port: Option<i64>,
            listed_proto: Option<String>,
            fqdn: Option<String>,
            ssl_ports: Option<Vec<u16>>,
            udp_port: Option<u16>,
            open_vpn_udp_ports: Option<Vec<u16>>,
            l2tp: Option<bool>,
            os: Option<String>,
            soft: Option<String>,
            build: Option<i64>,
            owner: Option<String>,
            abuse: Option<String>,
            num_login: Option<i64>,
            no_log: Option<bool>,
            log_permanent: Option<bool>,
            name: Option<String>,
            ping_to_google: Option<i64>,
            send_size: Option<u64>,
            recv_size: Option<u64>,
            #[serde(rename = "isKernelModeNAT")]
            is_kernel_mode_nat: Option<bool>,
        }
        let r = Raw::deserialize(d)?;
        let mut s = VpnServer {
            host_name: r.host_name.unwrap_or_default(),
            ip: r.ip,
            score: r.score.unwrap_or(0),
            ping: r.ping.unwrap_or(0),
            speed: r.speed.unwrap_or(0),
            country_long: r.country_long.unwrap_or_default(),
            country_short: r.country_short.unwrap_or_default(),
            sessions: r.sessions.unwrap_or(0),
            uptime_ms: r.uptime_ms.unwrap_or(0),
            total_users: r.total_users.unwrap_or(0),
            total_traffic: r.total_traffic.unwrap_or(0),
            log_type: r.log_type.unwrap_or_default(),
            operator_name: r.operator_name.unwrap_or_default(),
            message: r.message.unwrap_or_default(),
            listed_port: r.listed_port.or(r.tcp_port).unwrap_or(0),
            listed_proto: r.listed_proto.unwrap_or_default(),
            fqdn: r.fqdn.unwrap_or_default(),
            ssl_ports: r.ssl_ports.unwrap_or_default(),
            udp_port: r.udp_port,
            open_vpn_udp_ports: r.open_vpn_udp_ports.unwrap_or_default(),
            l2tp: r.l2tp.unwrap_or(false),
            os: r.os,
            soft: r.soft,
            build: r.build,
            owner: r.owner,
            abuse: r.abuse,
            num_login: r.num_login,
            no_log: r.no_log.unwrap_or(false),
            log_permanent: r.log_permanent.unwrap_or(false),
            name: r.name,
            ping_to_google: r.ping_to_google.unwrap_or(0),
            send_size: r.send_size.unwrap_or(0),
            recv_size: r.recv_size.unwrap_or(0),
            is_kernel_mode_nat: r.is_kernel_mode_nat.unwrap_or(false),
            test_rank: 0,
        };
        s.fqdn_fallback();
        Ok(s)
    }
}

/// Swift's `Character.isNewline`: LF, VT, FF, CR, NEL, LS, PS (CRLF is one character, so it splits once either way).
fn is_newline(c: char) -> bool {
    matches!(c, '\n' | '\u{B}' | '\u{C}' | '\r' | '\u{85}' | '\u{2028}' | '\u{2029}')
}

/// Parses the `iphone` CSV API response. Lines that are comments, too short or without an IPv4 address are skipped.
pub fn parse(csv: &str) -> Vec<VpnServer> {
    let mut out = Vec::new();
    for line in csv.split(is_newline).filter(|l| !l.is_empty()) {
        if line.starts_with('*') || line.starts_with('#') {
            continue;
        }
        let f: Vec<&str> = line.split(',').collect();
        if f.len() < 15 {
            continue;
        }
        // The config blob is always the last column; a stray comma in the message must not shift it.
        let config = f[f.len() - 1];
        let message = f[13..f.len() - 1].join(",");
        if !is_ipv4_literal(f[1]) {
            continue;
        }
        let (listed_port, listed_proto) = match STANDARD.decode(config) {
            Ok(bytes) => open_vpn_endpoint(&String::from_utf8_lossy(&bytes)),
            Err(_) => (0, String::new()),
        };
        let int = |s: &str| s.parse::<i64>().unwrap_or(0);
        let mut s = VpnServer {
            host_name: f[0].into(),
            ip: f[1].into(),
            score: int(f[2]),
            ping: int(f[3]),
            speed: int(f[4]),
            country_long: f[5].into(),
            country_short: f[6].into(),
            sessions: int(f[7]),
            uptime_ms: int(f[8]),
            total_users: int(f[9]),
            total_traffic: int(f[10]),
            log_type: f[11].into(),
            operator_name: f[12].into(),
            message,
            listed_port,
            listed_proto,
            ..Default::default()
        };
        s.fqdn_fallback();
        out.push(s);
    }
    out
}

/// (port, "tcp"/"udp") from the `proto` and `remote` lines of an OpenVPN config; port 0 if absent or invalid.
pub fn open_vpn_endpoint(cfg: &str) -> (i64, String) {
    let mut proto = String::new();
    let mut port = 0;
    for line in cfg.split(is_newline) {
        let w: Vec<&str> = line.split(' ').filter(|w| !w.is_empty()).collect();
        if w.first() == Some(&"proto") && w.len() > 1 {
            proto = if w[1].starts_with("tcp") { "tcp" } else { "udp" }.into();
        }
        if w.first() == Some(&"remote") && w.len() > 2 {
            if let Ok(p) = w[2].parse::<i64>() {
                if is_valid_port(Some(p)) {
                    port = p;
                }
            }
        }
    }
    (port, proto)
}

/// Text of the list table, following the Windows client (client_exe.c FUN_00525490 / FUN_00525da0).
pub mod list_format {
    /// Up to 1 h in minutes, up to 24 h in hours, beyond that in days; cut-offs are the original's `< 3,600,001 ms`
    /// and `< 86,400,001 ms`; singular for exactly one.
    pub fn uptime(ms: i64) -> String {
        let ms = ms.max(0);
        fn unit(n: i64, word: &str) -> String {
            format!("{n} {word}{}", if n == 1 { "" } else { "s" })
        }
        if ms < 3_600_001 {
            unit(ms / 60_000, "min")
        } else if ms < 86_400_001 {
            unit(ms / 3_600_000, "hour")
        } else {
            unit(ms / 86_400_000, "day")
        }
    }

    pub fn sessions(n: i64) -> String {
        format!("{n} session{}", if n == 1 { "" } else { "s" })
    }

    /// The count is printed with en_US thousands separators.
    pub fn logins(n: i64) -> String {
        let digits = n.unsigned_abs().to_string();
        let mut grouped = String::new();
        for (i, c) in digits.chars().enumerate() {
            if i > 0 && (digits.len() - i) % 3 == 0 {
                grouped.push(',');
            }
            grouped.push(c);
        }
        format!("{}{grouped} login{}", if n < 0 { "-" } else { "" }, if n == 1 { "" } else { "s" })
    }

    /// "Permanent" / "2 Weeks" / "No Logs"; anything else is shown as the server sent it.
    pub fn logging(log_type: &str) -> String {
        let t = log_type.to_lowercase();
        if t.starts_with("no") {
            "No Logs".into()
        } else if t.contains('2') && t.contains("week") {
            "2 Weeks".into()
        } else if t.starts_with("perm") {
            "Permanent".into()
        } else if log_type.is_empty() {
            "-".into()
        } else {
            log_type.into()
        }
    }

    /// "<PingToGoogle>, <PingToJapan>", each as "<n> ms" or "-" when 0.
    pub fn pings(google: i64, japan: i64) -> String {
        let one = |v: i64| if v == 0 { "-".to_string() } else { format!("{v} ms") };
        format!("{}, {}", one(google), one(japan))
    }

    pub fn udp(port: Option<u16>) -> &'static str {
        if port.is_none() {
            "-"
        } else {
            "UDP OK"
        }
    }

    /// Within 24 h of now (the original's `< 86,400,001 ms`) the list is OK, older it is stale.
    pub fn is_list_ok(age_seconds: f64) -> bool {
        age_seconds.abs() * 1000.0 < 86_400_001.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vpngate_testkit::golden::{json_eq, load};

    fn case<'a>(v: &'a Value, name: &str) -> &'a Value {
        v["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no case {name}"))
    }

    fn servers_json(list: &[VpnServer]) -> Value {
        serde_json::to_value(list).unwrap()
    }

    #[test]
    fn parse_vectors() {
        let v = load("serverlist");
        let snap = case(&v, "parse-snapshot");
        let csv =
            std::fs::read_to_string(vpngate_testkit::golden::dir().join("..").join(snap["file"].as_str().unwrap()))
                .unwrap();
        let got = parse(&csv);
        assert_eq!(got.len() as u64, snap["count"].as_u64().unwrap());
        assert!(json_eq(&servers_json(&got), &snap["servers"]));
        for name in ["parse-edge-lines", "parse-crlf"] {
            let c = case(&v, name);
            let got = parse(c["csv"].as_str().unwrap());
            assert!(json_eq(&servers_json(&got), &c["servers"]), "{name}");
        }
    }

    #[test]
    fn server_json() {
        let v = load("serverlist");
        for c in case(&v, "server-json-decode")["cases"].as_array().unwrap() {
            let s: VpnServer = serde_json::from_str(c["input"].as_str().unwrap()).unwrap();
            assert!(json_eq(&serde_json::to_value(&s).unwrap(), &c["server"]), "{c}");
            assert_eq!(s.connect_port().map(Value::from).unwrap_or(Value::Null), c["connectPort"], "{c}");
        }
        let c = case(&v, "server-json-encode");
        let s: VpnServer = serde_json::from_value(c["server"].clone()).unwrap();
        assert!(json_eq(&serde_json::to_value(&s).unwrap(), &c["server"]));
        assert_eq!(s.connect_port().unwrap(), c["connectPort"].as_i64().unwrap());
        assert_eq!(s.flag(), c["flag"].as_str().unwrap());
        assert_eq!(serde_json::to_value(s.prioritized_ssl_ports()).unwrap(), c["prioritizedSslPorts"]);
    }

    #[test]
    fn ports_and_flags() {
        let v = load("serverlist");
        for c in case(&v, "port-priority")["cases"].as_array().unwrap() {
            let ports: Vec<u16> = serde_json::from_value(c["ports"].clone()).unwrap();
            assert_eq!(serde_json::to_value(VpnServer::port_priority(&ports)).unwrap(), c["result"]);
        }
        for c in case(&v, "connect-port")["cases"].as_array().unwrap() {
            let mut s = VpnServer::new("h", "1.1.1.1");
            s.listed_port = c["listedPort"].as_i64().unwrap();
            s.ssl_ports = serde_json::from_value(c["sslPorts"].clone()).unwrap();
            assert_eq!(s.connect_port().map(Value::from).unwrap_or(Value::Null), c["result"], "{c}");
        }
        for c in case(&v, "flag")["cases"].as_array().unwrap() {
            let mut s = VpnServer::new("h", "1.1.1.1");
            s.country_short = c["countryShort"].as_str().unwrap().into();
            assert_eq!(s.flag(), c["flag"].as_str().unwrap());
        }
    }

    #[test]
    fn format_vectors() {
        use list_format::*;
        let v = load("serverlist");
        let each = |name: &str, f: &dyn Fn(&Value) -> String| {
            for c in case(&v, name)["cases"].as_array().unwrap() {
                assert_eq!(f(c), c["text"].as_str().unwrap(), "{name}: {c}");
            }
        };
        each("format-uptime", &|c| uptime(c["ms"].as_i64().unwrap()));
        each("format-sessions", &|c| sessions(c["n"].as_i64().unwrap()));
        each("format-logins", &|c| logins(c["n"].as_i64().unwrap()));
        each("format-logging", &|c| logging(c["logType"].as_str().unwrap()));
        each("format-pings", &|c| pings(c["google"].as_i64().unwrap(), c["japan"].as_i64().unwrap()));
        each("format-udp", &|c| udp(c["port"].as_u64().map(|p| p as u16)).to_string());
        for c in case(&v, "format-list-ok")["cases"].as_array().unwrap() {
            assert_eq!(is_list_ok(c["ageSeconds"].as_f64().unwrap()), c["ok"].as_bool().unwrap(), "{c}");
        }
    }
}
