//! IPC messages between the UI and the daemon, and the connection configuration. The JSON is the Swift `Codable` output
//! (`IPCMessages.swift`): the same keys, optionals omitted when absent, `Data` as base64, and the same missing-field
//! defaults on decode.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::routing_rule::RoutingConfig;

pub const HELPER_SOCKET_PATH: &str = "/var/run/vpngate-mac.sock";
/// Bumped whenever the helper's behaviour or IPC changes.
pub const HELPER_VERSION: i64 = 8;
pub const DEFAULT_SOCKS_PORT: i64 = 1080;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ConnectionState {
    Disconnected,
    Connecting,
    Authenticating,
    Dhcp,
    Connected,
    Reconnecting,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    #[default]
    None,
    Http,
    Socks5,
}

/// All three of `kind`, `host` and `port` are required when decoding (Swift's synthesized decoder).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ProxySettings {
    pub kind: ProxyKind,
    pub host: String,
    pub port: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}

/// How a connection exposes the VPN: capture the whole machine, or only serve a local SOCKS5 proxy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum TunnelMode {
    #[default]
    FullTunnel,
    SocksProxy,
}

/// `Data?` fields travel as standard base64 strings.
pub(crate) mod b64_opt {
    use super::*;

    pub fn serialize<S: Serializer>(v: &Option<Vec<u8>>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_str(&STANDARD.encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Vec<u8>>, D::Error> {
        Option::<String>::deserialize(d)?.map(|t| STANDARD.decode(t).map_err(serde::de::Error::custom)).transpose()
    }
}

fn default_ports() -> Vec<i64> {
    vec![443, 992, 5555, 1194]
}
fn default_hub() -> String {
    "VPNGATE".into()
}
fn default_user() -> String {
    "vpn".into()
}
fn default_auth() -> String {
    "anonymous".into()
}
fn default_one() -> i64 {
    1
}
fn default_true() -> bool {
    true
}
fn default_socks_port() -> i64 {
    DEFAULT_SOCKS_PORT
}

/// Full configuration for establishing a SoftEther session. Only `host` is required when decoding.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectConfig {
    pub host: String,
    #[serde(default = "default_ports")]
    pub ports: Vec<i64>,
    #[serde(default = "default_hub")]
    pub hub_name: String,
    #[serde(default = "default_user")]
    pub user_name: String,
    /// anonymous, password, plain, cert, ticket
    #[serde(default = "default_auth")]
    pub auth_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub cert_der: Option<Vec<u8>>,
    /// PKCS#1 RSAPrivateKey DER (PKCS#8 also accepted). Never logged.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub private_key_der: Option<Vec<u8>>,
    #[serde(default, skip_serializing_if = "Option::is_none", with = "b64_opt")]
    pub ticket: Option<Vec<u8>>,
    #[serde(default)]
    pub proxy: ProxySettings,
    #[serde(default = "default_one")]
    pub max_connection: i64,
    #[serde(default)]
    pub use_compress: bool,
    #[serde(default = "default_true")]
    pub use_udp_accel: bool,
    /// SoftEther "Disable QoS" (login `qos` = !disableQoS).
    #[serde(default, rename = "disableQoS")]
    pub disable_qos: bool,
    #[serde(default)]
    pub half_connection: bool,
    #[serde(default = "default_true")]
    pub auto_reconnect: bool,
    /// Seconds between reconnect attempts; `None` keeps the daemon's default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_interval: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_count: Option<i64>,
    #[serde(default = "default_true", rename = "blockIPv6")]
    pub block_ipv6: bool,
    #[serde(default)]
    pub check_server_cert: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_cert_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_mac_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,
    #[serde(default)]
    pub tunnel_mode: TunnelMode,
    #[serde(default = "default_socks_port")]
    pub socks_port: i64,
}

impl ConnectConfig {
    /// A config with every field at its decode default.
    pub fn new(host: impl Into<String>) -> Self {
        ConnectConfig {
            host: host.into(),
            ports: default_ports(),
            hub_name: default_hub(),
            user_name: default_user(),
            auth_type: default_auth(),
            password: None,
            cert_der: None,
            private_key_der: None,
            ticket: None,
            proxy: ProxySettings::default(),
            max_connection: 1,
            use_compress: false,
            use_udp_accel: true,
            disable_qos: false,
            half_connection: false,
            auto_reconnect: true,
            reconnect_interval: None,
            reconnect_count: None,
            block_ipv6: true,
            check_server_cert: false,
            server_cert_fingerprint: None,
            mtu: None,
            virtual_mac_address: None,
            routing: None,
            tunnel_mode: TunnelMode::FullTunnel,
            socks_port: DEFAULT_SOCKS_PORT,
        }
    }
}

/// UI to daemon. Only `cmd` is required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelperRequest {
    /// connect | disconnect | status
    pub cmd: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<i64>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<ProxySettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_reconnect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "blockIPv6")]
    pub block_ipv6: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel_mode: Option<TunnelMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks_port: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<ConnectConfig>,
}

impl HelperRequest {
    pub fn new(cmd: impl Into<String>) -> Self {
        HelperRequest {
            cmd: cmd.into(),
            host: None,
            port: None,
            ports: None,
            proxy: None,
            auto_reconnect: None,
            block_ipv6: None,
            routing: None,
            tunnel_mode: None,
            socks_port: None,
            config: None,
        }
    }
}

/// Daemon to UI. `state`, `bytesIn` and `bytesOut` are required when decoding (Swift's synthesized decoder ignores
/// the `= 0` initialisers).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HelperEvent {
    pub state: ConnectionState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    #[serde(default, rename = "virtualIP", skip_serializing_if = "Option::is_none")]
    pub virtual_ip: Option<String>,
    pub bytes_in: u64,
    pub bytes_out: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_version: Option<i64>,
}

impl HelperEvent {
    pub fn new(state: ConnectionState) -> Self {
        HelperEvent {
            state,
            server: None,
            virtual_ip: None,
            bytes_in: 0,
            bytes_out: 0,
            log: None,
            error: None,
            helper_version: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vpngate_testkit::golden::{json_eq, load};

    fn case(name: &str) -> Value {
        load("ipc")["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap().clone()
    }

    fn full_config() -> ConnectConfig {
        let mut c = ConnectConfig::new("h");
        c.ports = vec![443, 992];
        c.hub_name = "HUB".into();
        c.user_name = "u".into();
        c.auth_type = "cert".into();
        c.password = Some("pw".into());
        c.cert_der = Some(vec![1, 2, 3]);
        c.private_key_der = Some(vec![4, 5]);
        c.ticket = Some(vec![6]);
        c.proxy = ProxySettings {
            kind: ProxyKind::Socks5,
            host: "p".into(),
            port: 1080,
            username: Some("u".into()),
            password: Some("pw".into()),
        };
        c.max_connection = 4;
        c.use_compress = true;
        c.use_udp_accel = false;
        c.disable_qos = true;
        c.half_connection = true;
        c.auto_reconnect = false;
        c.reconnect_interval = Some(2.5);
        c.reconnect_count = Some(5);
        c.block_ipv6 = false;
        c.check_server_cert = true;
        c.server_cert_fingerprint = Some("ab".into());
        c.mtu = Some(1400);
        c.virtual_mac_address = Some("aa:bb:cc:dd:ee:ff".into());
        c.routing = Some(RoutingConfig {
            rules: vec![crate::routing_rule::RoutingRule::with_id(
                uuid::Uuid::from_u128(1),
                crate::routing_rule::RoutingRuleType::Cidr,
                "10.0.0.0/8",
                crate::routing_rule::RoutingAction::Direct,
                false,
            )],
            default_action: crate::routing_rule::RoutingAction::Block,
            bypass_private_networks: true,
        });
        c.tunnel_mode = TunnelMode::SocksProxy;
        c.socks_port = 9050;
        c
    }

    #[test]
    fn connect_config_vectors() {
        let d = serde_json::to_value(ConnectConfig::new("h")).unwrap();
        assert!(json_eq(&d, &case("connect-config-default")["json"]), "{d}");
        let f = serde_json::to_value(full_config()).unwrap();
        assert!(json_eq(&f, &case("connect-config-full")["json"]), "{f}");
        let back: ConnectConfig = serde_json::from_value(f).unwrap();
        assert_eq!(back, full_config());
        for c in case("connect-config-decode")["cases"].as_array().unwrap() {
            let r = serde_json::from_str::<ConnectConfig>(c["input"].as_str().unwrap());
            if c["error"] == true {
                assert!(r.is_err(), "{c}");
            } else {
                assert!(json_eq(&serde_json::to_value(r.unwrap()).unwrap(), &c["config"]), "{c}");
            }
        }
    }

    #[test]
    fn request_vectors() {
        let encoded = case("request-encode");
        let cases = encoded["cases"].as_array().unwrap();
        assert!(json_eq(&serde_json::to_value(HelperRequest::new("status")).unwrap(), &cases[0]));
        assert!(json_eq(&serde_json::to_value(HelperRequest::new("disconnect")).unwrap(), &cases[1]));
        let mut r = HelperRequest::new("connect");
        let cfg = full_config();
        r.host = Some("h".into());
        r.port = Some(443);
        r.ports = Some(vec![443, 992]);
        r.proxy = Some(cfg.proxy.clone());
        r.auto_reconnect = Some(true);
        r.block_ipv6 = Some(false);
        r.routing = cfg.routing.clone();
        r.tunnel_mode = Some(TunnelMode::FullTunnel);
        r.socks_port = Some(1080);
        r.config = Some(cfg);
        let got = serde_json::to_value(&r).unwrap();
        assert!(json_eq(&got, &cases[2]), "{got}");
        assert_eq!(serde_json::from_value::<HelperRequest>(got).unwrap(), r);

        for c in case("request-decode")["cases"].as_array().unwrap() {
            let r = serde_json::from_str::<HelperRequest>(c["input"].as_str().unwrap());
            if c["error"] == true {
                assert!(r.is_err(), "{c}");
            } else {
                assert!(json_eq(&serde_json::to_value(r.unwrap()).unwrap(), &c["request"]), "{c}");
            }
        }
    }

    #[test]
    fn event_vectors() {
        let c = case("event-encode");
        for (state, name) in c["cases"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| (serde_json::from_value::<ConnectionState>(s.clone()).unwrap(), s))
        {
            assert_eq!(serde_json::to_value(state).unwrap(), *name);
        }
        let events = c["events"].as_array().unwrap();
        assert!(json_eq(&serde_json::to_value(HelperEvent::new(ConnectionState::Disconnected)).unwrap(), &events[0]));
        let e = HelperEvent {
            state: ConnectionState::Connected,
            server: Some("s".into()),
            virtual_ip: Some("10.0.0.2".into()),
            bytes_in: 123,
            bytes_out: u64::MAX,
            log: Some("l".into()),
            error: Some("e".into()),
            helper_version: Some(HELPER_VERSION),
        };
        assert_eq!(serde_json::to_value(&e).unwrap(), events[1]);
        for c in case("event-decode")["cases"].as_array().unwrap() {
            let r = serde_json::from_str::<HelperEvent>(c["input"].as_str().unwrap());
            if c["error"] == true {
                assert!(r.is_err(), "{c}");
            } else {
                assert!(json_eq(&serde_json::to_value(r.unwrap()).unwrap(), &c["event"]), "{c}");
            }
        }
    }

    #[test]
    fn constants_and_proxy() {
        let c = case("constants");
        assert_eq!(c["helperSocketPath"], HELPER_SOCKET_PATH);
        assert_eq!(c["helperVersion"], HELPER_VERSION);
        assert_eq!(c["defaultSocksPort"], DEFAULT_SOCKS_PORT);
        let p = case("proxy-settings");
        assert!(json_eq(&serde_json::to_value(ProxySettings::default()).unwrap(), &p["default"]));
        let s: ProxySettings = serde_json::from_value(p["json"].clone()).unwrap();
        assert_eq!(serde_json::to_value(s).unwrap(), p["json"]);
    }
}
