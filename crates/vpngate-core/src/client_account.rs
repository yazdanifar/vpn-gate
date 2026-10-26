//! SoftEther client account (Connection Setting) and its JSON file format. Mirrors `ClientAccount.swift`: only `id`,
//! `name` and `host` are required when decoding, the proxy password is never written, dates are Swift `Date`s
//! (seconds since 2001-01-01 as a number).

use serde::{Deserialize, Serialize, Serializer};
use uuid::Uuid;

use crate::ipc::{ConnectConfig, ProxySettings, TunnelMode, DEFAULT_SOCKS_PORT};
use crate::routing_rule::RoutingConfig;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize)]
pub enum AccountAuthType {
    #[serde(rename = "Anonymous")]
    Anonymous,
    #[default]
    #[serde(rename = "Standard Password (SHA-0)")]
    Password,
    #[serde(rename = "Plain Password")]
    PlainPassword,
    #[serde(rename = "User Certificate")]
    Certificate,
}

impl AccountAuthType {
    pub fn raw_value(self) -> &'static str {
        match self {
            Self::Anonymous => "Anonymous",
            Self::Password => "Standard Password (SHA-0)",
            Self::PlainPassword => "Plain Password",
            Self::Certificate => "User Certificate",
        }
    }
}

/// Seconds between 1970-01-01 and Swift's reference date, 2001-01-01.
const REFERENCE_DATE_UNIX: f64 = 978_307_200.0;

/// Now as a Swift `Date` value.
pub fn now_reference_seconds() -> f64 {
    let unix = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
    unix - REFERENCE_DATE_UNIX
}

fn ser_proxy<S: Serializer>(p: &ProxySettings, s: S) -> Result<S::Ok, S::Error> {
    let mut safe = p.clone();
    safe.password = None;
    safe.serialize(s)
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ClientAccount {
    pub id: Uuid,
    pub name: String,
    pub host: String,
    pub port_list: Vec<u16>,
    pub hub: String,
    pub username: String,
    pub auth_type: AccountAuthType,
    #[serde(serialize_with = "ser_proxy")]
    pub proxy: ProxySettings,
    pub check_server_cert: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_cert_fingerprint: Option<String>,
    pub max_connection: i64,
    /// Splits send and receive onto separate TCP sockets.
    pub half_connection: bool,
    pub compression: bool,
    pub udp_acceleration: bool,
    #[serde(rename = "disableQoS")]
    pub disable_qos: bool,
    pub auto_reconnect: bool,
    /// Seconds between reconnect attempts.
    pub reconnect_interval: f64,
    pub reconnect_count: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_mac_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<i64>,
    /// Per-account routing rules; `None` means "use the app's global rules".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub routing: Option<RoutingConfig>,
    pub created_at: f64,
    pub updated_at: f64,
}

/// What `to_connect_config` adds to the account's own settings.
#[derive(Debug, Clone, PartialEq)]
pub struct ConnectOptions {
    pub password: Option<String>,
    pub cert_der: Option<Vec<u8>>,
    pub private_key_der: Option<Vec<u8>>,
    pub block_ipv6: bool,
    pub global_routing: Option<RoutingConfig>,
    pub tunnel_mode: TunnelMode,
    pub socks_port: i64,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        ConnectOptions {
            password: None,
            cert_der: None,
            private_key_der: None,
            block_ipv6: true,
            global_routing: None,
            tunnel_mode: TunnelMode::FullTunnel,
            socks_port: DEFAULT_SOCKS_PORT,
        }
    }
}

impl ClientAccount {
    /// An account with the Swift initialiser's defaults, stamped with the current time.
    pub fn new(name: impl Into<String>, host: impl Into<String>) -> Self {
        let now = now_reference_seconds();
        ClientAccount {
            id: Uuid::new_v4(),
            name: name.into(),
            host: host.into(),
            port_list: vec![443, 992, 5555, 1194],
            hub: "DEFAULT".into(),
            username: String::new(),
            auth_type: AccountAuthType::Password,
            proxy: ProxySettings::default(),
            check_server_cert: false,
            server_cert_fingerprint: None,
            max_connection: 1,
            half_connection: false,
            compression: false,
            udp_acceleration: true,
            disable_qos: false,
            auto_reconnect: true,
            reconnect_interval: 3.0,
            reconnect_count: 8,
            virtual_mac_address: None,
            mtu: None,
            routing: None,
            created_at: now,
            updated_at: now,
        }
    }

    /// The initialiser's invariants: at least one port, `maxConnection` within 1...32.
    pub fn normalize(&mut self) {
        if self.port_list.is_empty() {
            self.port_list = vec![443];
        }
        self.max_connection = self.max_connection.clamp(1, 32);
    }

    /// Converts the account into the daemon's connect configuration. `options.global_routing` is the app-wide rule
    /// set; the account's own `routing`, when set, replaces it entirely.
    pub fn to_connect_config(&self, options: ConnectOptions) -> ConnectConfig {
        ConnectConfig {
            host: self.host.clone(),
            ports: self.port_list.iter().map(|&p| i64::from(p)).collect(),
            hub_name: self.hub.clone(),
            user_name: self.username.clone(),
            auth_type: self.auth_type.raw_value().to_string(),
            password: options.password,
            cert_der: options.cert_der,
            private_key_der: options.private_key_der,
            ticket: None,
            proxy: self.proxy.clone(),
            max_connection: self.max_connection,
            use_compress: self.compression,
            use_udp_accel: self.udp_acceleration,
            disable_qos: self.disable_qos,
            half_connection: self.half_connection,
            auto_reconnect: self.auto_reconnect,
            reconnect_interval: Some(self.reconnect_interval),
            reconnect_count: Some(self.reconnect_count),
            block_ipv6: options.block_ipv6,
            check_server_cert: self.check_server_cert,
            server_cert_fingerprint: self.server_cert_fingerprint.clone(),
            mtu: self.mtu,
            virtual_mac_address: self.virtual_mac_address.clone(),
            routing: self.routing.clone().or(options.global_routing),
            tunnel_mode: options.tunnel_mode,
            socks_port: options.socks_port,
        }
    }
}

/// Tolerant like the Swift decoder: unknown keys (such as the old `hideFromVpnGateList`) are ignored, missing ones fall
/// back to their defaults, missing dates become now.
impl<'de> Deserialize<'de> for ClientAccount {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            id: Uuid,
            name: String,
            host: String,
            port_list: Option<Vec<u16>>,
            hub: Option<String>,
            username: Option<String>,
            auth_type: Option<AccountAuthType>,
            proxy: Option<ProxySettings>,
            check_server_cert: Option<bool>,
            server_cert_fingerprint: Option<String>,
            max_connection: Option<i64>,
            half_connection: Option<bool>,
            compression: Option<bool>,
            udp_acceleration: Option<bool>,
            #[serde(rename = "disableQoS")]
            disable_qos: Option<bool>,
            auto_reconnect: Option<bool>,
            reconnect_interval: Option<f64>,
            reconnect_count: Option<i64>,
            virtual_mac_address: Option<String>,
            mtu: Option<i64>,
            routing: Option<RoutingConfig>,
            created_at: Option<f64>,
            updated_at: Option<f64>,
        }
        let r = Raw::deserialize(d)?;
        let mut a = ClientAccount::new(r.name, r.host);
        a.id = r.id;
        if let Some(v) = r.port_list {
            a.port_list = v;
        }
        a.hub = r.hub.unwrap_or(a.hub);
        a.username = r.username.unwrap_or(a.username);
        a.auth_type = r.auth_type.unwrap_or(a.auth_type);
        a.proxy = r.proxy.unwrap_or(a.proxy);
        a.check_server_cert = r.check_server_cert.unwrap_or(a.check_server_cert);
        a.server_cert_fingerprint = r.server_cert_fingerprint;
        a.max_connection = r.max_connection.unwrap_or(a.max_connection);
        a.half_connection = r.half_connection.unwrap_or(a.half_connection);
        a.compression = r.compression.unwrap_or(a.compression);
        a.udp_acceleration = r.udp_acceleration.unwrap_or(a.udp_acceleration);
        a.disable_qos = r.disable_qos.unwrap_or(a.disable_qos);
        a.auto_reconnect = r.auto_reconnect.unwrap_or(a.auto_reconnect);
        a.reconnect_interval = r.reconnect_interval.unwrap_or(a.reconnect_interval);
        a.reconnect_count = r.reconnect_count.unwrap_or(a.reconnect_count);
        a.virtual_mac_address = r.virtual_mac_address;
        a.mtu = r.mtu;
        a.routing = r.routing;
        a.created_at = r.created_at.unwrap_or(a.created_at);
        a.updated_at = r.updated_at.unwrap_or(a.updated_at);
        a.normalize();
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::ProxyKind;
    use crate::routing_rule::{RoutingAction, RoutingRule, RoutingRuleType};
    use serde_json::Value;
    use vpngate_testkit::golden::{json_eq, load, unhex};

    const FIXED_DATE: f64 = 750_000_000.0;

    fn case(name: &str) -> Value {
        load("account")["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap().clone()
    }

    fn id(n: u128) -> Uuid {
        Uuid::from_u128(n)
    }

    fn routing() -> RoutingConfig {
        RoutingConfig {
            rules: vec![RoutingRule::with_id(
                id(1),
                RoutingRuleType::DomainSuffix,
                "example.com",
                RoutingAction::Direct,
                true,
            )],
            default_action: RoutingAction::Block,
            bypass_private_networks: true,
        }
    }

    fn minimal() -> ClientAccount {
        let mut a = ClientAccount::new("min", "h.example.com");
        a.id = id(2);
        a.created_at = FIXED_DATE;
        a.updated_at = FIXED_DATE;
        a
    }

    fn full() -> ClientAccount {
        let mut a = minimal();
        a.id = id(3);
        a.name = "full".into();
        a.host = "1.2.3.4".into();
        a.port_list = vec![443, 992];
        a.hub = "VPN".into();
        a.username = "bob".into();
        a.auth_type = AccountAuthType::Certificate;
        a.proxy = ProxySettings {
            kind: ProxyKind::Http,
            host: "proxy.local".into(),
            port: 8080,
            username: Some("u".into()),
            password: Some("secret".into()),
        };
        a.check_server_cert = true;
        a.server_cert_fingerprint = Some("ab".repeat(20));
        a.max_connection = 8;
        a.half_connection = true;
        a.compression = true;
        a.udp_acceleration = false;
        a.disable_qos = true;
        a.auto_reconnect = false;
        a.reconnect_interval = 7.5;
        a.reconnect_count = 3;
        a.virtual_mac_address = Some("aa:bb:cc:dd:ee:ff".into());
        a.mtu = Some(1400);
        a.routing = Some(routing());
        a
    }

    #[test]
    fn encode_vectors() {
        let m = serde_json::to_value(minimal()).unwrap();
        assert!(json_eq(&m, &case("encode-minimal")["json"]), "{m}");
        let f = serde_json::to_value(full()).unwrap();
        assert!(json_eq(&f, &case("encode-full-strips-proxy-password")["json"]), "{f}");
    }

    #[test]
    fn connect_config_vectors() {
        let opts = |c: &Value| ConnectOptions {
            password: c["password"].as_str().map(Into::into),
            cert_der: Some(unhex(c["certDer"].as_str().unwrap())),
            private_key_der: Some(unhex(c["privateKeyDer"].as_str().unwrap())),
            block_ipv6: c["blockIPv6"].as_bool().unwrap(),
            global_routing: Some(serde_json::from_value(c["globalRouting"].clone()).unwrap()),
            tunnel_mode: serde_json::from_value(c["tunnelMode"].clone()).unwrap(),
            socks_port: c["socksPort"].as_i64().unwrap(),
        };
        for (name, a) in [("minimal", minimal()), ("full", full())] {
            let c = case(&format!("connect-config-{name}"));
            let got = serde_json::to_value(a.to_connect_config(opts(&c))).unwrap();
            assert!(json_eq(&got, &c["config"]), "{name}: {got}");
        }
        let got = serde_json::to_value(full().to_connect_config(ConnectOptions::default())).unwrap();
        assert!(json_eq(&got, &case("connect-config-defaults")["config"]));
    }

    #[test]
    fn decode_vectors() {
        for c in case("decode")["cases"].as_array().unwrap() {
            let r = serde_json::from_str::<ClientAccount>(c["input"].as_str().unwrap());
            if c["error"] == true {
                assert!(r.is_err(), "{c}");
                continue;
            }
            let a = r.unwrap();
            let mut got = serde_json::to_value(&a).unwrap();
            if c["datesDefaulted"] == true {
                let now = now_reference_seconds();
                for k in ["createdAt", "updatedAt"] {
                    assert!((now - got[k].as_f64().unwrap()).abs() < 60.0);
                    got[k] = c["account"][k].clone();
                }
            }
            assert!(json_eq(&got, &c["account"]), "{got}");
        }
    }

    #[test]
    fn clamps_and_auth_types() {
        for c in case("init-clamps")["cases"].as_array().unwrap() {
            let mut a = minimal();
            if let Some(m) = c["maxConnection"].as_i64() {
                a.max_connection = m;
            }
            if let Some(p) = c.get("portList") {
                a.port_list = serde_json::from_value(p.clone()).unwrap();
            }
            a.normalize();
            if c.get("maxConnection").is_some() {
                assert_eq!(a.max_connection, c["result"].as_i64().unwrap());
            } else {
                assert_eq!(serde_json::to_value(&a.port_list).unwrap(), c["result"]);
            }
        }
        for c in case("auth-types")["cases"].as_array().unwrap() {
            let t: AccountAuthType = serde_json::from_value(c["raw"].clone()).unwrap();
            assert_eq!(t.raw_value(), c["raw"].as_str().unwrap());
        }
    }
}
