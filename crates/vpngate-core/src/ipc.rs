//! IPC messages between the UI and the daemon, and the connection configuration. The JSON is the Swift `Codable` output
//! (`IPCMessages.swift`): the same keys, optionals omitted when absent, `Data` as base64, and the same missing-field
//! defaults on decode.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::client_account::ClientAccount;
use crate::routing_rule::RoutingConfig;
use crate::server_list::VpnServer;

pub const HELPER_SOCKET_PATH: &str = "/var/run/vpngate-mac.sock";
/// Bumped whenever the helper's behaviour or IPC changes.
pub const HELPER_VERSION: i64 = 8;
/// Revision of the request/reply protocol. 9 added the request/reply commands (`listServers`, `refreshServers`,
/// `syncDat`, `probe`, `validateAccount`); every snapshot event carries it as `ipcVersion`. See `docs/cross-platform/IPC.md`.
pub const IPC_VERSION: i64 = 9;
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
    /// IPC v9: echoed in the reply so a client can match it to the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    /// `refreshServers` / `syncDat`: an alternative CSV list URL tried before the built-in ones.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<String>,
    /// `probe`: the relays to test.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<Vec<ProbeTarget>>,
    /// `probe`: seconds allowed per relay; the daemon default when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<f64>,
    /// `validateAccount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<ClientAccount>,
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
            id: None,
            mirror: None,
            targets: None,
            timeout: None,
            account: None,
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
    /// IPC v9: present in snapshots; absent from a v8 daemon, which does not know the request/reply commands.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipc_version: Option<i64>,
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
            ipc_version: None,
        }
    }
}

/// Where a server list came from. Serialized as the label the apps display.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ListSource {
    #[serde(rename = "Built-in")]
    Bundle,
    #[serde(rename = "Cached")]
    Cache,
    #[serde(rename = "Relay P2P")]
    RelaySync,
    #[serde(rename = "HTTP API")]
    HttpApi,
    #[serde(rename = "CSV Mirror")]
    Csv,
}

/// How a sync ended, which picks the next poll interval (client_exe.c FUN_00411140, 7366-7413).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SyncOutcome {
    /// HTTP API or a relay delivered a fresh verified list.
    Synced,
    /// There were relays to ask, and none answered.
    RelaysFailed,
    /// No source at all (no list to take relays from).
    NoRelays,
}

/// One relay for the `probe` request. Without `ports` the daemon uses the relay's own list, then 443.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeTarget {
    pub host: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<i64>>,
}

/// Reply to `listServers` and `refreshServers`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerListResult {
    pub servers: Vec<VpnServer>,
    pub source: ListSource,
    /// Unix milliseconds of the signed list; absent for the CSV mirror and for no list at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    /// The list is less than 36 h old.
    pub is_fresh: bool,
    pub outcome: SyncOutcome,
    /// Seconds until the next sync is due (random within the interval of `outcome`); `refreshServers` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_poll_seconds: Option<f64>,
}

/// Reply to `syncDat`: the same sync as `refreshServers`, without the servers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncResult {
    pub source: ListSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp_ms: Option<u64>,
    pub is_fresh: bool,
    pub outcome: SyncOutcome,
    pub server_count: u64,
    pub next_poll_seconds: f64,
}

/// One relay's connectivity test.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeEntry {
    pub host: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connect_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hello_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Reply to `probe`, in the order of the request's `targets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeResult {
    pub results: Vec<ProbeEntry>,
}

/// Reply to `validateAccount`: `error` says why an account would be rejected on connect.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidateResult {
    pub valid: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Daemon to UI, answering one request that carried an `id`. Event lines have `state`, reply lines have `reply` (the
/// command), so a v8 client that only knows events fails to decode them and ignores them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct HelperReply {
    pub reply: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i64>,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
}

impl HelperReply {
    pub fn success<T: Serialize>(cmd: &str, id: Option<i64>, result: &T) -> Self {
        HelperReply { reply: cmd.into(), id, ok: true, error: None, result: serde_json::to_value(result).ok() }
    }

    pub fn failure(cmd: &str, id: Option<i64>, error: impl Into<String>) -> Self {
        HelperReply { reply: cmd.into(), id, ok: false, error: Some(error.into()), result: None }
    }

    /// The typed result of a successful reply.
    pub fn decode<T: serde::de::DeserializeOwned>(&self) -> Option<T> {
        serde_json::from_value(self.result.clone()?).ok()
    }
}

/// A line from the daemon.
#[derive(Debug, Clone, PartialEq)]
pub enum ServerMessage {
    Event(HelperEvent),
    Reply(HelperReply),
}

impl ServerMessage {
    pub fn parse(line: &[u8]) -> Option<ServerMessage> {
        let v: serde_json::Value = serde_json::from_slice(line).ok()?;
        if v.get("reply").is_some() {
            serde_json::from_value(v).ok().map(ServerMessage::Reply)
        } else {
            serde_json::from_value(v).ok().map(ServerMessage::Event)
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
            ipc_version: None,
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
    fn v9_fields_are_additive() {
        let mut r = HelperRequest::new("probe");
        r.id = Some(7);
        r.targets = Some(vec![ProbeTarget { host: "h".into(), ports: None }]);
        r.timeout = Some(2.5);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v, serde_json::json!({"cmd":"probe","id":7,"targets":[{"host":"h"}],"timeout":2.5}));
        assert_eq!(serde_json::from_value::<HelperRequest>(v).unwrap(), r);
        // a v8 daemon's snapshot has no ipcVersion
        let e: HelperEvent = serde_json::from_str(r#"{"state":"disconnected","bytesIn":0,"bytesOut":0}"#).unwrap();
        assert_eq!(e.ipc_version, None);
    }

    #[test]
    fn replies_and_events_are_told_apart() {
        let reply =
            HelperReply::success("validateAccount", Some(3), &ValidateResult { valid: false, error: Some("x".into()) });
        let line = serde_json::to_vec(&reply).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&line).unwrap(),
            serde_json::json!({"reply":"validateAccount","id":3,"ok":true,"result":{"valid":false,"error":"x"}})
        );
        let ServerMessage::Reply(back) = ServerMessage::parse(&line).unwrap() else { panic!("not a reply") };
        assert_eq!(back.decode::<ValidateResult>().unwrap().error.as_deref(), Some("x"));
        assert!(matches!(
            ServerMessage::parse(br#"{"state":"connected","bytesIn":1,"bytesOut":2}"#),
            Some(ServerMessage::Event(_))
        ));
        assert_eq!(ServerMessage::parse(b"{}"), None);
        // a v8 client's HelperEvent decoder refuses a reply line
        assert!(serde_json::from_slice::<HelperEvent>(&line).is_err());
        let fail = HelperReply::failure("probe", None, "too many targets");
        assert_eq!(
            serde_json::to_value(&fail).unwrap(),
            serde_json::json!({"reply":"probe","ok":false,"error":"too many targets"})
        );
    }

    #[test]
    fn list_results_use_the_display_labels() {
        let r = ServerListResult {
            servers: vec![],
            source: ListSource::RelaySync,
            timestamp_ms: Some(5),
            is_fresh: true,
            outcome: SyncOutcome::RelaysFailed,
            next_poll_seconds: None,
        };
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            serde_json::json!({"servers":[],"source":"Relay P2P","timestampMs":5,"isFresh":true,"outcome":"relaysFailed"})
        );
        for (s, label) in [
            (ListSource::Bundle, "Built-in"),
            (ListSource::Cache, "Cached"),
            (ListSource::HttpApi, "HTTP API"),
            (ListSource::Csv, "CSV Mirror"),
        ] {
            assert_eq!(serde_json::to_value(s).unwrap(), label);
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
