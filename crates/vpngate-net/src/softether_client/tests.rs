use std::sync::{Arc, Mutex};

use serde_json::{json, Value};
use sha1::{Digest, Sha1};
use vpngate_core::ipc::{ProxyKind, ProxySettings};
use vpngate_core::pack::Pack;
use vpngate_core::sha0;
use vpngate_testkit::golden;

use super::*;
use crate::testing::fake_softether::FakeSoftEtherServer;
use crate::testing::replay_entropy::ReplayEntropy;

fn env() -> ClientEnvironment {
    ClientEnvironment { os_name: "macOS".into(), os_version: "14.5.0".into(), hostname: "golden-host".into() }
}

fn client(server: &FakeSoftEtherServer) -> SoftEtherClient {
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.use_udp_accel = false;
    client_with(server, cfg)
}

fn client_with(server: &FakeSoftEtherServer, cfg: ClientConfig) -> SoftEtherClient {
    SoftEtherClient::new(
        cfg,
        HostUniqueId::new([7; 32]),
        server.factory(),
        Box::new(crate::entropy::SystemEntropy),
        env(),
    )
}

async fn connect(c: &mut SoftEtherClient) -> Result<ConnectOutcome, StreamError> {
    let (host, port, auth) = (c.config().host.clone(), c.config().port, c.config().auth.clone());
    c.connect_once(&host, port, &auth, &mut |_| {}, None).await
}

fn welcome_of(o: ConnectOutcome) -> Welcome {
    match o {
        ConnectOutcome::Connected { welcome, .. } => *welcome,
        ConnectOutcome::Redirect(r) => panic!("unexpected redirect {r:?}"),
    }
}

async fn connect_error(server: &FakeSoftEtherServer) -> String {
    match connect(&mut client(server)).await {
        Ok(_) => panic!("connect should fail"),
        Err(e) => e.to_string(),
    }
}

// MARK: - handshake

#[tokio::test]
async fn happy_path() {
    let s = FakeSoftEtherServer::new();
    let mut c = client(&s);
    let logs = Mutex::new(Vec::<String>::new());
    let auth = ClientAuth::Anonymous;
    let o = c.connect_once("1.2.3.4", 443, &auth, &mut |m| logs.lock().unwrap().push(m.into()), None).await.unwrap();
    let w = welcome_of(o);
    assert_eq!(w.session_name, "SID-VPN-TEST-1");
    assert_eq!(w.timeout_ms, 20000);
    let r = s.requests();
    assert_eq!(r.len(), 2);
    assert_eq!((r[0].path.as_str(), r[0].content_type.as_str()), ("/vpnsvc/connect.cgi", "image/jpeg"));
    assert_eq!(&r[0].body[..6], b"GIF89a");
    assert_eq!((r[1].path.as_str(), r[1].content_type.as_str()), ("/vpnsvc/vpn.cgi", "application/octet-stream"));
    let logins = s.logins();
    assert_eq!(logins.len(), 1);
    assert_eq!(logins[0].str("hubname"), Some("VPNGATE"));
    assert_eq!(logins[0].int("authtype"), Some(0));
    assert!(logs.lock().unwrap().iter().any(|m| m.contains("Server: SoftEther VPN Server v432 build 9729")));
}

#[tokio::test]
async fn falls_back_to_plain_signature() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.reject_watermark = true);
    let mut c = client(&s);
    welcome_of(connect(&mut c).await.unwrap());
    assert_eq!(s.streams_created(), 2, "a fresh connection is used for the retry");
    assert!(s.stream_cancelled(0));
    assert!(!s.stream_cancelled(1));
    assert_eq!(s.requests()[1].body, b"VPNCONNECT");
    assert!(c.plain_signature());
    assert_eq!(c.signature_body(), b"VPNCONNECT", "additional connections match the first one");
}

#[tokio::test]
async fn login_errors_are_reported() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.login_error = 3);
    let e = connect_error(&s).await;
    assert!(e.starts_with("Server refused login: ERR_"), "{e}");
    assert!(e.contains("(3)"), "{e}");

    s.configure(|c| c.login_error = 987_654);
    assert_eq!(connect_error(&s).await, "Server refused login: ERR_987654 (987654): Unknown server error");
}

#[tokio::test]
async fn missing_random_is_not_softether() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.omit_random = true);
    assert!(connect_error(&s).await.contains("missing random"));
}

#[tokio::test]
async fn http_error_and_transport_failure_propagate() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.hello_status = 500);
    // Both the watermark and the plain retry get 500.
    assert_eq!(connect_error(&s).await, "HTTP: HTTP/1.1 500 Forbidden");

    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.fail_start = Some(StreamError::Io("Connection refused".into())));
    assert_eq!(connect_error(&s).await, "Connection refused");
    assert!(s.stream_cancelled(0));
}

#[tokio::test]
async fn bytes_after_the_welcome_stay_in_the_stream_buffer() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.trailing_after_welcome = vec![1, 2, 3, 4]);
    match connect(&mut client(&s)).await.unwrap() {
        ConnectOutcome::Connected { mut stream, .. } => assert_eq!(stream.buffer().take_all(), vec![1, 2, 3, 4]),
        ConnectOutcome::Redirect(_) => panic!("redirect"),
    }
}

#[tokio::test]
async fn welcome_split_into_tiny_chunks_still_parses() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| c.chunk_size = Some(1));
    assert_eq!(welcome_of(connect(&mut client(&s)).await.unwrap()).session_name, "SID-VPN-TEST-1");
}

#[tokio::test]
async fn proxy_settings_reach_the_stream_factory_and_login_pack() {
    let seen = Arc::new(Mutex::new(Vec::<(String, u16, ProxySettings)>::new()));
    let s = FakeSoftEtherServer::new();
    let inner = s.factory();
    let seen2 = seen.clone();
    let factory: StreamFactory = Arc::new(move |h, p, px| {
        seen2.lock().unwrap().push((h.into(), p, px.clone()));
        inner(h, p, px)
    });
    let proxy = ProxySettings { kind: ProxyKind::Socks5, host: "proxy.local".into(), port: 1080, ..Default::default() };
    let mut cfg = ClientConfig::new("1.2.3.4", 443, proxy.clone());
    cfg.use_udp_accel = false;
    let mut c =
        SoftEtherClient::new(cfg, HostUniqueId::new([7; 32]), factory, Box::new(crate::entropy::SystemEntropy), env());
    welcome_of(connect(&mut c).await.unwrap());
    assert_eq!(seen.lock().unwrap().as_slice(), &[("1.2.3.4".to_string(), 443, proxy)]);
    let login = &s.logins()[0];
    assert_eq!(login.str("ProxyHostname"), Some("proxy.local"));
    assert_eq!(login.int("ProxyPort"), Some(1080));
}

// MARK: - authentication

#[tokio::test]
async fn plain_password_auth() {
    let s = FakeSoftEtherServer::new();
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.auth = ClientAuth::PlainPassword("hunter2".into());
    cfg.use_udp_accel = false;
    welcome_of(connect(&mut client_with(&s, cfg)).await.unwrap());
    let l = &s.logins()[0];
    assert_eq!((l.int("authtype"), l.str("plain_password")), (Some(2), Some("hunter2")));
}

#[tokio::test]
async fn hashed_password_auth_uses_sha0_with_the_server_random() {
    let s = FakeSoftEtherServer::new();
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.user_name = "alice".into();
    cfg.auth = ClientAuth::HashedPassword("pässword".into());
    cfg.use_udp_accel = false;
    welcome_of(connect(&mut client_with(&s, cfg)).await.unwrap());
    let l = &s.logins()[0];
    assert_eq!(l.int("authtype"), Some(1));
    let mut inner = "pässword".as_bytes().to_vec();
    inner.extend(b"ALICE");
    let mut outer = sha0::hash(&inner).to_vec();
    outer.extend(0..20u8); // the fake server's random
    assert_eq!(l.data("secure_password"), Some(sha0::hash(&outer).as_slice()));
}

#[test]
fn only_ascii_letters_are_uppercased_for_the_password_hash() {
    assert_eq!(ascii_uppercased("aliçe-ß"), "ALIçE-ß");
}

#[tokio::test]
async fn ticket_auth() {
    let s = FakeSoftEtherServer::new();
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.auth = ClientAuth::Ticket(vec![9; 20]);
    cfg.use_udp_accel = false;
    welcome_of(connect(&mut client_with(&s, cfg)).await.unwrap());
    let l = &s.logins()[0];
    assert_eq!((l.int("authtype"), l.data("ticket")), (Some(99), Some([9u8; 20].as_slice())));
}

#[tokio::test]
async fn certificate_auth_without_a_key_fails_before_the_login_is_sent() {
    let s = FakeSoftEtherServer::new();
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.auth = ClientAuth::certificate(vec![1, 2, 3], None);
    cfg.use_udp_accel = false;
    let e = match connect(&mut client_with(&s, cfg)).await {
        Ok(_) => panic!("must fail"),
        Err(e) => e.to_string(),
    };
    assert_eq!(e, "Certificate authentication needs the account's private key");
    assert!(s.logins().is_empty());
}

// MARK: - login pack

#[tokio::test]
async fn login_pack_is_what_the_stock_client_sends() {
    let s = FakeSoftEtherServer::new();
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.use_udp_accel = true;
    cfg.max_connections = 100;
    let mut c = client_with(&s, cfg);
    let mut offered = Vec::new();
    let auth = ClientAuth::Anonymous;
    let o = c
        .connect_once(
            "1.2.3.4",
            443,
            &auth,
            &mut |_| {},
            Some(&mut |key: &[u8]| {
                offered.push(key.len());
                40123
            }),
        )
        .await
        .unwrap();
    welcome_of(o);
    assert_eq!(offered, vec![128]);
    let l = &s.logins()[0];
    assert_eq!(l.int("max_connection"), Some(32), "clamped to 32");
    assert_eq!(l.int("qos"), Some(1));
    assert_eq!(l.int("rudp_bulk_max_version"), Some(2));
    assert_eq!(l.int("udp_acceleration_client_port"), Some(40123));
    assert_eq!(l.data("udp_acceleration_client_key").map(<[u8]>::len), Some(20));
    assert_eq!(l.data("udp_acceleration_client_key_v2").map(<[u8]>::len), Some(128));
    assert_eq!(l.str("ServerProductName"), Some("SoftEther VPN Server"));
    assert_eq!((l.int("ServerProductVer"), l.int("ServerProductBuild")), (Some(432), Some(9729)));
    assert!(l.data("pencore").is_some());

    let id = HostUniqueId::new([7; 32]);
    assert_eq!(l.data("unique_id"), Some(id.login_id().as_slice()));
    assert_eq!(l.data("UniqueId"), Some(id.node_id().as_slice()));
}

#[tokio::test]
async fn disable_qos_and_half_connection_floor() {
    let s = FakeSoftEtherServer::new();
    let mut cfg = ClientConfig::new("1.2.3.4", 443, ProxySettings::default());
    cfg.use_udp_accel = false;
    cfg.disable_qos = true;
    cfg.half_connection = true;
    cfg.max_connections = 1;
    welcome_of(connect(&mut client_with(&s, cfg)).await.unwrap());
    let l = &s.logins()[0];
    assert_eq!((l.int("qos"), l.int("max_connection"), l.int("half_connection")), (Some(0), Some(4), Some(1)));
    assert!(l.data("udp_acceleration_client_key").is_none());
}

#[tokio::test]
async fn unique_id_is_stable_across_attempts() {
    let s = FakeSoftEtherServer::new();
    let mut c = client(&s);
    welcome_of(connect(&mut c).await.unwrap());
    welcome_of(connect(&mut c).await.unwrap());
    let logins = s.logins();
    assert_eq!(logins[0].data("unique_id"), logins[1].data("unique_id"));
    assert_eq!(logins[0].data("UniqueId"), logins[1].data("UniqueId"));
}

// MARK: - welcome validation

fn welcome_pack(f: impl FnOnce(&mut Pack)) -> Pack {
    let mut p = Pack::new();
    p.add_str("session_name", "SID");
    p.add_str("connection_name", "CID");
    p.add_data("session_key", &[5; 20]);
    f(&mut p);
    p
}

#[test]
fn welcome_requires_session_connection_name_and_key() {
    for p in [
        Pack::new(),
        {
            let mut p = Pack::new();
            p.add_str("session_name", "");
            p.add_str("connection_name", "C");
            p.add_data("session_key", &[0; 20]);
            p
        },
        {
            let mut p = Pack::new();
            p.add_str("session_name", "S");
            p.add_data("session_key", &[0; 20]);
            p
        },
        {
            let mut p = Pack::new();
            p.add_str("session_name", "S");
            p.add_str("connection_name", "C");
            p.add_data("session_key", &[0; 19]);
            p
        },
    ] {
        assert!(parse_welcome(&p, "1.2.3.4", 8).is_err());
    }
}

#[test]
fn welcome_timeout_defaults_and_floor() {
    assert_eq!(parse_welcome(&welcome_pack(|_| {}), "1.2.3.4", 8).unwrap().timeout_ms, 30000);
    assert_eq!(parse_welcome(&welcome_pack(|p| p.add_int("timeout", 10)), "1.2.3.4", 8).unwrap().timeout_ms, 500);
}

#[test]
fn max_connection_rule() {
    assert_eq!(negotiated_max_connection(8, false, 4, false, false), 4);
    assert_eq!(negotiated_max_connection(8, true, 4, false, false), 8, "UDP recovery lifts the client cap");
    assert_eq!(negotiated_max_connection(100, true, 4, false, false), 32);
    assert_eq!(negotiated_max_connection(0, false, 4, false, false), 1);
    assert_eq!(negotiated_max_connection(1, false, 4, true, false), 2, "QoS needs two");
    assert_eq!(negotiated_max_connection(1, false, 4, true, true), 4, "QoS with half connection needs four");
    let w = parse_welcome(&welcome_pack(|p| p.add_int("max_connection", 6)), "1.2.3.4", 3).unwrap();
    assert_eq!(w.max_connection, 3);
}

#[test]
fn port_validation() {
    assert_eq!(valid_port(443), Some(443));
    assert_eq!((valid_port(0), valid_port(65536)), (None, None));
}

#[test]
fn udp_server_ip_prefers_a_public_advertised_address() {
    assert_eq!(resolve_udp_server_ip(Some("8.8.8.8"), "1.2.3.4").as_deref(), Some("8.8.8.8"));
    assert_eq!(resolve_udp_server_ip(Some("10.0.0.5"), "1.2.3.4").as_deref(), Some("1.2.3.4"));
    assert_eq!(resolve_udp_server_ip(Some("0.0.0.0"), "1.2.3.4").as_deref(), Some("1.2.3.4"));
    assert_eq!(resolve_udp_server_ip(None, "relay.example"), None);
    assert_eq!(resolve_udp_server_ip(Some("not-an-ip"), "1.2.3.4").as_deref(), Some("1.2.3.4"));
}

#[test]
fn udp_server_ip_as_a_pack_integer() {
    // 8.8.4.4 with the first octet in the low byte
    let w =
        parse_welcome(&welcome_pack(|p| p.add_int("udp_acceleration_server_ip", 0x0404_0808)), "1.2.3.4", 8).unwrap();
    assert_eq!(w.udp_server_ip.as_deref(), Some("8.8.4.4"));
    let w = parse_welcome(
        &welcome_pack(|p| {
            p.add_int("udp_acceleration_server_ip", 0x0404_0808);
            p.add_bool("udp_acceleration_server_ip@ipv6_bool", true);
        }),
        "1.2.3.4",
        8,
    )
    .unwrap();
    assert_eq!(w.udp_server_ip.as_deref(), Some("1.2.3.4"));
}

#[test]
fn redirect_host_forms() {
    let mut p = Pack::new();
    assert_eq!(redirect_host(&p, "1.2.3.4").unwrap(), "1.2.3.4", "absent = same host");
    p.add_str("Ip", "0.0.0.0");
    assert_eq!(redirect_host(&p, "1.2.3.4").unwrap(), "1.2.3.4");

    let mut p = Pack::new();
    p.add_int("Ip", 0x0201_A8C0); // 192.168.1.2
    assert_eq!(redirect_host(&p, "x").unwrap(), "192.168.1.2");

    let mut p = Pack::new();
    p.add_str("Ip", "bad host!");
    assert!(redirect_host(&p, "x").is_err());

    let mut p = Pack::new();
    p.add_str("Ip", "relay.example");
    p.add_bool("Ip@ipv6_bool", true);
    assert!(redirect_host(&p, "x").unwrap_err().to_string().contains("IPv6"));
}

#[tokio::test]
async fn redirect_keeps_the_current_port_when_offered_else_takes_the_first() {
    for (ports, expected) in [(vec![992, 443], 443), (vec![992, 8443], 992)] {
        let s = FakeSoftEtherServer::new();
        s.configure(|c| {
            c.redirect = true;
            c.redirect_ports = Some(ports);
        });
        match connect(&mut client(&s)).await.unwrap() {
            ConnectOutcome::Redirect(r) => assert_eq!((r.port, r.host.as_str()), (expected, "5.6.7.8")),
            ConnectOutcome::Connected { .. } => panic!("expected a redirect"),
        }
        assert!(s.stream_cancelled(0));
    }
}

#[tokio::test]
async fn redirect_needs_a_20_byte_ticket_and_a_valid_port() {
    let s = FakeSoftEtherServer::new();
    s.configure(|c| {
        c.redirect = true;
        c.redirect_ticket = vec![1; 19];
    });
    assert_eq!(connect_error(&s).await, "Cluster redirect missing 20-byte ticket");

    s.configure(|c| {
        c.redirect_ticket = vec![1; 20];
        c.redirect_ports = Some(vec![70000]);
    });
    assert_eq!(connect_error(&s).await, "Cluster redirect to an invalid port (70000)");
}

// MARK: - helpers

#[test]
fn http_post_layout() {
    let b = http_post("/x", "text/plain", b"abc", "h.example");
    assert_eq!(
        String::from_utf8(b).unwrap(),
        "POST /x HTTP/1.1\r\nHost: h.example\r\nContent-Type: text/plain\r\nConnection: Keep-Alive\r\nContent-Length: 3\r\n\r\nabc"
    );
}

#[test]
fn watermark_is_the_gif_image() {
    let w = crate::watermark::soft_ether_watermark();
    assert_eq!(&w[..6], b"GIF89a");
    assert!(w.len() > 1000);
}

#[test]
fn host_unique_id_file_persists_and_is_private() {
    let dir = std::env::temp_dir().join(format!("vpngate-uid-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("uid");
    let a = HostUniqueId::load(&path, |n| vec![0xab; n]);
    let b = HostUniqueId::load(&path, |_| panic!("must read the file"));
    assert_eq!(a, b);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }
    // A malformed file is replaced.
    std::fs::write(&path, b"short").unwrap();
    assert_eq!(HostUniqueId::load(&path, |n| vec![0xcd; n]).key, [0xcd; 32]);
    std::fs::remove_dir_all(&dir).unwrap();
}

// MARK: - golden vectors

#[test]
fn host_unique_id_golden() {
    let doc = golden::load("transcripts/host_unique_id");
    for c in doc["cases"].as_array().unwrap() {
        let key: [u8; 32] = golden::unhex(c["keyHex"].as_str().unwrap()).try_into().unwrap();
        let id = HostUniqueId::new(key);
        assert_eq!(id.login_id().to_vec(), golden::unhex(c["loginIdHex"].as_str().unwrap()));
        assert_eq!(id.node_id().to_vec(), golden::unhex(c["nodeIdHex"].as_str().unwrap()));
    }
}

#[test]
fn pkcs8_unwrap_and_sign_with_the_golden_key() {
    let doc = golden::load("transcripts/softether_login");
    let case = doc["cases"].as_array().unwrap().iter().find(|c| c["name"] == "certificate").unwrap();
    let key = golden::unhex(case["config"]["auth"]["privateKeyPKCS8Hex"].as_str().unwrap());
    let inner = cert_auth::unwrap_pkcs8(&key).expect("PKCS#8 wrapper");
    assert!(inner.len() < key.len());
    assert!(cert_auth::unwrap_pkcs8(inner).is_none(), "a bare PKCS#1 key is not a PKCS#8 wrapper");
    assert_eq!(cert_auth::sign(b"challenge", &key).unwrap(), cert_auth::sign(b"challenge", inner).unwrap());
    assert!(cert_auth::sign(b"x", b"not a key").is_err());
    assert!(cert_auth::sign(b"x", &vec![0u8; cert_auth::MAX_KEY_BYTES + 1])
        .unwrap_err()
        .to_string()
        .contains("too large"));
}

fn auth_from(v: &Value) -> ClientAuth {
    let hex = |k: &str| golden::unhex(v[k].as_str().unwrap());
    match v["type"].as_str().unwrap() {
        "anonymous" => ClientAuth::Anonymous,
        "plainPassword" => ClientAuth::PlainPassword(v["password"].as_str().unwrap().into()),
        "hashedPassword" => ClientAuth::HashedPassword(v["password"].as_str().unwrap().into()),
        "certificate" => ClientAuth::certificate(hex("certDerHex"), Some(hex("privateKeyPKCS8Hex"))),
        "ticket" => ClientAuth::Ticket(hex("ticketHex")),
        t => panic!("auth type {t}"),
    }
}

/// One connection of a transcript: checks every client write against the recorded bytes and answers with the recorded
/// server bytes.
struct TapeStream {
    expected: Vec<Value>, // events of this connection, in order
    next: usize,
    incoming: std::collections::VecDeque<Vec<u8>>,
    buffer: vpngate_core::byte_buffer::ByteBuffer,
    cancelled: bool,
}

fn expected_bytes(e: &Value) -> Vec<u8> {
    // The transcript stores the head without the blank line that ends it.
    let mut out = format!("{}\r\n\r\n", e["head"].as_str().unwrap()).into_bytes();
    match e["kind"].as_str().unwrap() {
        "http" => {
            if let Some(body) = e["bodyHex"].as_str() {
                out.extend(golden::unhex(body));
            } else {
                assert_eq!(e["body"]["watermark"], true);
                out.extend(crate::watermark::soft_ether_watermark());
                out.extend(golden::unhex(e["body"]["paddingHex"].as_str().unwrap()));
            }
            out
        }
        k => panic!("event kind {k}"),
    }
}

#[async_trait::async_trait]
impl ByteStream for TapeStream {
    fn buffer(&mut self) -> &mut vpngate_core::byte_buffer::ByteBuffer {
        &mut self.buffer
    }

    async fn start(&mut self) -> Result<(), StreamError> {
        Ok(())
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
        let e = self.expected.get(self.next).expect("client wrote more than the transcript has");
        assert_eq!(e["dir"], "c2s", "the transcript expects the server to speak next");
        let want = expected_bytes(e);
        assert!(data == want.as_slice(), "client bytes differ from the transcript at event {}", self.next);
        self.next += 1;
        while let Some(r) = self.expected.get(self.next).filter(|e| e["dir"] == "s2c") {
            self.incoming.push_back(golden::unhex(r["hex"].as_str().unwrap()));
            self.next += 1;
        }
        Ok(())
    }

    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        if self.cancelled {
            return Err(StreamError::Closed);
        }
        self.incoming.pop_front().ok_or(StreamError::Closed)
    }

    fn cancel(&mut self) {
        self.cancelled = true;
    }
}

fn welcome_json(w: &Welcome) -> Value {
    let hex = |b: &Option<Vec<u8>>| {
        b.as_ref().map_or(Value::Null, |b| json!(b.iter().map(|x| format!("{x:02x}")).collect::<String>()))
    };
    json!({
        "sessionName": w.session_name, "connectionName": w.connection_name, "timeoutMs": w.timeout_ms,
        "message": w.message, "sessionKey": hex(&w.session_key), "maxConnection": w.max_connection,
        "useCompress": w.use_compress, "useEncrypt": w.use_encrypt, "halfConnection": w.half_connection,
        "qos": w.qos, "enableUdpRecovery": w.enable_udp_recovery, "useUdpAcceleration": w.use_udp_acceleration,
        "udpAccelVersion": w.udp_accel_version, "udpServerIp": w.udp_server_ip, "udpServerPort": w.udp_server_port,
        "udpServerCookie": w.udp_server_cookie, "udpClientCookie": w.udp_client_cookie, "udpServerKey": hex(&w.udp_server_key),
        "udpFastDisconnect": w.udp_fast_disconnect,
    })
}

#[tokio::test]
async fn golden_login_transcripts_replay_byte_for_byte() {
    let doc = golden::load("transcripts/softether_login");
    let mut replayed = 0;
    for case in doc["cases"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let cfg = &case["config"];
        let events: Vec<Value> = case["events"].as_array().unwrap().clone();
        // The data-phase frame of the first case belongs to the connection pool (U08b/U10).
        let events: Vec<Value> = events.into_iter().filter(|e| e["kind"] != "data").collect();
        let per_conn = |n: u64| -> Vec<Value> { events.iter().filter(|e| e["conn"] == n).cloned().collect() };

        let counter = Arc::new(Mutex::new(0u64));
        let events2 = events.clone();
        let _ = &per_conn;
        let factory: StreamFactory = Arc::new(move |_, _, _| {
            let mut n = counter.lock().unwrap();
            let expected: Vec<Value> = events2.iter().filter(|e| e["conn"] == *n).cloned().collect();
            *n += 1;
            Box::new(TapeStream {
                expected,
                next: 0,
                incoming: Default::default(),
                buffer: Default::default(),
                cancelled: false,
            })
        });

        let mut config = ClientConfig::new(
            cfg["host"].as_str().unwrap(),
            cfg["port"].as_u64().unwrap() as u16,
            ProxySettings::default(),
        );
        config.hub_name = cfg["hub"].as_str().unwrap().into();
        config.user_name = cfg["user"].as_str().unwrap().into();
        config.auth = auth_from(&cfg["auth"]);
        config.max_connections = cfg["maxConnections"].as_u64().unwrap() as usize;
        config.use_compress = cfg["useCompress"].as_bool().unwrap();
        config.half_connection = cfg["halfConnection"].as_bool().unwrap();
        config.use_udp_accel = cfg["useUdpAccel"].as_bool().unwrap();
        let key: [u8; 32] = golden::unhex(cfg["hostUniqueIdKey"].as_str().unwrap()).try_into().unwrap();
        let environment = ClientEnvironment {
            os_name: cfg["environment"]["osName"].as_str().unwrap().into(),
            os_version: cfg["environment"]["osVersion"].as_str().unwrap().into(),
            hostname: cfg["environment"]["hostname"].as_str().unwrap().into(),
        };
        let entropy = ReplayEntropy::new(&case["entropy"]);
        let mut client =
            SoftEtherClient::new(config.clone(), HostUniqueId::new(key), factory, Box::new(entropy), environment);

        // connect() minus the data services: follow at most one redirect, which is all the transcripts need.
        let run = async {
            let mut outcome = client.connect_once(&config.host, config.port, &config.auth, &mut |_| {}, None).await?;
            if let ConnectOutcome::Redirect(r) = outcome {
                outcome =
                    client.connect_once(&r.host, r.port, &ClientAuth::Ticket(r.ticket), &mut |_| {}, None).await?;
            }
            Ok::<_, StreamError>(outcome)
        };
        let result = &case["result"];
        match run.await {
            Ok(ConnectOutcome::Connected { welcome, .. }) => {
                assert_eq!(result["ok"], true, "{name}: transcript expects a failure");
                let got = welcome_json(&welcome);
                assert!(
                    golden::json_eq(&got, &result["welcome"]),
                    "{name}: welcome\n got {got}\nwant {}",
                    result["welcome"]
                );
            }
            Ok(ConnectOutcome::Redirect(_)) => panic!("{name}: second redirect"),
            Err(e) => {
                assert_eq!(result["ok"], false, "{name}: unexpected error {e}");
                assert_eq!(e.to_string(), result["error"].as_str().unwrap(), "{name}");
            }
        }
        replayed += 1;
    }
    assert_eq!(replayed, 10);
}

#[test]
fn sha1_is_what_the_login_id_uses() {
    // Guards the "login" prefix + key layout independently of the golden file.
    let mut h = Sha1::new();
    h.update(b"login");
    h.update([0u8; 32]);
    assert_eq!(HostUniqueId::new([0; 32]).login_id().to_vec(), h.finalize().to_vec());
}
