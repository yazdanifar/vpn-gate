//! SoftEther SSL-VPN client handshake: signature upload, login (anonymous, password, certificate, ticket) and welcome
//! validation. Protocol reference: SoftEtherVPN src/Cedar/Protocol.c.
//!
//! This is the connection-level half of `SoftEtherClient.swift`: one attempt per [`SoftEtherClient::connect_once`].
//! Redirect following, the connection pool and keep-alives are in `connection`; UDP acceleration comes in U10b.

use std::sync::Arc;

use vpngate_core::ipc::{ProxyKind, ProxySettings};
use vpngate_core::pack::Pack;
use vpngate_core::packets::pack_ip_string;
use vpngate_core::{sha0, softether_error, validation};

use crate::cert_auth;
use crate::entropy::{ClientEnvironment, Entropy};
use crate::host_unique_id::HostUniqueId;
use crate::stream::{ByteStream, StreamError, StreamFactory};
use crate::watermark::soft_ether_watermark;

pub const DEFAULT_HUB_NAME: &str = "VPNGATE";
pub const DEFAULT_USER_NAME: &str = "vpn";
pub(crate) const CLIENT_VER: u32 = 444;
pub(crate) const CLIENT_BUILD: u32 = 9807;
pub(crate) const CLIENT_STR: &str = "SoftEther VPN Client";
const PLAIN_SIGNATURE: &[u8] = b"VPNCONNECT";

/// Binds the UDP acceleration socket for the given v2 client key and returns its local port.
pub type UdpPrepare<'a> = dyn FnMut(&[u8]) -> u16 + Send + 'a;

pub type SignFn = Arc<dyn Fn(&[u8]) -> Result<Vec<u8>, StreamError> + Send + Sync>;

#[derive(Clone)]
pub enum ClientAuth {
    Anonymous,
    PlainPassword(String),
    /// Standard password (authtype 1). Takes the PLAINTEXT password; the SHA-0 hashing happens in the login pack.
    HashedPassword(String),
    Certificate {
        cert_der: Vec<u8>,
        sign: SignFn,
    },
    Ticket(Vec<u8>),
}

impl ClientAuth {
    /// Certificate login signing with the account's private key (PKCS#1 or PKCS#8 DER).
    pub fn certificate(cert_der: Vec<u8>, private_key_der: Option<Vec<u8>>) -> Self {
        let sign: SignFn = Arc::new(move |challenge| match &private_key_der {
            Some(k) if !k.is_empty() => cert_auth::sign(challenge, k),
            _ => Err(StreamError::Protocol("Certificate authentication needs the account's private key".into())),
        });
        ClientAuth::Certificate { cert_der, sign }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    pub session_name: String,
    pub connection_name: String,
    pub timeout_ms: i64,
    pub message: Option<String>,
    pub session_key: Option<Vec<u8>>,
    pub max_connection: usize,
    pub use_compress: bool,
    pub use_encrypt: bool,
    pub half_connection: bool,
    pub qos: bool,
    /// Server `enable_udp_recovery`: when set the server's max_connection is not capped by the client's setting.
    pub enable_udp_recovery: bool,

    // UDP acceleration
    pub use_udp_acceleration: bool,
    pub udp_accel_version: u32,
    pub udp_server_ip: Option<String>,
    pub udp_server_port: Option<u16>,
    pub udp_server_cookie: Option<u32>,
    pub udp_client_cookie: Option<u32>,
    pub udp_server_key: Option<Vec<u8>>,
    pub udp_fast_disconnect: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedirectInfo {
    pub host: String,
    pub port: u16,
    pub ticket: Vec<u8>,
}

pub enum ConnectOutcome {
    /// Logged in; the stream carries the data phase (bytes the server sent after the welcome are still in its buffer).
    Connected {
        welcome: Box<Welcome>,
        stream: Box<dyn ByteStream>,
    },
    Redirect(RedirectInfo),
}

#[derive(Clone)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub hub_name: String,
    pub user_name: String,
    pub auth: ClientAuth,
    pub proxy: ProxySettings,
    pub max_connections: usize,
    pub use_compress: bool,
    pub use_udp_accel: bool,
    pub disable_qos: bool,
    pub half_connection: bool,
}

impl ClientConfig {
    pub fn new(host: &str, port: u16, proxy: ProxySettings) -> Self {
        ClientConfig {
            host: host.to_string(),
            port,
            hub_name: DEFAULT_HUB_NAME.into(),
            user_name: DEFAULT_USER_NAME.into(),
            auth: ClientAuth::Anonymous,
            proxy,
            max_connections: 8,
            use_compress: false,
            use_udp_accel: true,
            disable_qos: false,
            half_connection: false,
        }
    }
}

/// Per-attempt values of the login pack that depend on the server hello and the UDP socket.
struct LoginArgs<'a> {
    random: &'a [u8],
    auth: &'a ClientAuth,
    host: &'a str,
    port: u16,
    client_udp_port: u16,
    client_key_v1: &'a [u8],
    client_key_v2: &'a [u8],
    server_name: &'a str,
    server_ver: u32,
    server_build: u32,
}

pub struct SoftEtherClient {
    config: ClientConfig,
    /// Clamped session size the login pack asks for.
    max_connections: usize,
    login_unique_id: [u8; 20],
    node_unique_id: [u8; 16],
    /// Set when the server rejected the watermark upload and the plain one was used; additional connections then match.
    plain_signature: bool,
    make_stream: StreamFactory,
    entropy: Box<dyn Entropy>,
    environment: ClientEnvironment,
}

impl SoftEtherClient {
    pub fn new(
        config: ClientConfig,
        unique_id: HostUniqueId,
        make_stream: StreamFactory,
        entropy: Box<dyn Entropy>,
        environment: ClientEnvironment,
    ) -> Self {
        // Half connection needs separate send/receive sockets; request at least 4 (upstream's own minimum, Protocol.c:6022).
        let floor = if config.half_connection { 4 } else { 1 };
        let max_connections = config.max_connections.min(32).max(floor);
        SoftEtherClient {
            max_connections,
            login_unique_id: unique_id.login_id(),
            node_unique_id: unique_id.node_id(),
            plain_signature: false,
            config,
            make_stream,
            entropy,
            environment,
        }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub(crate) fn make_stream(&self) -> StreamFactory {
        self.make_stream.clone()
    }

    /// Follows a cluster redirect: later connections (and additional ones) go to the new target with the ticket.
    pub(crate) fn retarget(&mut self, host: String, port: u16, auth: ClientAuth) {
        self.config.host = host;
        self.config.port = port;
        self.config.auth = auth;
    }

    /// Whether the plain `VPNCONNECT` signature had to be used (additional connections must match).
    pub fn plain_signature(&self) -> bool {
        self.plain_signature
    }

    /// One connection attempt: TLS, signature, login. `udp_prepare` is called with the 128-byte v2 client key when UDP
    /// acceleration is on and returns the local UDP port to advertise (0 when no socket could be bound).
    pub async fn connect_once(
        &mut self,
        host: &str,
        port: u16,
        auth: &ClientAuth,
        log: &mut (dyn FnMut(&str) + Send),
        udp_prepare: Option<&mut UdpPrepare<'_>>,
    ) -> Result<ConnectOutcome, StreamError> {
        let mut stream = (self.make_stream)(host, port, &self.config.proxy);
        let result = self.handshake(&mut stream, host, port, auth, log, udp_prepare).await;
        match result {
            Ok(welcome) => Ok(ConnectOutcome::Connected { welcome: Box::new(welcome), stream }),
            Err(HandshakeEnd::Redirect(info)) => {
                stream.cancel();
                Ok(ConnectOutcome::Redirect(info))
            }
            Err(HandshakeEnd::Failed(e)) => {
                stream.cancel();
                Err(e)
            }
        }
    }

    async fn handshake(
        &mut self,
        stream: &mut Box<dyn ByteStream>,
        host: &str,
        port: u16,
        auth: &ClientAuth,
        log: &mut (dyn FnMut(&str) + Send),
        udp_prepare: Option<&mut UdpPrepare<'_>>,
    ) -> Result<Welcome, HandshakeEnd> {
        stream.start().await?;
        log(&format!("TLS established with {host}:{port}"));

        // 1. Signature upload
        let body = self.signature_body();
        let hello = match upload_signature(stream.as_mut(), &body, host).await {
            Ok(h) => h,
            Err(e) => {
                log(&format!("Signature rejected ({e}); retrying plain"));
                stream.cancel();
                *stream = (self.make_stream)(host, port, &self.config.proxy);
                stream.start().await?;
                let h = upload_signature(stream.as_mut(), PLAIN_SIGNATURE, host).await?;
                self.plain_signature = true;
                h
            }
        };

        let random = match hello.data("random") {
            Some(r) if r.len() == 20 => r.to_vec(),
            _ => {
                return Err(StreamError::Protocol("Server hello missing random (not a SoftEther server?)".into()).into())
            }
        };
        let server_name = hello.str("hello").unwrap_or("").to_string();
        let server_ver = hello.int("version").unwrap_or(0);
        let server_build = hello.int("build").unwrap_or(0);
        log(&format!(
            "Server: {} v{server_ver} build {server_build}",
            if server_name.is_empty() { "?" } else { &server_name }
        ));

        // The client keys are drawn even with UDP acceleration off: the golden transcripts pin the draw order.
        let client_key_v1 = self.entropy.bytes(20);
        let client_key_v2 = self.entropy.bytes(128);
        let client_udp_port = match (self.config.use_udp_accel, udp_prepare) {
            (true, Some(prepare)) => prepare(&client_key_v2),
            _ => 0,
        };

        // 2. Login
        let login = self.login_pack(&LoginArgs {
            random: &random,
            auth,
            host,
            port,
            client_udp_port,
            client_key_v1: &client_key_v1,
            client_key_v2: &client_key_v2,
            server_name: &server_name,
            server_ver,
            server_build,
        })?;
        let body = self.with_dummy(login).serialize();
        stream.send(&http_post("/vpnsvc/vpn.cgi", "application/octet-stream", &body, host)).await?;
        let w = read_pack(stream.as_mut()).await?;

        if let Some(err) = w.int("error") {
            if err != 0 {
                return Err(StreamError::Protocol(format!(
                    "Server refused login: {}",
                    softether_error::describe(i64::from(err))
                ))
                .into());
            }
        }

        // Cluster redirect
        if w.int("Redirect").unwrap_or(0) != 0 {
            return Err(HandshakeEnd::Redirect(redirect_info(&w, host, port)?));
        }

        Ok(parse_welcome(&w, host, self.max_connections)?)
    }

    /// The signature body of every connection: the watermark plus random padding (HTTP_PACK_RAND_SIZE_MAX*2), or the
    /// plain marker when the server refused the watermark on the first connection.
    pub fn signature_body(&mut self) -> Vec<u8> {
        if self.plain_signature {
            return PLAIN_SIGNATURE.to_vec();
        }
        let mut body = soft_ether_watermark();
        let n = self.entropy.below(2000);
        body.extend(self.entropy.bytes(n));
        body
    }

    /// Adds the `pencore` padding upstream's HttpClientSend appends to every pack.
    pub fn with_dummy(&mut self, mut p: Pack) -> Pack {
        let n = self.entropy.below(1000);
        let pad = self.entropy.bytes(n);
        p.add_data("pencore", &pad);
        p
    }

    fn login_pack(&self, a: &LoginArgs<'_>) -> Result<Pack, StreamError> {
        let cfg = &self.config;
        let mut p = Pack::new();
        p.add_str("method", "login");
        p.add_str("hubname", &cfg.hub_name);
        p.add_str("username", &cfg.user_name);

        match a.auth {
            ClientAuth::Anonymous => p.add_int("authtype", 0),
            ClientAuth::HashedPassword(pw) => {
                p.add_int("authtype", 1);
                let mut data = pw.as_bytes().to_vec();
                data.extend(ascii_uppercased(&cfg.user_name).as_bytes());
                let hashed = sha0::hash(&data);
                let mut secure = hashed.to_vec();
                secure.extend_from_slice(a.random);
                p.add_data("secure_password", &sha0::hash(&secure));
            }
            ClientAuth::PlainPassword(pw) => {
                p.add_int("authtype", 2);
                p.add_str("plain_password", pw);
            }
            ClientAuth::Certificate { cert_der, sign } => {
                p.add_int("authtype", 3);
                p.add_data("cert", cert_der);
                let signature = sign(a.random)?;
                p.add_data("sign", &signature);
            }
            ClientAuth::Ticket(t) => {
                p.add_int("authtype", 99);
                p.add_data("ticket", t);
            }
        }

        p.add_str("client_str", CLIENT_STR);
        p.add_int("client_ver", CLIENT_VER);
        p.add_int("client_build", CLIENT_BUILD);
        p.add_int("protocol", 0); // TCP
        p.add_str("hello", CLIENT_STR);
        p.add_int("version", CLIENT_VER);
        p.add_int("build", CLIENT_BUILD);
        p.add_int("client_id", 0);
        p.add_int("max_connection", self.max_connections as u32);
        p.add_bool("use_encrypt", true);
        p.add_bool("use_compress", cfg.use_compress);
        p.add_bool("half_connection", cfg.half_connection);
        p.add_bool("require_bridge_routing_mode", false);
        p.add_bool("require_monitor_mode", false);
        p.add_bool("qos", !cfg.disable_qos);
        p.add_bool("support_bulk_on_rudp", true);
        p.add_bool("support_hmac_on_bulk_of_rudp", true);
        p.add_bool("support_udp_recovery", true);
        p.add_data("unique_id", &self.login_unique_id);

        if cfg.use_udp_accel {
            p.add_bool("use_udp_acceleration", true);
            p.add_ipv4("udp_acceleration_client_ip", 0);
            p.add_int("udp_acceleration_client_port", u32::from(a.client_udp_port));
            p.add_data("udp_acceleration_client_key", a.client_key_v1);
            p.add_data("udp_acceleration_client_key_v2", a.client_key_v2);
            p.add_bool("support_hmac_on_udp_acceleration", true);
            p.add_bool("support_udp_accel_fast_disconnect_detect", true);
            p.add_int("udp_acceleration_version", 2);
            p.add_int("udp_acceleration_max_version", 2);
        }
        p.add_int("rudp_bulk_max_version", 2);

        // Node info
        p.add_str("ClientProductName", CLIENT_STR);
        p.add_str("ServerProductName", a.server_name);
        p.add_str("ClientOsName", &self.environment.os_name);
        p.add_str("ClientOsVer", &self.environment.os_version);
        p.add_str("ClientOsProductId", "");
        p.add_str("ClientHostname", &self.environment.hostname);
        p.add_str("ServerHostname", a.host);
        p.add_str("ProxyHostname", if cfg.proxy.kind == ProxyKind::None { "" } else { &cfg.proxy.host });
        p.add_data("UniqueId", &self.node_unique_id);
        p.add_int("ClientProductVer", CLIENT_VER);
        p.add_int("ClientProductBuild", CLIENT_BUILD);
        p.add_int("ServerProductVer", a.server_ver);
        p.add_int("ServerProductBuild", a.server_build);
        p.add_int("ClientPort", 0);
        p.add_int("ServerPort2", u32::from(a.port));
        p.add_int("ProxyPort", cfg.proxy.port.clamp(0, i64::from(u32::MAX)) as u32);
        p.add_ipv4("ClientIpAddress", 0);
        p.add_ipv4("ServerIpAddress", 0);
        p.add_ipv4("ProxyIpAddress", 0);
        for name in ["ClientIpAddress6", "ServerIpAddress6", "ProxyIpAddress6"] {
            p.add_data(name, &[0u8; 16]);
        }
        Ok(p)
    }
}

enum HandshakeEnd {
    Redirect(RedirectInfo),
    Failed(StreamError),
}

impl From<StreamError> for HandshakeEnd {
    fn from(e: StreamError) -> Self {
        HandshakeEnd::Failed(e)
    }
}

/// Upstream `Upper()` only maps a-z; a Unicode uppercase would also change non-ASCII letters and break the hash.
pub fn ascii_uppercased(s: &str) -> String {
    s.to_ascii_uppercase()
}

pub fn http_post(path: &str, content_type: &str, body: &[u8], host: &str) -> Vec<u8> {
    let mut out = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {content_type}\r\nConnection: Keep-Alive\r\nContent-Length: {}\r\n\r\n",
        body.len()
    )
    .into_bytes();
    out.extend_from_slice(body);
    out
}

pub async fn upload_signature(s: &mut dyn ByteStream, body: &[u8], host: &str) -> Result<Pack, StreamError> {
    s.send(&http_post("/vpnsvc/connect.cgi", "image/jpeg", body, host)).await?;
    read_pack(s).await
}

pub async fn read_pack(s: &mut dyn ByteStream) -> Result<Pack, StreamError> {
    let head = s.recv_http_head().await?;
    if head.status_code() != Some(200) {
        return Err(StreamError::Protocol(format!("HTTP: {}", head.status)));
    }
    let len = match head.headers.get("content-length").and_then(|v| v.parse::<usize>().ok()) {
        Some(n) if n > 0 && n < 1 << 20 => n,
        _ => return Err(StreamError::Protocol("Bad response length".into())),
    };
    let body = s.recv(len).await?;
    Pack::parse(&body).map_err(|e| StreamError::Protocol(e.to_string()))
}

// MARK: - Welcome field validation (hostile servers: TLS verification is off for VPN Gate relays)

/// Session size per upstream (Protocol.c ClientConnectGetSessionKey): the server's value, capped by the client's own
/// setting unless the server offers UDP recovery, clamped to 1...32, and at least 2 (4 with half connection) under QoS.
pub fn negotiated_max_connection(
    server: i64,
    enable_udp_recovery: bool,
    client: usize,
    qos: bool,
    half: bool,
) -> usize {
    let mut n = server;
    if !enable_udp_recovery {
        n = n.min(client as i64);
    }
    n = n.clamp(1, 32);
    if qos {
        n = n.max(if half { 4 } else { 2 });
    }
    n as usize
}

pub fn valid_port(raw: u32) -> Option<u16> {
    u16::try_from(raw).ok().filter(|p| *p != 0)
}

fn is_ipv6_flagged(w: &Pack, name: &str) -> bool {
    w.int(&format!("{name}@ipv6_bool")).unwrap_or(0) != 0
}

/// Redirect target from the pack's `Ip`: a hostname/IPv4 string, or SoftEther's pack integer. 0.0.0.0 / absent = same host.
pub fn redirect_host(w: &Pack, fallback: &str) -> Result<String, StreamError> {
    if is_ipv6_flagged(w, "Ip") {
        return Err(StreamError::Protocol("Cluster redirect to an IPv6 address is not supported".into()));
    }
    let candidate = match (w.str("Ip"), w.int("Ip")) {
        (Some(s), _) if !s.is_empty() => s.to_string(),
        (_, Some(n)) => pack_ip_string(n),
        _ => return Ok(fallback.to_string()),
    };
    if !validation::is_valid_host(&candidate) {
        return Err(StreamError::Protocol("Cluster redirect to an invalid host".into()));
    }
    Ok(if candidate == "0.0.0.0" { fallback.to_string() } else { candidate })
}

fn redirect_info(w: &Pack, host: &str, port: u16) -> Result<RedirectInfo, StreamError> {
    let ticket = match w.data("Ticket") {
        Some(t) if t.len() == 20 => t.to_vec(),
        _ => return Err(StreamError::Protocol("Cluster redirect missing 20-byte ticket".into())),
    };
    let redirect_ip = redirect_host(w, host)?;
    let mut redirect_port = port;
    // "Port" is a list: the original client keeps the port it is already using if the server offers it,
    // otherwise takes the first one (client_exe.c:53335-53370).
    let offered = w.ints("Port");
    if let Some(first) = offered.first() {
        let chosen = if offered.contains(&u32::from(port)) { u32::from(port) } else { *first };
        redirect_port = valid_port(chosen)
            .ok_or_else(|| StreamError::Protocol(format!("Cluster redirect to an invalid port ({chosen})")))?;
    }
    Ok(RedirectInfo { host: redirect_ip, port: redirect_port, ticket })
}

/// The UDP endpoint to use: the advertised IPv4 if it is a public literal, else the TCP peer (unspecified/private
/// advertisements are the server's own view of itself behind NAT). `None` if neither is an IPv4 literal.
pub fn resolve_udp_server_ip(advertised: Option<&str>, tcp_host: &str) -> Option<String> {
    if let Some(a) = advertised {
        if validation::is_ipv4_literal(a) && !validation::is_non_public_ipv4(a) {
            return Some(a.to_string());
        }
    }
    validation::is_ipv4_literal(tcp_host).then(|| tcp_host.to_string())
}

/// Parses the welcome; without a session name and key nothing after this could work (upstream ParseWelcome fails the
/// same way). Upstream also asks for the policy:* elements, but PackGetPolicy never fails, so nothing is required of them.
pub fn parse_welcome(w: &Pack, host: &str, client_max_connections: usize) -> Result<Welcome, StreamError> {
    let malformed = || {
        StreamError::Protocol(
            "Malformed welcome from server (missing session_name, connection_name or session_key)".into(),
        )
    };
    let session_name = w.str("session_name").filter(|s| !s.is_empty()).ok_or_else(malformed)?;
    let connection_name = w.str("connection_name").ok_or_else(malformed)?;
    let session_key = w.data("session_key").filter(|k| k.len() == 20).ok_or_else(malformed)?;

    let flag = |n: &str| w.int(n).unwrap_or(0) != 0;
    let use_compress = flag("use_compress");
    let use_encrypt = flag("use_encrypt");
    let half_connection = flag("half_connection");
    let qos = flag("qos");
    let enable_udp_recovery = flag("enable_udp_recovery");
    let max_connection = negotiated_max_connection(
        i64::from(w.int("max_connection").unwrap_or(1)),
        enable_udp_recovery,
        client_max_connections,
        qos,
        half_connection,
    );
    let timeout_ms = i64::from(w.int("timeout").unwrap_or(30000)).max(500);
    let message = w.data("Msg").map(|m| String::from_utf8_lossy(m).into_owned());

    // A bad value only disables UDP; the TCP session is unaffected.
    let advertised = match w.str("udp_acceleration_server_ip") {
        Some(s) if !s.is_empty() => Some(s.to_string()),
        _ => match w.int("udp_acceleration_server_ip") {
            Some(n) if !is_ipv6_flagged(w, "udp_acceleration_server_ip") => Some(pack_ip_string(n)),
            _ => None,
        },
    };

    Ok(Welcome {
        session_name: session_name.to_string(),
        connection_name: connection_name.to_string(),
        timeout_ms,
        message,
        session_key: Some(session_key.to_vec()),
        max_connection,
        use_compress,
        use_encrypt,
        half_connection,
        qos,
        enable_udp_recovery,
        use_udp_acceleration: flag("use_udp_acceleration"),
        udp_accel_version: w.int("udp_acceleration_version").unwrap_or(1),
        udp_server_ip: resolve_udp_server_ip(advertised.as_deref(), host),
        udp_server_port: w.int("udp_acceleration_server_port").and_then(valid_port),
        udp_server_cookie: w.int("udp_acceleration_server_cookie"),
        udp_client_cookie: w.int("udp_acceleration_client_cookie"),
        udp_server_key: w.data("udp_acceleration_server_key_v2").map(<[u8]>::to_vec),
        udp_fast_disconnect: flag("udp_accel_fast_disconnect_detect"),
    })
}

#[cfg(test)]
mod tests;
