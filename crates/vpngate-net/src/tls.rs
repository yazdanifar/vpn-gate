//! TLS stream over TCP (direct or through an HTTP CONNECT / SOCKS5 proxy).
//!
//! By default it accepts the self-signed certificates VPN Gate relays use; the policy can pin the leaf certificate's
//! SHA-1/SHA-256 fingerprint or require system trust (through the platform verifier).

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{self, CryptoProvider};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as TlsError, SignatureScheme};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::cert_pin::ServerCertPolicy;
use vpngate_core::ipc::ProxySettings;

use crate::proxy;
use crate::stream::{ByteStream, StreamError};

pub const DEFAULT_START_TIMEOUT: Duration = Duration::from_secs(15);
const KEEPALIVE_IDLE: Duration = Duration::from_secs(60);

type FailureSlot = Arc<Mutex<Option<String>>>;

/// Applies a `ServerCertPolicy` as a rustls verifier, remembering why it refused so `start` can report it instead of a
/// bare TLS alert.
#[derive(Debug)]
struct PolicyVerifier {
    policy: ServerCertPolicy,
    provider: Arc<CryptoProvider>,
    system: Option<Arc<dyn ServerCertVerifier>>,
    failure: FailureSlot,
}

impl PolicyVerifier {
    fn refuse(&self, reason: String) -> TlsError {
        *self.failure.lock().unwrap() = Some(reason.clone());
        TlsError::General(reason)
    }
}

impl ServerCertVerifier for PolicyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, TlsError> {
        if let Some(why) = self.policy.rejection(Some(end_entity.as_ref())) {
            return Err(self.refuse(why.to_string()));
        }
        if let Some(system) = &self.system {
            system
                .verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
                .map_err(|e| self.refuse(format!("Server certificate is not trusted: {e}")))?;
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        crypto::verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        crypto::verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider.signature_verification_algorithms.supported_schemes()
    }
}

fn client_config(policy: &ServerCertPolicy, failure: &FailureSlot) -> Result<ClientConfig, StreamError> {
    let provider = Arc::new(crypto::ring::default_provider());
    let system: Option<Arc<dyn ServerCertVerifier>> = if *policy == ServerCertPolicy::SystemTrust {
        let v = rustls_platform_verifier::Verifier::new(provider.clone())
            .map_err(|e| StreamError::Protocol(format!("System certificate store unavailable: {e}")))?;
        Some(Arc::new(v))
    } else {
        None
    };
    let verifier =
        PolicyVerifier { policy: policy.clone(), provider: provider.clone(), system, failure: failure.clone() };
    // TLS 1.2 is rustls' floor, so no explicit minimum is needed.
    Ok(ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| StreamError::Protocol(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

pub struct TlsStream {
    host: String,
    port: u16,
    proxy: ProxySettings,
    policy: ServerCertPolicy,
    buffer: ByteBuffer,
    failure: FailureSlot,
    io: Option<tokio_rustls::client::TlsStream<TcpStream>>,
    peer: Option<SocketAddr>,
}

impl TlsStream {
    pub fn new(host: &str, port: u16, proxy: &ProxySettings, policy: ServerCertPolicy) -> Self {
        TlsStream {
            host: host.to_string(),
            port,
            proxy: proxy.clone(),
            policy,
            buffer: ByteBuffer::new(),
            failure: Arc::default(),
            io: None,
            peer: None,
        }
    }

    pub async fn start_with_timeout(&mut self, limit: Duration) -> Result<(), StreamError> {
        let result = match tokio::time::timeout(limit, self.connect()).await {
            Ok(r) => r,
            Err(_) => Err(StreamError::Timeout),
        };
        if result.is_err() {
            // A failed or timed-out attempt must not stay half-open.
            self.io = None;
            if let Some(why) = self.failure.lock().unwrap().clone() {
                return Err(StreamError::Protocol(why));
            }
        }
        result
    }

    async fn connect(&mut self) -> Result<(), StreamError> {
        let tcp = match proxy::effective(&self.proxy) {
            Some((p, proxy_port)) => proxy::connect(p, proxy_port, &self.host, self.port).await?,
            None => crate::connect::connect_tcp(&self.host, self.port).await?,
        };
        tcp.set_nodelay(true)?;
        SockRef::from(&tcp).set_tcp_keepalive(&TcpKeepalive::new().with_time(KEEPALIVE_IDLE))?;
        self.peer = tcp.peer_addr().ok();

        let config = client_config(&self.policy, &self.failure)?;
        // An IP literal gives `ServerName::IpAddress`, for which rustls sends no SNI.
        let name = ServerName::try_from(self.host.clone())
            .map_err(|_| StreamError::Protocol(format!("Invalid server name: {}", self.host)))?;
        let tls = TlsConnector::from(Arc::new(config)).connect(name, tcp).await?;
        self.io = Some(tls);
        Ok(())
    }
}

#[async_trait]
impl ByteStream for TlsStream {
    fn buffer(&mut self) -> &mut ByteBuffer {
        &mut self.buffer
    }

    async fn start(&mut self) -> Result<(), StreamError> {
        self.start_with_timeout(DEFAULT_START_TIMEOUT).await
    }

    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError> {
        let io = self.io.as_mut().ok_or(StreamError::Closed)?;
        io.write_all(data).await?;
        io.flush().await?;
        Ok(())
    }

    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError> {
        let io = self.io.as_mut().ok_or(StreamError::Closed)?;
        let mut buf = vec![0u8; 65536];
        let n = io.read(&mut buf).await?;
        if n == 0 {
            return Err(StreamError::Closed);
        }
        buf.truncate(n);
        Ok(buf)
    }

    fn cancel(&mut self) {
        self.io = None;
    }

    /// The peer of the ready connection: the address the hostname resolved to, or the proxy's address behind a proxy.
    fn remote_ipv4(&self) -> Option<String> {
        match self.peer?.ip() {
            IpAddr::V4(a) => Some(a.to_string()),
            IpAddr::V6(a) => a.to_ipv4_mapped().map(|a| a.to_string()),
        }
    }
}
