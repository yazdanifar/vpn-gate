//! Network engine without OS calls: TLS, SoftEther client, bridge, DNS, session.

pub mod cert_auth;
pub mod connection;
pub mod connection_pool;
pub mod dns_message;
pub mod dns_proxy;
pub mod dns_server;
pub mod entropy;
pub mod ethernet_bridge;
pub mod host_unique_id;
pub mod probe;
pub mod proxy;
pub mod session;
pub mod socks;
pub mod softether_client;
pub mod stream;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
pub mod tls;
pub mod udp_accel;
pub mod watermark;
