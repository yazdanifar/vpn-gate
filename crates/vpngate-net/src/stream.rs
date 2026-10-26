//! Byte stream under the SoftEther protocol.

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use vpngate_core::byte_buffer::ByteBuffer;
use vpngate_core::http_head::{self, HttpHead};
use vpngate_core::ipc::ProxySettings;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamError {
    Closed,
    Timeout,
    Protocol(String),
    /// Any other transport failure (refused, no route, TLS alert, ...).
    Io(String),
}

impl fmt::Display for StreamError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StreamError::Closed => f.write_str("Connection closed"),
            StreamError::Timeout => f.write_str("Timed out"),
            StreamError::Protocol(m) | StreamError::Io(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for StreamError {}

impl From<std::io::Error> for StreamError {
    fn from(e: std::io::Error) -> Self {
        StreamError::Io(e.to_string())
    }
}

#[async_trait]
pub trait ByteStream: Send {
    /// Bytes read from the transport but not consumed yet.
    fn buffer(&mut self) -> &mut ByteBuffer;
    async fn start(&mut self) -> Result<(), StreamError>;
    async fn send(&mut self, data: &[u8]) -> Result<(), StreamError>;
    /// Reads whatever the transport has next (at least 1 byte) or fails.
    async fn read_chunk(&mut self) -> Result<Vec<u8>, StreamError>;
    fn cancel(&mut self);
    /// IPv4 address the connection really went to (after `start`), when the transport can tell.
    fn remote_ipv4(&self) -> Option<String> {
        None
    }

    async fn recv(&mut self, n: usize) -> Result<Vec<u8>, StreamError> {
        while self.buffer().len() < n {
            let chunk = self.read_chunk().await?;
            self.buffer().append(&chunk);
        }
        Ok(self.buffer().take(n).expect("buffer holds n bytes"))
    }

    async fn recv_u32(&mut self) -> Result<u32, StreamError> {
        let b = self.recv(4).await?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    async fn recv_http_head(&mut self) -> Result<HttpHead, StreamError> {
        loop {
            if let Some(head) = self.buffer().take_up_to(&http_head::TERMINATOR) {
                return Ok(HttpHead::parse(&head));
            }
            if self.buffer().len() > http_head::MAX_SIZE {
                return Err(StreamError::Protocol("HTTP header too large".into()));
            }
            let chunk = self.read_chunk().await?;
            self.buffer().append(&chunk);
        }
    }
}

pub type StreamFactory = Arc<dyn Fn(&str, u16, &ProxySettings) -> Box<dyn ByteStream> + Send + Sync>;
