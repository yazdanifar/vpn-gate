//! Wire format after login (SoftEther Connection.c): `u32 n` then n x (`u32 size` + frame), or the keep-alive marker
//! `0xFFFFFFFF`, `u32 len`, len junk bytes. Big-endian.

use crate::byte_buffer::ByteBuffer;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use std::fmt;
use std::io::{Read, Write};

pub const MAX_BLOCK: usize = 3200;
pub const MAX_BLOCKS_PER_BATCH: usize = 4095;
pub const KEEP_ALIVE_MAGIC: u32 = 0xFFFF_FFFF;
pub const MAX_KEEP_ALIVE: usize = 4095;
/// Default output limit of [`uncompress_frame`].
pub const DEFAULT_MAX_FRAME: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataPhaseItem {
    Frame(Vec<u8>),
    KeepAlive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataPhaseError {
    OversizedBlock(usize),
    BadBlockCount(usize),
    BadKeepAlive(usize),
    DecompressionFailed,
    CompressionFailed,
}

impl DataPhaseError {
    /// Swift's case spelling (`badKeepAlive(4096)`), as recorded in the golden vectors.
    pub fn name(self) -> String {
        match self {
            DataPhaseError::OversizedBlock(n) => format!("oversizedBlock({n})"),
            DataPhaseError::BadBlockCount(n) => format!("badBlockCount({n})"),
            DataPhaseError::BadKeepAlive(n) => format!("badKeepAlive({n})"),
            DataPhaseError::DecompressionFailed => "decompressionFailed".into(),
            DataPhaseError::CompressionFailed => "compressionFailed".into(),
        }
    }
}

impl fmt::Display for DataPhaseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataPhaseError::OversizedBlock(n) => write!(f, "Oversized block ({n} bytes)"),
            DataPhaseError::BadBlockCount(n) => write!(f, "Bad block count ({n})"),
            DataPhaseError::BadKeepAlive(n) => write!(f, "Bad keep-alive length ({n})"),
            DataPhaseError::DecompressionFailed => f.write_str("Zlib block decompression failed"),
            DataPhaseError::CompressionFailed => f.write_str("Zlib block compression failed"),
        }
    }
}

impl std::error::Error for DataPhaseError {}

/// Compresses one Ethernet frame as a zlib stream. The bytes differ from Apple zlib's output; they inflate the same.
pub fn compress_frame(frame: &[u8]) -> Result<Vec<u8>, DataPhaseError> {
    let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
    enc.write_all(frame).map_err(|_| DataPhaseError::CompressionFailed)?;
    enc.finish().map_err(|_| DataPhaseError::CompressionFailed)
}

/// Inflates a zlib-compressed frame; more than `max_len` bytes of output is a failure.
pub fn uncompress_frame(data: &[u8], max_len: usize) -> Result<Vec<u8>, DataPhaseError> {
    let mut out = Vec::new();
    ZlibDecoder::new(data)
        .take(max_len as u64 + 1)
        .read_to_end(&mut out)
        .map_err(|_| DataPhaseError::DecompressionFailed)?;
    if out.len() > max_len {
        return Err(DataPhaseError::DecompressionFailed);
    }
    Ok(out)
}

pub fn encode<F: AsRef<[u8]>>(frames: &[F]) -> Vec<u8> {
    let mut out = (frames.len() as u32).to_be_bytes().to_vec();
    for f in frames {
        let f = f.as_ref();
        out.extend_from_slice(&(f.len() as u32).to_be_bytes());
        out.extend_from_slice(f);
    }
    out
}

pub fn encode_compressed<F: AsRef<[u8]>>(frames: &[F], use_compress: bool) -> Result<Vec<u8>, DataPhaseError> {
    if !use_compress {
        return Ok(encode(frames));
    }
    let blocks = frames.iter().map(|f| compress_frame(f.as_ref())).collect::<Result<Vec<_>, _>>()?;
    Ok(encode(&blocks))
}

pub fn encode_keep_alive(junk: &[u8]) -> Vec<u8> {
    let mut out = KEEP_ALIVE_MAGIC.to_be_bytes().to_vec();
    out.extend_from_slice(&(junk.len() as u32).to_be_bytes());
    out.extend_from_slice(junk);
    out
}

#[derive(Debug, Clone, Copy)]
enum State {
    Header,
    KeepAliveLength,
    KeepAliveBody(usize),
    BlockSize { remaining: usize },
    BlockBody { size: usize, remaining: usize },
}

/// Incremental decoder: feed it whatever chunks the socket returns.
#[derive(Debug)]
pub struct DataPhaseDecoder {
    buf: ByteBuffer,
    state: State,
    pub use_compress: bool,
}

impl DataPhaseDecoder {
    pub fn new(use_compress: bool) -> Self {
        DataPhaseDecoder { buf: ByteBuffer::new(), state: State::Header, use_compress }
    }

    fn u32(&mut self) -> Option<u32> {
        let b = self.buf.take(4)?;
        Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    /// Decodes what is complete. On an error the items decoded earlier in this call are dropped, like Swift's `throws`.
    pub fn feed(&mut self, bytes: &[u8]) -> Result<Vec<DataPhaseItem>, DataPhaseError> {
        self.buf.append(bytes);
        let mut out = Vec::new();
        loop {
            match self.state {
                State::Header => {
                    let Some(n) = self.u32() else { return Ok(out) };
                    if n == KEEP_ALIVE_MAGIC {
                        self.state = State::KeepAliveLength;
                    } else if n == 0 {
                        continue;
                    } else if n as usize > MAX_BLOCKS_PER_BATCH {
                        return Err(DataPhaseError::BadBlockCount(n as usize));
                    } else {
                        self.state = State::BlockSize { remaining: n as usize };
                    }
                }
                State::KeepAliveLength => {
                    let Some(n) = self.u32() else { return Ok(out) };
                    if n as usize > MAX_KEEP_ALIVE {
                        return Err(DataPhaseError::BadKeepAlive(n as usize));
                    }
                    self.state = State::KeepAliveBody(n as usize);
                }
                State::KeepAliveBody(n) => {
                    if self.buf.take(n).is_none() {
                        return Ok(out);
                    }
                    out.push(DataPhaseItem::KeepAlive);
                    self.state = State::Header;
                }
                State::BlockSize { remaining } => {
                    let Some(n) = self.u32() else { return Ok(out) };
                    if n as usize > MAX_BLOCK {
                        return Err(DataPhaseError::OversizedBlock(n as usize));
                    }
                    self.state = State::BlockBody { size: n as usize, remaining };
                }
                State::BlockBody { size, remaining } => {
                    let Some(raw) = self.buf.take(size) else { return Ok(out) };
                    let frame = if self.use_compress { uncompress_frame(&raw, DEFAULT_MAX_FRAME)? } else { raw };
                    out.push(DataPhaseItem::Frame(frame));
                    self.state =
                        if remaining > 1 { State::BlockSize { remaining: remaining - 1 } } else { State::Header };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::{load, unhex};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn golden() {
        let v = load("dataphase");
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let hx = |k: &str| unhex(c[k].as_str().unwrap());
            if name.starts_with("encode-") {
                let frames: Vec<Vec<u8>> =
                    c["frames"].as_array().unwrap().iter().map(|f| unhex(f.as_str().unwrap())).collect();
                assert_eq!(encode(&frames), hx("hex"), "{name}");
            } else if name == "keepalive-encode" {
                assert_eq!(encode_keep_alive(&hx("junk")), hx("hex"), "{name}");
            } else if name.starts_with("compress-") {
                // Not byte-exact against Apple zlib: check the round trip and that Swift's own bytes still inflate.
                let frame = hx("frame");
                assert_eq!(
                    uncompress_frame(&compress_frame(&frame).unwrap(), DEFAULT_MAX_FRAME).unwrap(),
                    frame,
                    "{name}"
                );
                assert_eq!(
                    uncompress_frame(&hx("swiftCompressed"), DEFAULT_MAX_FRAME).unwrap(),
                    hx("roundTrip"),
                    "{name}"
                );
            } else if name.starts_with("uncompress-") {
                let r = uncompress_frame(&hx("input"), c["maxLen"].as_u64().unwrap() as usize);
                match c["error"].as_str() {
                    Some(e) => assert_eq!(r.unwrap_err().name(), e, "{name}"),
                    None => assert_eq!(r.unwrap(), hx("output"), "{name}"),
                }
            } else if name.starts_with("decode-") {
                let mut d = DataPhaseDecoder::new(c["useCompress"].as_bool().unwrap());
                let chunks = c["chunks"].as_array().unwrap();
                // The exporter records one step per chunk and stops at the first error.
                for (i, step) in c["steps"].as_array().unwrap().iter().enumerate() {
                    let r = d.feed(&unhex(chunks[i].as_str().unwrap()));
                    match step["error"].as_str() {
                        Some(e) => assert_eq!(r.unwrap_err().name(), e, "{name} chunk {i}"),
                        None => {
                            let want: Vec<DataPhaseItem> = step["items"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .map(|it| match it["frame"].as_str() {
                                    Some(f) => DataPhaseItem::Frame(unhex(f)),
                                    None => DataPhaseItem::KeepAlive,
                                })
                                .collect();
                            assert_eq!(r.unwrap(), want, "{name} chunk {i}");
                        }
                    }
                }
            } else {
                panic!("unhandled dataphase vector {name}");
            }
        }
    }

    #[test]
    fn compress_round_trip_and_limits() {
        let frame: Vec<u8> = (0..=255u8).cycle().take(1500).collect();
        let z = compress_frame(&frame).unwrap();
        assert_eq!(uncompress_frame(&z, 1500).unwrap(), frame);
        assert_eq!(uncompress_frame(&z, 1499), Err(DataPhaseError::DecompressionFailed));
        let batch = encode_compressed(&[frame.clone(), vec![]], true).unwrap();
        let mut d = DataPhaseDecoder::new(true);
        assert_eq!(d.feed(&batch).unwrap(), vec![DataPhaseItem::Frame(frame), DataPhaseItem::Frame(vec![])]);
        assert_eq!(hex(&encode_compressed(&[[1u8]], false).unwrap()), "000000010000000101");
    }
}
