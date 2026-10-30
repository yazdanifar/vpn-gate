//! UDP acceleration v2 packet framing and encryption (ChaCha20-Poly1305, RFC 8439).
//! Reference: SoftEther src/Cedar/UdpAccel.c (version 2.0).

use crate::chacha_poly;
use std::fmt;

pub const IV_SIZE: usize = 12;
pub const MAC_SIZE: usize = 16;
/// Cookie + MyTick + YourTick + Size + Flag.
pub const MIN_PLAINTEXT_SIZE: usize = 4 + 8 + 8 + 2 + 1;
pub const MIN_PACKET_SIZE: usize = IV_SIZE + MIN_PLAINTEXT_SIZE + MAC_SIZE;
/// Upstream pads `rand() % MIN(room, 32)`.
pub const MAX_PADDING: usize = 31;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UdpAccelError {
    Protocol(String),
    AuthenticationFailure,
}

impl UdpAccelError {
    /// Spelling used by the golden vectors (`protocolError("...")`, `authenticationFailure`).
    pub fn name(&self) -> String {
        match self {
            UdpAccelError::Protocol(m) => format!("protocolError({m:?})"),
            UdpAccelError::AuthenticationFailure => "authenticationFailure".into(),
        }
    }
}

impl fmt::Display for UdpAccelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UdpAccelError::Protocol(m) => f.write_str(m),
            UdpAccelError::AuthenticationFailure => f.write_str("UDP packet authentication failed"),
        }
    }
}

impl std::error::Error for UdpAccelError {}

fn protocol(m: String) -> UdpAccelError {
    UdpAccelError::Protocol(m)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAccelHeader {
    pub cookie: u32,
    pub my_tick: u64,
    pub your_tick: u64,
    pub size: u16,
    /// The flag byte is upstream's COMPRESS flag (UdpAccel.c:353, :914): nonzero means the payload is zlib-compressed.
    /// A keep-alive is an empty payload with flag 0.
    pub compressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpAccelDecoded {
    pub header: UdpAccelHeader,
    pub payload: Vec<u8>,
}

/// What goes into one packet.
#[derive(Debug, Clone)]
pub struct UdpAccelFields<'a> {
    pub cookie: u32,
    pub my_tick: u64,
    pub your_tick: u64,
    pub compressed: bool,
    pub payload: &'a [u8],
    pub padding: usize,
}

/// Padding length for a packet carrying `data_size` bytes (UdpAccel.c:535-540): zero when the packet already reaches
/// `max_size`, else `random(min(max_size - current, 32))`, where `random(n)` returns a value below `n`.
pub fn padding_size(data_size: usize, max_size: usize, random: impl FnOnce(usize) -> usize) -> usize {
    let current = MIN_PACKET_SIZE + data_size;
    if current >= max_size {
        return 0;
    }
    random((max_size - current).min(32))
}

fn key_of(key32: &[u8]) -> Result<[u8; 32], UdpAccelError> {
    match key32.get(..32) {
        Some(k) => Ok(k.try_into().expect("32 bytes")),
        None => Err(protocol(format!("Invalid ChaCha20-Poly1305 key size ({} < 32)", key32.len()))),
    }
}

/// Encrypts and encodes a packet. Returns the wire bytes and the IV for the next packet. Plain mode
/// (`udp_acceleration_use_encryption == false`) has no IV, AEAD or MAC (UdpAccel.c:382,526) and never pads.
pub fn encode(
    key32: &[u8],
    iv: &[u8],
    f: &UdpAccelFields<'_>,
    plain_mode: bool,
) -> Result<(Vec<u8>, Vec<u8>), UdpAccelError> {
    let key = if plain_mode { None } else { Some(key_of(key32)?) };
    if !plain_mode && iv.len() != IV_SIZE {
        return Err(protocol(format!("Invalid IV size ({} != {IV_SIZE})", iv.len())));
    }

    let mut plain = Vec::with_capacity(MIN_PLAINTEXT_SIZE + f.payload.len() + f.padding);
    plain.extend_from_slice(&f.cookie.to_be_bytes());
    plain.extend_from_slice(&(if f.my_tick == 0 { 1 } else { f.my_tick }).to_be_bytes());
    plain.extend_from_slice(&f.your_tick.to_be_bytes());
    plain.extend_from_slice(&(f.payload.len().min(usize::from(u16::MAX)) as u16).to_be_bytes());
    plain.push(u8::from(f.compressed));
    plain.extend_from_slice(f.payload);
    if f.padding > 0 && !plain_mode {
        plain.resize(plain.len() + f.padding.min(32), 0);
    }

    let Some(key) = key else { return Ok((plain, iv.to_vec())) };
    let nonce: [u8; IV_SIZE] = iv.try_into().expect("checked length");
    let (ct, tag) = chacha_poly::seal(&key, &nonce, &plain);
    let next_iv = if ct.len() >= IV_SIZE { ct[ct.len() - IV_SIZE..].to_vec() } else { iv.to_vec() };
    let mut packet = Vec::with_capacity(IV_SIZE + ct.len() + MAC_SIZE);
    packet.extend_from_slice(iv);
    packet.extend_from_slice(&ct);
    packet.extend_from_slice(&tag);
    Ok((packet, next_iv))
}

/// Decrypts and decodes a received packet; trailing padding after the payload is ignored.
pub fn decode(packet: &[u8], key32: &[u8], plain_mode: bool) -> Result<UdpAccelDecoded, UdpAccelError> {
    let plain = if plain_mode { packet.to_vec() } else { decrypt(packet, key32)? };
    parse(&plain)
}

fn decrypt(packet: &[u8], key32: &[u8]) -> Result<Vec<u8>, UdpAccelError> {
    if packet.len() < MIN_PACKET_SIZE {
        return Err(protocol(format!("UDP packet too short ({} < {MIN_PACKET_SIZE})", packet.len())));
    }
    let key = key_of(key32)?;
    let nonce: [u8; IV_SIZE] = packet[..IV_SIZE].try_into().expect("12 bytes");
    let (ct, tag) = packet[IV_SIZE..].split_at(packet.len() - IV_SIZE - MAC_SIZE);
    let tag: [u8; MAC_SIZE] = tag.try_into().expect("16 bytes");
    chacha_poly::open(&key, &nonce, ct, &tag).ok_or(UdpAccelError::AuthenticationFailure)
}

fn parse(plain: &[u8]) -> Result<UdpAccelDecoded, UdpAccelError> {
    if plain.len() < MIN_PLAINTEXT_SIZE {
        return Err(protocol(format!("Decrypted UDP packet too short ({})", plain.len())));
    }
    let size = u16::from_be_bytes([plain[20], plain[21]]);
    let end = MIN_PLAINTEXT_SIZE + usize::from(size);
    if plain.len() < end {
        return Err(protocol(format!("Truncated UDP payload ({} < {end})", plain.len())));
    }
    let u64_at = |o: usize| u64::from_be_bytes(plain[o..o + 8].try_into().expect("8 bytes"));
    Ok(UdpAccelDecoded {
        header: UdpAccelHeader {
            cookie: u32::from_be_bytes(plain[0..4].try_into().expect("4 bytes")),
            my_tick: u64_at(4),
            your_tick: u64_at(12),
            size,
            compressed: plain[22] != 0,
        },
        payload: plain[MIN_PLAINTEXT_SIZE..end].to_vec(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vpngate_testkit::golden::{load, unhex};

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn decoded_json(d: &UdpAccelDecoded) -> Value {
        serde_json::json!({"compressed": d.header.compressed, "cookie": d.header.cookie, "myTick": d.header.my_tick,
            "payload": hex(&d.payload), "size": d.header.size, "yourTick": d.header.your_tick})
    }

    #[test]
    fn golden() {
        let v = load("udpaccel");
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            let hx = |k: &str| unhex(c[k].as_str().unwrap());
            let plain = c["plainMode"].as_bool().unwrap_or(false);
            if name == "constants" {
                assert_eq!(IV_SIZE as u64, c["ivSize"]);
                assert_eq!(MAC_SIZE as u64, c["macSize"]);
                assert_eq!(MAX_PADDING as u64, c["maxPadding"]);
                assert_eq!(MIN_PACKET_SIZE as u64, c["minPacketSize"]);
                assert_eq!(MIN_PLAINTEXT_SIZE as u64, c["minPlaintextSize"]);
            } else if name == "padding-size" {
                for k in c["cases"].as_array().unwrap() {
                    let mut asked = None;
                    let got = padding_size(
                        k["dataSize"].as_u64().unwrap() as usize,
                        k["maxSize"].as_u64().unwrap() as usize,
                        |n| {
                            asked = Some(n);
                            n - 1
                        },
                    );
                    assert_eq!(got as u64, k["result"], "{k}");
                    assert_eq!(asked.map(|n| n as u64), k["randomBound"].as_u64(), "{k}");
                }
            } else if c.get("payload").is_some() {
                let f = UdpAccelFields {
                    cookie: c["cookie"].as_u64().unwrap() as u32,
                    my_tick: c["myTick"].as_u64().unwrap(),
                    your_tick: c["yourTick"].as_u64().unwrap(),
                    compressed: c["compressed"].as_bool().unwrap(),
                    payload: &hx("payload"),
                    padding: c["padding"].as_u64().unwrap() as usize,
                };
                let r = encode(&hx("key"), &hx("iv"), &f, plain);
                match c["error"].as_str() {
                    Some(e) => assert_eq!(r.unwrap_err().name(), e, "{name}"),
                    None => {
                        let (packet, next_iv) = r.unwrap();
                        assert_eq!(packet, hx("packet"), "{name}");
                        assert_eq!(next_iv, hx("nextIV"), "{name}");
                        assert_eq!(decoded_json(&decode(&packet, &hx("key"), plain).unwrap()), c["decoded"], "{name}");
                    }
                }
            } else {
                let r = decode(&hx("packet"), &hx("key"), plain);
                match c["error"].as_str() {
                    Some(e) => assert_eq!(r.unwrap_err().name(), e, "{name}"),
                    None => assert_eq!(decoded_json(&r.unwrap()), c["decoded"], "{name}"),
                }
            }
        }
    }
}
