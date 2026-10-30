//! Certificate authentication (authtype 3): the server sends a 20-byte random challenge and expects an RSA
//! PKCS#1 v1.5 / SHA-1 signature over it.

use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::RsaPrivateKey;
use sha1::Sha1;

use crate::stream::StreamError;

pub const MAX_CERT_BYTES: usize = 16 * 1024;
pub const MAX_KEY_BYTES: usize = 16 * 1024;

/// Signs `challenge` with the RSA key (PKCS#1 or PKCS#8 DER). Errors never include key material.
pub fn sign(challenge: &[u8], private_key_der: &[u8]) -> Result<Vec<u8>, StreamError> {
    if private_key_der.len() > MAX_KEY_BYTES {
        return Err(StreamError::Protocol("Private key too large".into()));
    }
    let pkcs1 = unwrap_pkcs8(private_key_der).unwrap_or(private_key_der);
    let key = RsaPrivateKey::from_pkcs1_der(pkcs1).map_err(|_| {
        StreamError::Protocol("Private key is not a valid RSA key (PKCS#1 or PKCS#8 DER expected)".into())
    })?;
    let sig = SigningKey::<Sha1>::new(key)
        .try_sign(challenge)
        .map_err(|_| StreamError::Protocol("Signing the server challenge failed".into()))?;
    Ok(sig.to_vec())
}

/// PKCS#8 PrivateKeyInfo { INTEGER 0, SEQUENCE alg, OCTET STRING key } -> the inner PKCS#1 key; `None` if `der` is not
/// that shape.
pub fn unwrap_pkcs8(der: &[u8]) -> Option<&[u8]> {
    let mut pos = 0usize;
    let header = |expect: u8, pos: &mut usize| -> Option<(usize, usize)> {
        if *pos + 2 > der.len() || der[*pos] != expect {
            return None;
        }
        let mut len = der[*pos + 1] as usize;
        *pos += 2;
        if len & 0x80 != 0 {
            let n = len & 0x7f;
            if !(1..=3).contains(&n) || *pos + n > der.len() {
                return None;
            }
            len = 0;
            for _ in 0..n {
                len = len << 8 | der[*pos] as usize;
                *pos += 1;
            }
        }
        if *pos + len > der.len() {
            return None;
        }
        Some((*pos, len))
    };
    header(0x30, &mut pos)?;
    let (vs, vl) = header(0x02, &mut pos)?;
    if vl != 1 || der[vs] != 0 {
        return None;
    }
    pos = vs + vl;
    let (a, al) = header(0x30, &mut pos)?;
    pos = a + al;
    let (ks, kl) = header(0x04, &mut pos)?;
    Some(&der[ks..ks + kl])
}
