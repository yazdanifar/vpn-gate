//! Turns user-supplied certificate and key files into the DER blobs the daemon needs: an X.509 certificate and an RSA
//! private key as PKCS#1 `RSAPrivateKey` (mirrors `CertImport.swift` / `CertImport.cs`). Only RSA; nothing touches disk.
//! PKCS#12 (`.p12` / `.pfx`) goes through `parse_pkcs12`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rsa::pkcs1::{DecodeRsaPrivateKey, EncodeRsaPrivateKey};
use rsa::pkcs8::DecodePrivateKey;
use rsa::RsaPrivateKey;

struct Block {
    label: String,
    headers: Vec<String>,
    der: Vec<u8>,
}

fn pem_blocks(data: &[u8]) -> Vec<Block> {
    let text = String::from_utf8_lossy(data);
    let mut out = Vec::new();
    let mut current: Option<(String, Vec<String>, String)> = None;
    for line in text.lines().map(str::trim) {
        if let Some(label) = line.strip_prefix("-----BEGIN ").and_then(|l| l.strip_suffix("-----")) {
            current = Some((label.to_string(), Vec::new(), String::new()));
        } else if line.starts_with("-----END ") {
            if let Some((label, headers, body)) = current.take() {
                if let Ok(der) = STANDARD.decode(body) {
                    out.push(Block { label, headers, der });
                }
            }
        } else if let Some((_, headers, body)) = current.as_mut() {
            if line.contains(':') {
                headers.push(line.to_string());
            } else {
                body.push_str(line);
            }
        }
    }
    out
}

/// Length of the DER element at the start of `data` (tag + length + content), if well-formed.
fn der_len(data: &[u8]) -> Option<usize> {
    let first = *data.get(1)?;
    let (n, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return None;
        }
        let bytes = data.get(2..2 + count)?;
        (bytes.iter().fold(0usize, |a, &b| (a << 8) | usize::from(b)), 2 + count)
    };
    Some(header + n)
}

fn is_der_sequence(data: &[u8]) -> bool {
    data.first() == Some(&0x30) && der_len(data) == Some(data.len())
}

const NOT_CERT: &str = "That file is not an X.509 certificate (PEM or DER expected).";

pub fn parse_certificate(data: &[u8]) -> Result<Vec<u8>, String> {
    let der =
        match pem_blocks(data).into_iter().find(|b| matches!(b.label.as_str(), "CERTIFICATE" | "X509 CERTIFICATE")) {
            Some(b) => b.der,
            None => data.to_vec(),
        };
    // A certificate is SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm SEQUENCE, signature BIT STRING }.
    if !is_der_sequence(&der) {
        return Err(NOT_CERT.into());
    }
    let header = if der[1] < 0x80 { 2 } else { 2 + usize::from(der[1] & 0x7f) };
    if der.get(header) != Some(&0x30) {
        return Err(NOT_CERT.into());
    }
    Ok(der)
}

fn encrypted() -> String {
    "That private key is passphrase-protected. Decrypt it first (openssl rsa -in key.pem -out key-plain.pem).".into()
}

fn unsupported(kind: &str) -> String {
    format!("{kind} keys are not supported: SoftEther certificate login needs an RSA key.")
}

/// PKCS#1 (`RSA PRIVATE KEY`), PKCS#8 (`PRIVATE KEY`) or raw DER of either; returns PKCS#1 DER.
pub fn parse_private_key(data: &[u8]) -> Result<Vec<u8>, String> {
    let mut der = None;
    for b in pem_blocks(data) {
        match b.label.as_str() {
            "ENCRYPTED PRIVATE KEY" => return Err(encrypted()),
            "EC PRIVATE KEY" => return Err(unsupported("EC")),
            "DSA PRIVATE KEY" => return Err(unsupported("DSA")),
            "RSA PRIVATE KEY" => {
                if b.headers.iter().any(|h| h.to_lowercase().contains("encrypted")) {
                    return Err(encrypted());
                }
                der = Some(b.der);
            }
            "PRIVATE KEY" => der = Some(b.der),
            _ => {}
        }
        if der.is_some() {
            break;
        }
    }
    let der = match der {
        Some(d) => d,
        None if is_der_sequence(data) => data.to_vec(),
        None => return Err("That file is not an RSA private key (PEM or DER expected).".into()),
    };
    let key = RsaPrivateKey::from_pkcs1_der(&der).or_else(|_| RsaPrivateKey::from_pkcs8_der(&der)).map_err(|_| {
        "That file is not a usable RSA private key (EC and passphrase-protected keys are not supported).".to_string()
    })?;
    key.to_pkcs1_der().map(|d| d.as_bytes().to_vec()).map_err(|e| e.to_string())
}

/// A PKCS#12 bundle: the first private key with its leaf certificate, as `(certificate DER, PKCS#1 key DER)`.
pub fn parse_pkcs12(data: &[u8], passphrase: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    use p12_keystore::{KeyStore, KeyStoreEntry, Pkcs12ImportPolicy};
    let store = KeyStore::from_pkcs12(data, passphrase, Pkcs12ImportPolicy::Strict)
        .map_err(|_| "That file could not be opened as PKCS#12. Check the passphrase.".to_string())?;
    for (_, entry) in store.entries() {
        if let KeyStoreEntry::PrivateKeyChain(chain) = entry {
            let Some(leaf) = chain.certs().first() else { continue };
            let key = parse_private_key(chain.key().as_der())?;
            return Ok((leaf.as_der().to_vec(), key));
        }
    }
    Err("That PKCS#12 file holds no private key with a certificate.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem(label: &str, der: &[u8]) -> Vec<u8> {
        let b64 = STANDARD.encode(der);
        let lines: Vec<&str> = b64.as_bytes().chunks(64).map(|c| std::str::from_utf8(c).unwrap()).collect();
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----\n", lines.join("\n")).into_bytes()
    }

    /// SEQUENCE { SEQUENCE { INTEGER 1 }, SEQUENCE {}, BIT STRING 00 }: certificate-shaped.
    fn fake_cert() -> Vec<u8> {
        vec![0x30, 0x0b, 0x30, 0x03, 0x02, 0x01, 0x01, 0x30, 0x00, 0x03, 0x02, 0x00, 0x00]
    }

    #[test]
    fn certificates() {
        let der = fake_cert();
        assert_eq!(parse_certificate(&der).unwrap(), der, "raw DER");
        assert_eq!(parse_certificate(&pem("CERTIFICATE", &der)).unwrap(), der, "PEM");
        assert!(parse_certificate(b"hello").is_err());
        assert!(parse_certificate(&der[..5]).is_err(), "truncated");
    }

    #[test]
    fn keys_reject_what_the_swift_app_rejects() {
        assert!(parse_private_key(&pem("ENCRYPTED PRIVATE KEY", b"x")).unwrap_err().contains("passphrase"));
        assert!(parse_private_key(&pem("EC PRIVATE KEY", b"x")).unwrap_err().starts_with("EC"));
        let legacy = b"-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----\n";
        assert!(parse_private_key(legacy).unwrap_err().contains("passphrase"));
        assert!(parse_private_key(b"nope").is_err());
        assert!(parse_private_key(&fake_cert()).is_err(), "valid DER but no key");
    }

    #[test]
    fn pkcs8_and_pkcs1_both_give_pkcs1() {
        use rsa::pkcs8::EncodePrivateKey;
        let mut rng = rsa::rand_core::OsRng;
        let key = RsaPrivateKey::new(&mut rng, 1024).unwrap();
        let pkcs1 = key.to_pkcs1_der().unwrap().as_bytes().to_vec();
        let pkcs8 = key.to_pkcs8_der().unwrap().as_bytes().to_vec();
        assert_eq!(parse_private_key(&pem("RSA PRIVATE KEY", &pkcs1)).unwrap(), pkcs1);
        assert_eq!(parse_private_key(&pem("PRIVATE KEY", &pkcs8)).unwrap(), pkcs1);
        assert_eq!(parse_private_key(&pkcs8).unwrap(), pkcs1, "raw DER");
    }

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("testdata").join(name)).unwrap()
    }

    #[test]
    fn pkcs12_gives_the_same_identity_as_the_pem_files() {
        let cert = parse_certificate(&fixture("cert.pem")).unwrap();
        let key = parse_private_key(&fixture("key.pem")).unwrap();
        for name in ["modern.p12", "legacy.p12"] {
            let (c, k) = parse_pkcs12(&fixture(name), "secret").unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!((c, k), (cert.clone(), key.clone()), "{name}");
        }
    }

    #[test]
    fn pkcs12_errors_are_explained() {
        assert!(parse_pkcs12(&fixture("modern.p12"), "wrong").unwrap_err().contains("passphrase"));
        assert!(parse_pkcs12(b"not a p12", "").is_err());
    }
}
