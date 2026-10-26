//! Server certificate pin: SHA-1 (40 hex) or SHA-256 (64 hex) fingerprint of the DER leaf certificate, as shown by
//! SoftEther / openssl (colons and spaces allowed, any case).

use sha1::{Digest, Sha1};
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CertPin {
    digest: Vec<u8>,
}

impl CertPin {
    pub fn parse(text: &str) -> Option<CertPin> {
        let chars: Vec<char> = text.chars().filter(|c| !c.is_whitespace() && *c != ':').collect();
        if !(chars.len() == 40 || chars.len() == 64) || !chars.iter().all(char::is_ascii_hexdigit) {
            return None;
        }
        let digest =
            chars.chunks(2).map(|p| (p[0].to_digit(16).unwrap() * 16 + p[1].to_digit(16).unwrap()) as u8).collect();
        Some(CertPin { digest })
    }

    pub fn digest(&self) -> &[u8] {
        &self.digest
    }

    pub fn matches(&self, cert_der: &[u8]) -> bool {
        let actual: Vec<u8> =
            if self.digest.len() == 20 { Sha1::digest(cert_der).to_vec() } else { Sha256::digest(cert_der).to_vec() };
        actual == self.digest
    }
}

/// What the TLS verify step should do for a given configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerCertPolicy {
    /// VPN Gate relays: self-signed, unverified.
    AcceptAny,
    Pinned(CertPin),
    /// A fingerprint is configured but unparseable: fail closed.
    InvalidPin,
    /// "Verify server certificate" without a pin.
    SystemTrust,
}

impl ServerCertPolicy {
    pub fn new(check_server_cert: bool, fingerprint: Option<&str>) -> Self {
        let fp = fingerprint.unwrap_or("").trim_matches(|c: char| {
            c.is_whitespace() && !matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{85}' | '\u{2028}' | '\u{2029}')
        });
        if !fp.is_empty() {
            CertPin::parse(fp).map_or(ServerCertPolicy::InvalidPin, ServerCertPolicy::Pinned)
        } else if check_server_cert {
            ServerCertPolicy::SystemTrust
        } else {
            ServerCertPolicy::AcceptAny
        }
    }

    /// `None` when the presented leaf is acceptable, otherwise the reason it is not.
    pub fn rejection(&self, leaf_der: Option<&[u8]>) -> Option<&'static str> {
        match self {
            ServerCertPolicy::AcceptAny | ServerCertPolicy::SystemTrust => None,
            ServerCertPolicy::InvalidPin => {
                Some("Server certificate fingerprint is not a valid SHA-1/SHA-256 hex string")
            }
            ServerCertPolicy::Pinned(pin) => match leaf_der {
                None => Some("Server presented no certificate to match the pinned fingerprint"),
                Some(der) if pin.matches(der) => None,
                Some(_) => Some("Server certificate does not match the pinned fingerprint"),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::{load, unhex};

    fn group<'a>(v: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        v["cases"].as_array().unwrap().iter().find(|g| g["name"] == name).unwrap()
    }

    #[test]
    fn golden_pins() {
        let v = load("certpin");
        let cert = unhex(group(&v, "cert")["derHex"].as_str().unwrap());
        let mut other = cert.clone();
        other[0] ^= 1;
        for c in group(&v, "pin-parse")["cases"].as_array().unwrap() {
            let input = c["input"].as_str().unwrap();
            let pin = CertPin::parse(input);
            match c["digest"].as_str() {
                None => assert!(pin.is_none(), "{input:?}"),
                Some(d) => {
                    let pin = pin.unwrap_or_else(|| panic!("{input:?}"));
                    assert_eq!(pin.digest(), unhex(d), "{input:?}");
                    assert_eq!(pin.matches(&cert), c["matchesCert"].as_bool().unwrap(), "{input:?}");
                    assert_eq!(pin.matches(&other), c["matchesOther"].as_bool().unwrap(), "{input:?}");
                }
            }
        }
    }

    #[test]
    fn golden_cert_hashes_agree() {
        let v = load("certpin");
        let c = group(&v, "cert");
        let der = unhex(c["derHex"].as_str().unwrap());
        assert_eq!(Sha1::digest(&der).to_vec(), unhex(c["sha1"].as_str().unwrap()));
        assert_eq!(Sha256::digest(&der).to_vec(), unhex(c["sha256"].as_str().unwrap()));
    }

    #[test]
    fn golden_policy() {
        let v = load("certpin");
        let cert = unhex(group(&v, "cert")["derHex"].as_str().unwrap());
        let mut other = cert.clone();
        other[0] ^= 1;
        for c in group(&v, "policy")["cases"].as_array().unwrap() {
            let fp = c["fingerprint"].as_str();
            let p = ServerCertPolicy::new(c["checkServerCert"].as_bool().unwrap(), fp);
            let kind = match p {
                ServerCertPolicy::AcceptAny => "acceptAny",
                ServerCertPolicy::Pinned(_) => "pinned",
                ServerCertPolicy::InvalidPin => "invalidPin",
                ServerCertPolicy::SystemTrust => "systemTrust",
            };
            assert_eq!(kind, c["policy"].as_str().unwrap(), "{fp:?}");
            // The vectors' "good" cert is the one the pin was derived from, except for the all-zero style pins.
            assert_eq!(p.rejection(Some(&cert)), c["rejectGood"].as_str(), "{fp:?}");
            assert_eq!(p.rejection(None), c["rejectNone"].as_str(), "{fp:?}");
            assert_eq!(p.rejection(Some(&other)), c["rejectOther"].as_str(), "{fp:?}");
        }
    }
}
