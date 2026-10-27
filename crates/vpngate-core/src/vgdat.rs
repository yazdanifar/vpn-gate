//! VPNGate.dat: header, RC4-encrypted outer Pack signed with the VPN Gate API certificate, optionally zlib-compressed
//! inner Pack. `parse_inner_servers` turns the inner Pack into `VpnServer`s.

use crate::pack::{Pack, PackValue};
use crate::server_list::VpnServer;
use crate::{rc4::Rc4, sha0};
use base64::Engine;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fmt;
use std::io::Read;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VgDatError {
    InvalidHeader,
    Truncated,
    SignatureVerificationFailed,
    DecompressionFailed,
    InvalidPack,
}

impl VgDatError {
    /// The case name used by the golden vectors (and the Swift enum).
    pub fn name(self) -> &'static str {
        match self {
            VgDatError::InvalidHeader => "invalidHeader",
            VgDatError::Truncated => "truncated",
            VgDatError::SignatureVerificationFailed => "signatureVerificationFailed",
            VgDatError::DecompressionFailed => "decompressionFailed",
            VgDatError::InvalidPack => "invalidPack",
        }
    }
}

impl fmt::Display for VgDatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            VgDatError::InvalidHeader => "Invalid VPNGate.dat header",
            VgDatError::Truncated => "Truncated VPNGate.dat file",
            VgDatError::SignatureVerificationFailed => "VPNGate.dat RSA signature verification failed",
            VgDatError::DecompressionFailed => "Failed to decompress VPNGate.dat inner payload",
            VgDatError::InvalidPack => "Invalid Pack format in VPNGate.dat",
        })
    }
}

impl std::error::Error for VgDatError {}

/// 36 hours in milliseconds (VG_ALLOW_TIME_DIFF from client_exe.c / VG.c).
pub const ALLOW_TIME_DIFF_MS: u64 = 36 * 3600 * 1000;

/// Largest inflated `data` accepted (the real list is ~75 KB).
pub const MAX_INFLATED_SIZE: usize = 16 * 1024 * 1024;

const HEADER_LEN: usize = 0xF0;
const BODY_OFFSET: usize = 0x104;

/// RSA-1024 public certificate (CN=vpngate_api_cert, O=SoftEther Corporation) that signs VPNGate.dat.
pub const API_CERTIFICATE_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIB/zCCAWgCAQAwDQYJKoZIhvcNAQEFBQAwSDEZMBcGA1UEAxQQdnBuZ2F0ZV9h
cGlfY2VydDEeMBwGA1UEChMVU29mdEV0aGVyIENvcnBvcmF0aW9uMQswCQYDVQQG
EwJKUDAeFw0xMzAxMTUwNjM4MTVaFw0zNzAxMDkwNjM4MTVaMEgxGTAXBgNVBAMU
EHZwbmdhdGVfYXBpX2NlcnQxHjAcBgNVBAoTFVNvZnRFdGhlciBDb3Jwb3JhdGlv
bjELMAkGA1UEBhMCSlAwgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBANKvJddX
AO7XIt+ZXBvzH10R/nlFV9RRG7nW0Kge6/FVVlfgYuninG/s9RF6rloWh4v7sotp
GUKFJ7jD76NAzkemvsNpcQfkddxZD/Nv6k3ZoWK1Z2Wm77UkhBiI34/Ez9uLPgiJ
rc10hwkeixpO2V5ewi0RvWEayq79xGS1jLpnAgMBAAEwDQYJKoZIhvcNAQEFBQAD
gYEAMKQNaIw5eusl1sOZ6BlcqVCXRAFG+/rF9ZFUHQzdu3hO2k1F08naMpoO9PIE
d8yEiIuOzeylfCReS34JclCWOz/IVVgk9gYNDKeGZpM17ZuXes1EkG4SrCDqUnaN
/gl7JR92FEfGHsyteExq/09Q7b1BfHCHSmXfKhoOBD/TlV4=
-----END CERTIFICATE-----
";

/// Splits one DER element off the front of `buf`: (whole element, content, rest).
fn der_element(buf: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let first = *buf.get(1)?;
    let (len, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7F);
        if n == 0 || n > 4 {
            return None;
        }
        let len = buf.get(2..2 + n)?.iter().fold(0usize, |acc, b| acc << 8 | usize::from(*b));
        (len, 2 + n)
    };
    let end = header.checked_add(len)?;
    Some((buf.get(..end)?, buf.get(header..end)?, buf.get(end..)?))
}

/// The SubjectPublicKeyInfo of an X.509 certificate: the sixth field of TBSCertificate after the optional version
/// (serial, signature algorithm, issuer, validity, subject), so skip those and return the next element whole.
fn spki_of_certificate(cert_der: &[u8]) -> Option<&[u8]> {
    let (_, cert, _) = der_element(cert_der)?;
    let (_, mut tbs, _) = der_element(cert)?;
    if *tbs.first()? == 0xA0 {
        tbs = der_element(tbs)?.2;
    }
    for _ in 0..5 {
        tbs = der_element(tbs)?.2;
    }
    der_element(tbs).map(|(whole, _, _)| whole)
}

fn api_key() -> Option<RsaPublicKey> {
    let b64: String = API_CERTIFICATE_PEM.lines().filter(|l| !l.starts_with("-----")).collect();
    let der = base64::engine::general_purpose::STANDARD.decode(b64).ok()?;
    RsaPublicKey::from_public_key_der(spki_of_certificate(&der)?).ok()
}

/// The client's named tunables (client_exe.c FUN_0061b3f0 / FUN_0061b380 / FUN_0061b430).
/// A verified VPNGate.dat may carry a `DynList`: an unencrypted nested Pack of name -> int64 that overrides the defaults
/// compiled into the client. A lookup returns the default when the name is absent or its value is 0, otherwise the
/// value clamped to [default / 5, default * 50]. Names compare case-insensitively.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VgTunables {
    values: HashMap<String, u64>,
}

impl VgTunables {
    /// Elements that are not int64 read as 0 in the original (= use the default), so they are skipped.
    /// An unparseable blob gives an empty set.
    pub fn from_dyn_list(blob: &[u8]) -> VgTunables {
        let mut values = HashMap::new();
        if let Ok(pack) = Pack::parse(blob) {
            for e in pack.elements() {
                if let Some(PackValue::Int64(v)) = e.values.first() {
                    values.insert(e.name.to_lowercase(), *v);
                }
            }
        }
        VgTunables { values }
    }

    /// The original keeps one process-wide table and only overwrites names a newer list mentions.
    pub fn merge(&mut self, newer: &VgTunables) {
        for (k, v) in &newer.values {
            self.values.insert(k.clone(), *v);
        }
    }

    pub fn values(&self) -> &HashMap<String, u64> {
        &self.values
    }

    pub fn value(&self, name: &str, default: u64) -> u64 {
        match self.values.get(&name.to_lowercase()) {
            Some(&v) if v != 0 => v.max(default / 5).min(default.saturating_mul(50)),
            _ => default,
        }
    }

    /// Milliseconds tunable as seconds.
    pub fn seconds(&self, name: &str, default_ms: u64) -> f64 {
        self.value(name, default_ms) as f64 / 1000.0
    }
}

#[derive(Debug, Clone)]
pub struct VgDatFile {
    pub header_text: String,
    pub soap_url: String,
    pub timestamp_ms: u64,
    pub inner: Pack,
    pub is_fresh: bool,
    pub tunables: VgTunables,
}

fn within(now_ms: u64, ts_ms: u64, allowed_ms: u64) -> bool {
    now_ms.abs_diff(ts_ms) <= allowed_ms
}

/// Parses and always verifies a VPNGate.dat. `now_ms` (Unix milliseconds) is a parameter so tests can pin freshness.
pub fn parse(data: &[u8], now_ms: u64) -> Result<VgDatFile, VgDatError> {
    if data.len() <= BODY_OFFSET {
        return Err(VgDatError::Truncated);
    }
    let header_text = String::from_utf8_lossy(&data[..HEADER_LEN]).into_owned();
    if !header_text.starts_with("[VPNGate Data File]") {
        return Err(VgDatError::InvalidHeader);
    }

    let seed = &data[HEADER_LEN..BODY_OFFSET];
    let key = Sha1::digest(seed);
    let body = Rc4::cipher(&key, &data[BODY_OFFSET..]);
    let outer = Pack::parse(&body).map_err(|_| VgDatError::InvalidPack)?;

    let (Some(outer_data), Some(data_size), Some(sign), Some(ts)) = (
        outer.data("data"),
        outer.int("data_size"),
        outer.data("sign"),
        outer.data("timestamp").filter(|t| t.len() == 8),
    ) else {
        return Err(VgDatError::InvalidPack);
    };
    let soap_url = outer
        .str("soap_url")
        .map(str::to_string)
        .or_else(|| outer.data("soap_url").map(|d| String::from_utf8_lossy(d).into_owned()))
        .unwrap_or_default();
    let compressed = outer.int("compressed").unwrap_or(0) != 0;
    let ts_ms = u64::from_be_bytes(ts.try_into().expect("checked to be 8 bytes"));

    // RSA PKCS#1 v1.5 over SHA-1 of: timestamp || data || data_size (big endian).
    let mut signed = Vec::with_capacity(ts.len() + outer_data.len() + 4);
    signed.extend_from_slice(ts);
    signed.extend_from_slice(outer_data);
    signed.extend_from_slice(&data_size.to_be_bytes());
    let valid = api_key().is_some_and(|k| {
        Signature::try_from(sign).is_ok_and(|s| VerifyingKey::<Sha1>::new(k).verify(&signed, &s).is_ok())
    });
    if !valid {
        return Err(VgDatError::SignatureVerificationFailed);
    }

    let inflated;
    let inner_bytes = if compressed {
        inflated = decompress(outer_data, data_size as usize)?;
        &inflated[..]
    } else {
        outer_data
    };
    let inner = Pack::parse(inner_bytes).map_err(|_| VgDatError::InvalidPack)?;
    let tunables = inner.data("DynList").map(VgTunables::from_dyn_list).unwrap_or_default();

    Ok(VgDatFile {
        header_text,
        soap_url,
        timestamp_ms: ts_ms,
        is_fresh: within(now_ms, ts_ms, ALLOW_TIME_DIFF_MS),
        inner,
        tunables,
    })
}

/// The server records of a verified list's inner Pack (`VGDat.parseInnerServers`). `NumHosts` is never trusted past the
/// length of the `IP` array, and rows without an IP are skipped.
pub fn parse_inner_servers(inner: &Pack) -> Vec<VpnServer> {
    let Some(num_hosts) = inner.int("NumHosts") else { return Vec::new() };
    let ips = inner.strs("IP");
    let count = (num_hosts as usize).min(ips.len());
    let fqdns = inner.strs("Fqdn");
    let host_names = inner.strs("HostName");
    let country_shorts = inner.strs("CountryShort");
    let country_fulls = inner.strs("CountryFull");
    let scores = inner.int64s("Score");
    let pings = inner.ints("PingToJapan");
    let speeds = inner.int64s("SpeedToJapan");
    let num_clients = inner.ints("NumClients");
    let uptimes = inner.int64s("Uptime");
    let ssl_ports = inner.strs("SslPorts");
    let udp_ports = inner.ints("UdpPort");
    let openvpn_ports = inner.strs("OpenVpnUdpPorts");
    let l2tps = inner.ints("L2TP");
    let oss = inner.ints("Os");
    let softs = inner.strs("Soft");
    let builds = inner.ints("Build");
    let owners = inner.strs("Owner");
    let abuses = inner.strs("Abuse");
    let messages = inner.strs("Message");
    let num_logins = inner.int64s("NumLogin");
    let logs = inner.ints("Log");
    let log_permanents = inner.ints("LogPermanent");
    let names = inner.strs("Name");
    let pings_google = inner.ints("PingToGoogle");
    let send_sizes = inner.int64s("SendSize");
    let recv_sizes = inner.int64s("RecvSize");
    let kernel_nats = inner.ints("IsKernelModeNAT");

    let clamp = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    let ports_of = |s: &str| -> Vec<u16> { s.split(' ').filter_map(|p| p.parse().ok()).collect() };
    let mut servers = Vec::with_capacity(count);
    for (i, &ip) in ips.iter().enumerate().take(count) {
        if ip.is_empty() {
            continue;
        }
        let fqdn = fqdns.get(i).copied().unwrap_or_default();
        let host_name = host_names.get(i).copied().filter(|h| !h.is_empty()).unwrap_or(fqdn);
        let ssl = ports_of(ssl_ports.get(i).copied().unwrap_or_default());
        let udp_port = udp_ports.get(i).filter(|&&p| p > 0).and_then(|&p| u16::try_from(p).ok());
        let send_size = send_sizes.get(i).copied().unwrap_or(0);
        let recv_size = recv_sizes.get(i).copied().unwrap_or(0);
        let permanent = log_permanents.get(i).is_some_and(|&v| v != 0);
        let two_weeks = logs.get(i).is_some_and(|&v| v != 0);
        let first_port = VpnServer::port_priority(&ssl)
            .first()
            .map(|&p| i64::from(p))
            .unwrap_or_else(|| udp_port.map_or(443, i64::from));
        let owner = owners.get(i).map(|s| s.to_string());
        let num_login = num_logins.get(i).map(|&v| clamp(v));
        let mut s = VpnServer::new(host_name, ip);
        s.score = scores.get(i).map_or(0, |&v| clamp(v));
        s.ping = pings.get(i).map_or(0, |&v| i64::from(v));
        s.speed = speeds.get(i).map_or(0, |&v| clamp(v));
        s.country_long = country_fulls.get(i).copied().unwrap_or_default().to_string();
        s.country_short = country_shorts.get(i).copied().unwrap_or_default().to_string();
        s.sessions = num_clients.get(i).map_or(0, |&v| i64::from(v));
        s.uptime_ms = uptimes.get(i).map_or(0, |&v| clamp(v));
        s.total_users = num_login.unwrap_or(0);
        s.total_traffic = clamp(send_size.saturating_add(recv_size));
        s.log_type = if permanent {
            "Permanent"
        } else if two_weeks {
            "2 Weeks"
        } else {
            "No Log"
        }
        .into();
        s.operator_name = owner.clone().unwrap_or_default();
        s.message = messages.get(i).copied().unwrap_or_default().to_string();
        s.listed_port = first_port;
        s.listed_proto = "tcp".into();
        s.fqdn = fqdn.to_string();
        s.ssl_ports = ssl;
        s.udp_port = udp_port;
        s.open_vpn_udp_ports = ports_of(openvpn_ports.get(i).copied().unwrap_or_default());
        s.l2tp = l2tps.get(i).is_some_and(|&v| v != 0);
        s.os = oss.get(i).map(|v| v.to_string());
        s.soft = softs.get(i).map(|s| s.to_string());
        s.build = builds.get(i).map(|&v| i64::from(v));
        s.owner = owner;
        s.abuse = abuses.get(i).map(|s| s.to_string());
        s.num_login = num_login;
        s.no_log = !permanent && !two_weeks;
        s.log_permanent = permanent;
        s.name = names.get(i).map(|s| s.to_string());
        s.ping_to_google = pings_google.get(i).map_or(0, |&v| i64::from(v));
        s.send_size = send_size;
        s.recv_size = recv_size;
        s.is_kernel_mode_nat = kernel_nats.get(i).is_some_and(|&v| v != 0);
        servers.push(s);
    }
    servers
}

/// Inflates a zlib stream (2-byte header, raw deflate, big-endian Adler-32) to exactly `expected_size` bytes.
/// A longer or shorter stream, a bad header or a bad Adler-32 is rejected.
pub fn decompress(data: &[u8], expected_size: usize) -> Result<Vec<u8>, VgDatError> {
    let fail = VgDatError::DecompressionFailed;
    if expected_size == 0 || expected_size > MAX_INFLATED_SIZE || data.len() < 6 {
        return Err(fail);
    }
    // CMF/FLG: deflate, 32K window, no preset dictionary, header checksum a multiple of 31.
    if data[0] & 0x0F != 8 || (usize::from(data[0]) << 8 | usize::from(data[1])) % 31 != 0 || data[1] & 0x20 != 0 {
        return Err(fail);
    }
    let raw = &data[2..data.len() - 4];
    let adler = u32::from_be_bytes(data[data.len() - 4..].try_into().expect("4 bytes"));

    // One spare byte: an inflated stream longer than expected_size shows up as expected_size + 1.
    let mut out = Vec::with_capacity(expected_size + 1);
    flate2::read::DeflateDecoder::new(raw).take(expected_size as u64 + 1).read_to_end(&mut out).map_err(|_| fail)?;
    if out.len() != expected_size || adler32(&out) != adler {
        return Err(fail);
    }
    Ok(out)
}

pub fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in bytes {
        a = (a + u32::from(byte)) % 65521;
        b = (b + a) % 65521;
    }
    b << 16 | a
}

fn probe_tag(ts: &[u8; 8]) -> [u8; 8] {
    let s3 = sha0::hash(&sha0::hash(&sha0::hash(&Sha1::digest(ts))));
    s3[..8].try_into().expect("8 bytes")
}

/// The 16-byte probe sent with `GET /vgc_download_dat/`: 8 bytes big-endian timestamp (ms) followed by the first 8
/// bytes of SHA0(SHA0(SHA0(SHA1(timestamp)))).
pub fn generate_probe(timestamp_ms: u64) -> [u8; 16] {
    let ts = timestamp_ms.to_be_bytes();
    let mut probe = [0u8; 16];
    probe[..8].copy_from_slice(&ts);
    probe[8..].copy_from_slice(&probe_tag(&ts));
    probe
}

pub fn verify_probe(probe: &[u8], allowed_diff_ms: u64, now_ms: u64) -> bool {
    let Ok(probe) = <&[u8; 16]>::try_from(probe) else {
        return false;
    };
    let ts: [u8; 8] = probe[..8].try_into().expect("8 bytes");
    within(now_ms, u64::from_be_bytes(ts), allowed_diff_ms) && probe_tag(&ts) == probe[8..]
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::{load, unhex};

    fn fixture() -> Vec<u8> {
        std::fs::read(vpngate_testkit::golden::dir().join("../VPNGate.dat")).expect("Tests/Fixtures/VPNGate.dat")
    }

    fn mutate(data: &[u8], recipe: &str) -> Vec<u8> {
        let (op, arg) = recipe.split_once(':').unwrap();
        let mut d = data.to_vec();
        match op {
            "truncate" => d.truncate(arg.parse().unwrap()),
            "xor" | "set" => {
                let (off, val) = arg.split_once('=').unwrap();
                let (off, val): (usize, u8) = (off.parse().unwrap(), val.parse().unwrap());
                if op == "xor" {
                    d[off] ^= val;
                } else {
                    d[off] = val;
                }
            }
            _ => panic!("unknown mutation {recipe}"),
        }
        d
    }

    #[test]
    fn golden() {
        let v = load("vgdat");
        let dat = fixture();
        for c in v["cases"].as_array().unwrap() {
            let name = c["name"].as_str().unwrap();
            match name {
                "fixture" => {
                    let f = parse(&dat, c["nowMs"].as_u64().unwrap()).unwrap();
                    assert_eq!(f.header_text, c["headerText"].as_str().unwrap());
                    assert_eq!(f.soap_url, c["soapURL"].as_str().unwrap());
                    assert_eq!(f.timestamp_ms, c["timestampMs"].as_u64().unwrap());
                    assert_eq!(f.is_fresh, c["isFresh"].as_bool().unwrap());
                    let names: Vec<&str> = f.inner.elements().iter().map(|e| e.name.as_str()).collect();
                    let want: Vec<&str> =
                        c["innerPackElementNames"].as_array().unwrap().iter().map(|n| n.as_str().unwrap()).collect();
                    assert_eq!(names, want);
                    let hosts = (f.inner.int("NumHosts").unwrap() as usize).min(f.inner.strs("IP").len());
                    assert_eq!(hosts as u64, c["serverCount"].as_u64().unwrap());
                    let got = serde_json::to_value(parse_inner_servers(&f.inner)).unwrap();
                    assert_eq!(got.as_array().unwrap().len(), c["servers"].as_array().unwrap().len());
                    for (g, w) in got.as_array().unwrap().iter().zip(c["servers"].as_array().unwrap()) {
                        assert!(vpngate_testkit::golden::json_eq(g, w), "{g}\n{w}");
                    }
                }
                n if n.starts_with("freshness") => {
                    let f = parse(&dat, c["nowMs"].as_u64().unwrap()).unwrap();
                    assert_eq!(f.is_fresh, c["isFresh"].as_bool().unwrap(), "{n}");
                }
                n if c.get("mutation").is_some() => {
                    let err = parse(&mutate(&dat, c["mutation"].as_str().unwrap()), 0).map(|_| ()).unwrap_err();
                    assert_eq!(Some(err.name()), c["error"].as_str(), "{n}");
                }
                "probe" => {
                    assert_eq!(
                        generate_probe(c["timestampMs"].as_u64().unwrap()).to_vec(),
                        unhex(c["probe"].as_str().unwrap())
                    );
                }
                n if n.starts_with("verify-") => {
                    let ok = verify_probe(
                        &unhex(c["probe"].as_str().unwrap()),
                        ALLOW_TIME_DIFF_MS,
                        c["nowMs"].as_u64().unwrap(),
                    );
                    assert_eq!(ok, c["valid"].as_bool().unwrap(), "{n}");
                }
                n if n.starts_with("inflate-") => {
                    let r =
                        decompress(&unhex(c["input"].as_str().unwrap()), c["expectedSize"].as_u64().unwrap() as usize);
                    match c["error"].as_str() {
                        Some(e) => assert_eq!(r.unwrap_err().name(), e, "{n}"),
                        None => assert_eq!(r.unwrap(), unhex(c["output"].as_str().unwrap()), "{n}"),
                    }
                }
                "tunables" => tunables_case(c),
                other => panic!("unhandled vgdat case {other}"),
            }
        }
    }

    fn tunables_case(c: &serde_json::Value) {
        let t = VgTunables::from_dyn_list(&unhex(c["dynList"].as_str().unwrap()));
        let want = |m: &serde_json::Value| -> HashMap<String, u64> {
            m.as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.as_u64().unwrap())).collect()
        };
        assert_eq!(t.values(), &want(&c["values"]));
        for l in c["lookups"].as_array().unwrap() {
            let (name, d) = (l["name"].as_str().unwrap(), l["default"].as_u64().unwrap());
            assert_eq!(t.value(name, d), l["value"].as_u64().unwrap(), "{name}/{d}");
            assert_eq!(t.seconds(name, d), l["seconds"].as_f64().unwrap(), "{name}/{d}");
        }
        assert!(VgTunables::from_dyn_list(&[1, 2, 3]).values().is_empty());
        assert_eq!(c["unparseable"].as_object().unwrap().len(), 0);

        // Same recipe as Export.swift: {a: 100, b: 200} then {B: 300}.
        let list = |entries: &[(&str, u64)]| {
            let mut p = Pack::new();
            for (n, v) in entries {
                p.add_int64(n, *v);
            }
            VgTunables::from_dyn_list(&p.serialize())
        };
        let mut older = VgTunables::default();
        older.merge(&list(&[("a", 100), ("b", 200)]));
        older.merge(&list(&[("B", 300)]));
        assert_eq!(older.values(), &want(&c["merged"]));
    }

    #[test]
    fn adler32_known_value() {
        assert_eq!(adler32(b"Wikipedia"), 0x11E6_0398);
    }

    #[test]
    fn api_certificate_yields_a_1024_bit_key() {
        use rsa::traits::PublicKeyParts;
        assert_eq!(api_key().expect("key").size(), 128);
    }
}
