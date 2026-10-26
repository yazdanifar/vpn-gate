//! Validation for values that end up in privileged command lines or sockets.

pub fn is_valid_port(p: Option<i64>) -> bool {
    p.is_some_and(|p| (1..=65535).contains(&p))
}

pub fn is_ipv4_literal(s: &str) -> bool {
    parse_ipv4(s).is_some()
}

/// Four dot-separated decimal fields of 1-3 ASCII digits, each at most 255. Leading zeros are accepted (`01.02.03.04`).
fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let mut out = [0u8; 4];
    let mut parts = s.split('.');
    for o in &mut out {
        let p = parts.next()?;
        if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *o = u8::try_from(p.parse::<u16>().ok()?).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// IPv4 literal or RFC 1123 hostname. Never starts with '-' (would be parsed as an option).
pub fn is_valid_host(s: &str) -> bool {
    if s.is_empty() || s.chars().count() > 253 {
        return false;
    }
    if is_ipv4_literal(s) {
        return true;
    }
    if s.chars().all(|c| c.is_numeric() || c == '.') {
        return false; // malformed dotted number, not a hostname
    }
    if s.starts_with(['-', '.']) || s.ends_with(['-', '.']) {
        return false;
    }
    s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') && !s.contains("..")
}

fn octets(s: &str) -> Option<[u8; 4]> {
    parse_ipv4(s)
}

/// Loopback (127/8), link-local (169.254/16) and 0/8 hosts must never get a bypass route.
pub fn is_local_address(s: &str) -> bool {
    match octets(s) {
        Some(o) => o[0] == 127 || (o[0] == 169 && o[1] == 254) || o[0] == 0,
        None => s.eq_ignore_ascii_case("localhost"),
    }
}

/// Unspecified, loopback, link-local and RFC 1918 IPv4 literals: never a usable address to advertise to a remote client.
pub fn is_non_public_ipv4(s: &str) -> bool {
    let Some(o) = octets(s) else { return false };
    o[0] == 0
        || o[0] == 10
        || o[0] == 127
        || (o[0] == 169 && o[1] == 254)
        || (o[0] == 172 && (16..=31).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
}

/// A pinned server certificate fingerprint: SHA-1 (40) or SHA-256 (64) hex digits, ':' ' ' '-' separators allowed.
/// Returns the bare lowercase hex, or `None` when the text is not such a fingerprint.
pub fn normalized_fingerprint(s: &str) -> Option<String> {
    let hex: String =
        s.chars().filter(|&c| !c.is_whitespace() && c != ':' && c != '-').flat_map(char::to_lowercase).collect();
    ((hex.len() == 40 || hex.len() == 64) && hex.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hex)
}

/// A "Virtual Network Adapter" MAC address: 6 hex byte fields, ':' or '-' separated (empty fields skipped, 1-2 digits
/// each). The locally-administered bit is not enforced; whatever was typed is passed through.
pub fn parse_mac_address(s: &str) -> Option<[u8; 6]> {
    let mut out = [0u8; 6];
    let mut parts = s.split([':', '-']).filter(|p| !p.is_empty());
    for o in &mut out {
        *o = u8::from_str_radix(parts.next()?, 16).ok()?;
    }
    parts.next().is_none().then_some(out)
}

/// Hub and user names travel in the SoftEther handshake: at most 255 bytes, no NUL.
pub fn is_valid_identity_field(s: &str) -> bool {
    s.len() <= 255 && !s.as_bytes().contains(&0)
}

/// A bare IPv4 or IPv6 address literal (no "/prefix"). IPv6 accepts the full and `::` compressed forms only (no zone id,
/// no embedded IPv4). Used to validate an address (e.g. a resolved DNS answer) before it reaches a `route` command line.
pub fn is_ip_literal(s: &str) -> bool {
    is_ipv4_literal(s) || is_ipv6_literal(s)
}

fn is_ipv6_literal(s: &str) -> bool {
    if !s.contains(':') {
        return false;
    }
    let groups = |part: &str| -> Option<usize> {
        if part.is_empty() {
            return Some(0);
        }
        let mut n = 0;
        for g in part.split(':') {
            if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                return None;
            }
            n += 1;
        }
        Some(n)
    };
    let mut halves = s.split("::");
    let (head, tail) = (halves.next().unwrap_or_default(), halves.next());
    if halves.next().is_some() {
        return false;
    }
    match tail {
        Some(t) => matches!((groups(head), groups(t)), (Some(h), Some(t)) if h + t <= 8),
        None => groups(head) == Some(8),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vpngate_testkit::golden::load;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn golden() {
        let v = load("validation");
        let groups = v["cases"].as_array().unwrap();
        assert_eq!(groups.len(), 9);
        for g in groups {
            let func = g["function"].as_str().unwrap();
            for c in g["cases"].as_array().unwrap() {
                let input = &c["input"];
                let want = &c["result"];
                let text = || input.as_str().unwrap();
                let ctx = format!("{func}({input})");
                match func {
                    "isValidPort" => assert_eq!(is_valid_port(input.as_i64()), want.as_bool().unwrap(), "{ctx}"),
                    "isIPv4Literal" => assert_eq!(is_ipv4_literal(text()), want.as_bool().unwrap(), "{ctx}"),
                    "isValidHost" => assert_eq!(is_valid_host(text()), want.as_bool().unwrap(), "{ctx}"),
                    "isLocalAddress" => assert_eq!(is_local_address(text()), want.as_bool().unwrap(), "{ctx}"),
                    "isNonPublicIPv4" => assert_eq!(is_non_public_ipv4(text()), want.as_bool().unwrap(), "{ctx}"),
                    "isIPLiteral" => assert_eq!(is_ip_literal(text()), want.as_bool().unwrap(), "{ctx}"),
                    "isValidIdentityField" => {
                        assert_eq!(is_valid_identity_field(text()), want.as_bool().unwrap(), "{ctx}")
                    }
                    "normalizedFingerprint" => {
                        assert_eq!(normalized_fingerprint(text()).as_deref(), want.as_str(), "{ctx}")
                    }
                    "parseMacAddress" => {
                        assert_eq!(parse_mac_address(text()).map(|m| hex(&m)).as_deref(), want.as_str(), "{ctx}")
                    }
                    other => panic!("unknown function {other}"),
                }
            }
        }
    }

    #[test]
    fn hosts_ported_from_swift_unit_tests() {
        for h in ["1.2.3.4", "219.100.37.7", "vpn927125019.opengw.net", "a", "my-host.example.com"] {
            assert!(is_valid_host(h), "{h}");
        }
        for h in [
            "",
            "-interface",
            "1.2.3",
            "1.2.3.256",
            "a b",
            "a;b",
            "a$(b)",
            "..",
            ".a",
            "a.",
            "a..b",
            "ho\nst",
            "höst",
            "1.2.3.4/32",
        ] {
            assert!(!is_valid_host(h), "{h:?}");
        }
        assert!(!is_valid_host(&"a".repeat(254)));
    }

    #[test]
    fn mac_single_digits_are_lenient() {
        assert_eq!(parse_mac_address("0:a:b:c:d:e"), Some([0, 0xa, 0xb, 0xc, 0xd, 0xe]));
        for bad in ["", "00:AC:DE:12:34", "00:AC:DE:12:34:56:78", "GG:AC:DE:12:34:56", "00AC.DE12.3456"] {
            assert_eq!(parse_mac_address(bad), None, "{bad}");
        }
    }
}
