//! User routing rules: validation, the first-match-wins matcher and the CIDR parser. Mirrors `RoutingRule.swift`.
//! Domain regexes use the `regex` crate, so only the syntax common to it and ICU is supported.

use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// What happens to traffic a rule matches: through the tunnel, around it, or dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoutingAction {
    Proxy,
    Direct,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoutingRuleType {
    DomainSuffix,
    DomainFull,
    DomainKeyword,
    DomainRegex,
    Ip,
    Cidr,
}

impl RoutingRuleType {
    pub fn is_domain(self) -> bool {
        !matches!(self, Self::Ip | Self::Cidr)
    }
}

/// Swift's `trimmingCharacters(in: .whitespaces)`: Unicode space separators and tab.
fn is_blank(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\u{A0}' | '\u{1680}' | '\u{2000}'..='\u{200A}' | '\u{202F}' | '\u{205F}' | '\u{3000}')
}

pub(crate) fn trim_blank(s: &str) -> &str {
    s.trim_matches(is_blank)
}

/// "Traffic matching `value` (as `type`) gets `action`." The first enabled rule that matches wins.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingRule {
    pub id: Uuid,
    #[serde(rename = "type")]
    pub rule_type: RoutingRuleType,
    pub value: String,
    pub action: RoutingAction,
    pub enabled: bool,
}

impl RoutingRule {
    /// New enabled rule with a random id; `value` is trimmed like the Swift initialiser does.
    pub fn new(rule_type: RoutingRuleType, value: &str, action: RoutingAction) -> Self {
        Self::with_id(Uuid::new_v4(), rule_type, value, action, true)
    }

    pub fn with_id(id: Uuid, rule_type: RoutingRuleType, value: &str, action: RoutingAction, enabled: bool) -> Self {
        RoutingRule { id, rule_type, value: trim_blank(value).to_string(), action, enabled }
    }

    /// `None` when `value` is a well-formed instance of `rule_type`; otherwise a short message for the editor.
    pub fn validation_error(rule_type: RoutingRuleType, value: &str) -> Option<&'static str> {
        let v = trim_blank(value);
        if v.is_empty() {
            return Some("Value is required.");
        }
        match rule_type {
            RoutingRuleType::DomainSuffix | RoutingRuleType::DomainFull => {
                (!is_plausible_domain(v)).then_some("Not a valid domain name.")
            }
            RoutingRuleType::DomainKeyword => None,
            RoutingRuleType::DomainRegex => regex::Regex::new(v).is_err().then_some("Not a valid regular expression."),
            RoutingRuleType::Ip => CidrMatcher::parse(v).is_none().then_some("Not a valid IPv4 or IPv6 address."),
            RoutingRuleType::Cidr => {
                if !v.contains('/') {
                    Some("A CIDR needs a /prefix, e.g. 10.0.0.0/8.")
                } else {
                    CidrMatcher::parse(v).is_none().then_some("Not a valid CIDR range.")
                }
            }
        }
    }

    pub fn error(&self) -> Option<&'static str> {
        Self::validation_error(self.rule_type, &self.value)
    }

    pub fn is_valid(&self) -> bool {
        self.error().is_none()
    }
}

fn is_plausible_domain(s: &str) -> bool {
    !s.is_empty()
        && s.chars().count() <= 253
        && !s.starts_with('.')
        && !s.ends_with('.')
        && !s.contains("..")
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
}

/// `id` and `enabled` are optional when decoding (a missing id gets a fresh one); `type`, `value` and `action` are not.
impl<'de> Deserialize<'de> for RoutingRule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            id: Option<Uuid>,
            #[serde(rename = "type")]
            rule_type: RoutingRuleType,
            value: String,
            action: RoutingAction,
            enabled: Option<bool>,
        }
        let r = Raw::deserialize(d)?;
        Ok(RoutingRule::with_id(
            r.id.unwrap_or_else(Uuid::new_v4),
            r.rule_type,
            &r.value,
            r.action,
            r.enabled.unwrap_or(true),
        ))
    }
}

/// The complete routing configuration: an ordered rule list, what unmatched traffic does, and whether to bypass
/// private/local networks.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoutingConfig {
    #[serde(default)]
    pub rules: Vec<RoutingRule>,
    #[serde(default = "default_action")]
    pub default_action: RoutingAction,
    #[serde(default)]
    pub bypass_private_networks: bool,
}

fn default_action() -> RoutingAction {
    RoutingAction::Proxy
}

impl Default for RoutingConfig {
    fn default() -> Self {
        RoutingConfig { rules: Vec::new(), default_action: RoutingAction::Proxy, bypass_private_networks: false }
    }
}

impl RoutingConfig {
    /// Ranges bypassed when `bypass_private_networks` is on: RFC 1918, link-local, CGNAT, loopback, IPv6 ULA/link-local.
    pub const PRIVATE_NETWORK_RANGES: [&'static str; 9] = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "169.254.0.0/16",
        "127.0.0.0/8",
        "100.64.0.0/10",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    ];

    /// True when this config changes nothing: everything through the tunnel, no custom rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty() && !self.bypass_private_networks && self.default_action == RoutingAction::Proxy
    }

    /// `rules`, with the private ranges appended as low-priority `direct` rules when enabled.
    pub fn effective_rules(&self) -> Vec<RoutingRule> {
        let mut out = self.rules.clone();
        if self.bypass_private_networks {
            out.extend(
                Self::PRIVATE_NETWORK_RANGES
                    .iter()
                    .map(|r| RoutingRule::new(RoutingRuleType::Cidr, r, RoutingAction::Direct)),
            );
        }
        out
    }
}

/// First enabled rule that matches a domain name or IP literal wins.
pub mod routing_matcher {
    use super::*;

    /// The destination has not resolved yet (e.g. a DNS query): only domain rules apply.
    pub fn match_domain(domain: &str, config: &RoutingConfig) -> Option<RoutingRule> {
        let d = domain.to_lowercase();
        let d = d.trim_matches('.');
        for rule in config.effective_rules() {
            if !rule.enabled || !rule.rule_type.is_domain() {
                continue;
            }
            let hit = match rule.rule_type {
                RoutingRuleType::DomainFull => d == rule.value.to_lowercase(),
                RoutingRuleType::DomainSuffix => {
                    let suf = rule.value.to_lowercase();
                    d == suf || d.strip_suffix(&suf).is_some_and(|rest| rest.ends_with('.'))
                }
                RoutingRuleType::DomainKeyword => d.contains(&rule.value.to_lowercase()),
                RoutingRuleType::DomainRegex => {
                    RegexBuilder::new(&rule.value).case_insensitive(true).build().is_ok_and(|re| re.is_match(d))
                }
                _ => false,
            };
            if hit {
                return Some(rule);
            }
        }
        None
    }

    /// The destination is a literal IP.
    pub fn match_ip(ip: &str, config: &RoutingConfig) -> Option<RoutingRule> {
        let target = CidrMatcher::parse(ip)?;
        config.effective_rules().into_iter().find(|rule| {
            rule.enabled
                && !rule.rule_type.is_domain()
                && CidrMatcher::parse(&rule.value).is_some_and(|m| m.contains(&target))
        })
    }

    /// The matched rule's action for the domain, else for the IP, else `config.default_action`.
    pub fn action(domain: Option<&str>, ip: Option<&str>, config: &RoutingConfig) -> RoutingAction {
        if let Some(rule) = domain.and_then(|d| match_domain(d, config)) {
            return rule.action;
        }
        if let Some(rule) = ip.and_then(|i| match_ip(i, config)) {
            return rule.action;
        }
        config.default_action
    }
}

/// A parsed IPv4/IPv6 address or CIDR range, compared as raw bytes so v4 and v6 share one implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CidrMatcher {
    /// 4 (v4) or 16 (v6) bytes.
    bytes: Vec<u8>,
    /// Bits that must match; `bytes.len() * 8` for a bare address.
    prefix_length: usize,
}

impl CidrMatcher {
    pub fn parse(text: &str) -> Option<Self> {
        let mut parts = text.splitn(2, '/').filter(|p| !p.is_empty());
        // Swift's split omits empty pieces, so "/8" is one part and "1.2.3.4/" has no prefix part.
        let first = parts.next()?;
        let second = parts.next();
        let bytes = parse_address(first)?;
        let prefix_length = match second {
            Some(p) => {
                let p: usize = p.parse::<i64>().ok().and_then(|p| usize::try_from(p).ok())?;
                if p > bytes.len() * 8 {
                    return None;
                }
                p
            }
            None => bytes.len() * 8,
        };
        Some(CidrMatcher { bytes, prefix_length })
    }

    /// True when `other` (a bare address) falls inside this range.
    pub fn contains(&self, other: &CidrMatcher) -> bool {
        if self.bytes.len() != other.bytes.len() {
            return false;
        }
        let mut remaining = self.prefix_length;
        for (a, b) in self.bytes.iter().zip(&other.bytes) {
            if remaining == 0 {
                break;
            }
            let bits = remaining.min(8);
            let mask = if bits == 8 { 0xFF } else { !(0xFFu8 >> bits) };
            if a & mask != b & mask {
                return false;
            }
            remaining -= bits;
        }
        true
    }
}

fn parse_address(s: &str) -> Option<Vec<u8>> {
    parse_ipv4(s).or_else(|| parse_ipv6(s))
}

fn parse_ipv4(s: &str) -> Option<Vec<u8>> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    parts
        .iter()
        .map(|p| {
            if p.is_empty() || p.len() > 3 || !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            u8::try_from(p.parse::<u16>().ok()?).ok()
        })
        .collect()
}

/// Full and "::" compressed forms; no zone id, no embedded IPv4.
fn parse_ipv6(s: &str) -> Option<Vec<u8>> {
    if !s.contains(':') {
        return None;
    }
    fn groups(part: &str) -> Option<Vec<u16>> {
        if part.is_empty() {
            return Some(Vec::new());
        }
        part.split(':')
            .map(|g| {
                if g.is_empty() || g.len() > 4 || !g.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return None;
                }
                u16::from_str_radix(g, 16).ok()
            })
            .collect()
    }
    let halves: Vec<&str> = s.split("::").collect();
    if halves.len() > 2 {
        return None;
    }
    let all = if halves.len() == 2 {
        let head = groups(halves[0])?;
        let tail = groups(halves[1])?;
        if head.len() + tail.len() > 8 {
            return None;
        }
        let zeros = 8 - head.len() - tail.len();
        [head, vec![0; zeros], tail].concat()
    } else {
        let g = groups(s)?;
        if g.len() != 8 {
            return None;
        }
        g
    };
    Some(all.iter().flat_map(|g| g.to_be_bytes()).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vpngate_testkit::golden::{json_eq, load};

    fn case(name: &str) -> Value {
        load("routing")["cases"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap().clone()
    }

    fn parse_type(v: &Value) -> RoutingRuleType {
        serde_json::from_value(v.clone()).unwrap()
    }

    #[test]
    fn validation_vectors() {
        let c = case("validation");
        for c in c["cases"].as_array().unwrap() {
            let got = RoutingRule::validation_error(parse_type(&c["type"]), c["value"].as_str().unwrap());
            assert_eq!(got, c["error"].as_str(), "{c}");
        }
    }

    #[test]
    fn private_ranges() {
        let c = case("private-ranges");
        assert_eq!(serde_json::to_value(RoutingConfig::PRIVATE_NETWORK_RANGES).unwrap(), c["ranges"]);
    }

    #[test]
    fn matcher_vectors() {
        for name in ["rules-default-proxy", "rules-default-direct", "rules-bypass-private", "empty"] {
            let c = case(name);
            let cfg: RoutingConfig = serde_json::from_value(c["config"].clone()).unwrap();
            assert!(json_eq(&serde_json::to_value(&cfg).unwrap(), &c["config"]), "{name}");
            assert_eq!(cfg.is_empty(), c["isEmpty"].as_bool().unwrap(), "{name}");
            let eff: Vec<String> = cfg.effective_rules().iter().map(|r| r.value.clone()).collect();
            assert_eq!(serde_json::to_value(eff).unwrap(), c["effectiveRules"], "{name}");
            let matched = |r: Option<RoutingRule>| match r {
                Some(r) => serde_json::json!({"action": r.action, "type": r.rule_type, "value": r.value}),
                None => Value::Null,
            };
            for d in c["domain"].as_array().unwrap() {
                let input = d["input"].as_str().unwrap();
                let m = routing_matcher::match_domain(input, &cfg);
                assert_eq!(matched(m.clone()), d["matched"], "{name} domain {input}");
                assert_eq!(
                    routing_matcher::action(Some(input), None, &cfg),
                    serde_json::from_value(d["action"].clone()).unwrap()
                );
            }
            for d in c["ip"].as_array().unwrap() {
                let input = d["input"].as_str().unwrap();
                assert_eq!(matched(routing_matcher::match_ip(input, &cfg)), d["matched"], "{name} ip {input}");
                assert_eq!(
                    routing_matcher::action(None, Some(input), &cfg),
                    serde_json::from_value(d["action"].clone()).unwrap()
                );
            }
            for d in c["both"].as_array().unwrap() {
                let got = routing_matcher::action(d["domain"].as_str(), d["ip"].as_str(), &cfg);
                assert_eq!(serde_json::to_value(got).unwrap(), d["action"], "{name} both {d}");
            }
        }
    }

    #[test]
    fn json_vectors() {
        for c in case("rule-json")["cases"].as_array().unwrap() {
            let r = serde_json::from_str::<RoutingRule>(c["input"].as_str().unwrap());
            if c["rule"].is_null() {
                assert!(r.is_err());
                continue;
            }
            let mut got = serde_json::to_value(r.unwrap()).unwrap();
            if c["idPresent"] == false {
                got["id"] = c["rule"]["id"].clone();
            }
            assert_eq!(got, c["rule"]);
        }
        for c in case("config-json")["cases"].as_array().unwrap() {
            let r = serde_json::from_str::<RoutingConfig>(c["input"].as_str().unwrap());
            if c["error"] == true {
                assert!(r.is_err());
            } else {
                assert_eq!(serde_json::to_value(r.unwrap()).unwrap(), c["config"]);
            }
        }
    }

    #[test]
    fn cidr_contains() {
        let m = |s| CidrMatcher::parse(s).unwrap();
        assert!(m("10.0.0.0/8").contains(&m("10.9.9.9")));
        assert!(!m("10.0.0.0/8").contains(&m("11.0.0.1")));
        assert!(!m("10.0.0.0/8").contains(&m("::1")));
        assert!(m("::/0").contains(&m("2001:db8::1")));
        assert!(CidrMatcher::parse("1.2.3.4/33").is_none());
    }
}
