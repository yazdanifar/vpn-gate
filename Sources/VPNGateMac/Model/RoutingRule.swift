// Mirrors of the engine's JSON types (crates/vpngate-core). The engine owns the logic; the app only needs the
// shapes, the editors' validation and the list formatting. Golden JSON in Tests/Fixtures/golden pins them.
import Foundation

/// What happens to traffic a rule matches: through the tunnel, around it over the original path, or dropped.
public enum RoutingAction: String, Codable, CaseIterable, Identifiable, Equatable {
    case proxy, direct, block
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .proxy: return "Proxy"
        case .direct: return "Direct"
        case .block: return "Block"
        }
    }
}

/// How a rule's `value` is matched, modelled on the V2rayN / V2Ray routing matchers.
public enum RoutingRuleType: String, Codable, CaseIterable, Identifiable, Equatable {
    case domainSuffix, domainFull, domainKeyword, domainRegex, ip, cidr
    public var id: String { rawValue }
    public var isDomain: Bool {
        switch self {
        case .domainSuffix, .domainFull, .domainKeyword, .domainRegex: return true
        case .ip, .cidr: return false
        }
    }
    public var label: String {
        switch self {
        case .domainSuffix: return "Domain suffix"
        case .domainFull: return "Domain (exact)"
        case .domainKeyword: return "Domain keyword"
        case .domainRegex: return "Domain regex"
        case .ip: return "IP address"
        case .cidr: return "IP range (CIDR)"
        }
    }
}

/// One user-defined routing rule: "traffic matching `value` (as `type`) gets `action`."
/// Order matters: the first enabled rule that matches wins (like V2rayN's rule list).
public struct RoutingRule: Identifiable, Codable, Equatable, Hashable {
    public var id: UUID
    public var type: RoutingRuleType
    public var value: String
    public var action: RoutingAction
    public var enabled: Bool

    public init(id: UUID = UUID(), type: RoutingRuleType, value: String, action: RoutingAction, enabled: Bool = true) {
        self.id = id
        self.type = type
        self.value = value.trimmingCharacters(in: .whitespaces)
        self.action = action
        self.enabled = enabled
    }

    private enum CodingKeys: String, CodingKey { case id, type, value, action, enabled }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            id: try c.decodeIfPresent(UUID.self, forKey: .id) ?? UUID(),
            type: try c.decode(RoutingRuleType.self, forKey: .type),
            value: try c.decode(String.self, forKey: .value),
            action: try c.decode(RoutingAction.self, forKey: .action),
            enabled: try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? true
        )
    }

    /// nil when `value` is a well-formed instance of `type`; otherwise a short message for the editor.
    public static func validationError(type: RoutingRuleType, value: String) -> String? {
        let v = value.trimmingCharacters(in: .whitespaces)
        if v.isEmpty { return "Value is required." }
        switch type {
        case .domainSuffix, .domainFull:
            return isPlausibleDomain(v) ? nil : "Not a valid domain name."
        case .domainKeyword:
            return nil  // any substring is valid
        case .domainRegex:
            return (try? NSRegularExpression(pattern: v)) != nil ? nil : "Not a valid regular expression."
        case .ip:
            return CIDRMatcher(v) != nil ? nil : "Not a valid IPv4 or IPv6 address."
        case .cidr:
            guard v.contains("/") else { return "A CIDR needs a /prefix, e.g. 10.0.0.0/8." }
            return CIDRMatcher(v) != nil ? nil : "Not a valid CIDR range."
        }
    }

    public var validationError: String? { Self.validationError(type: type, value: value) }
    public var isValid: Bool { validationError == nil }

    private static func isPlausibleDomain(_ s: String) -> Bool {
        !s.isEmpty && s.count <= 253 && s.first != "." && s.last != "." && !s.contains("..")
            && s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }
    }
}

/// The user's complete routing configuration: an ordered rule list, what unmatched traffic does, and
/// whether to also bypass private/local networks (RFC 1918 etc.) without the user having to type them in.
public struct RoutingConfig: Codable, Equatable, Hashable {
    public var rules: [RoutingRule]
    public var defaultAction: RoutingAction
    /// Bypasses LAN and other non-routable ranges (RFC 1918, link-local, CGNAT, loopback; IPv6 ULA/link-local)
    /// around the tunnel, same idea as V2rayN's bundled "bypass LAN" rule.
    public var bypassPrivateNetworks: Bool

    public init(rules: [RoutingRule] = [], defaultAction: RoutingAction = .proxy, bypassPrivateNetworks: Bool = false) {
        self.rules = rules
        self.defaultAction = defaultAction
        self.bypassPrivateNetworks = bypassPrivateNetworks
    }

    private enum CodingKeys: String, CodingKey { case rules, defaultAction, bypassPrivateNetworks }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            rules: try c.decodeIfPresent([RoutingRule].self, forKey: .rules) ?? [],
            defaultAction: try c.decodeIfPresent(RoutingAction.self, forKey: .defaultAction) ?? .proxy,
            bypassPrivateNetworks: try c.decodeIfPresent(Bool.self, forKey: .bypassPrivateNetworks) ?? false
        )
    }

    /// True when this config changes nothing (the plain, pre-feature behaviour): everything through the tunnel,
    /// no custom rules. The helper takes a fast path in that case.
    public var isEmpty: Bool { rules.isEmpty && !bypassPrivateNetworks && defaultAction == .proxy }

    /// Private/local ranges bypassed when `bypassPrivateNetworks` is on, always `.direct` and always checked
    /// first (a user rule can still override one explicitly, since it is still searched first in `rules`).
    public static let privateNetworkRanges: [String] = [
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "127.0.0.0/8", "100.64.0.0/10",
        "fc00::/7", "fe80::/10", "::1/128",
    ]

    /// `rules`, with the private-network ranges appended as low-priority `.direct` rules when enabled. User
    /// rules are searched first, so an explicit rule for an address inside one of these ranges still wins.
    public var effectiveRules: [RoutingRule] {
        guard bypassPrivateNetworks else { return rules }
        return rules + Self.privateNetworkRanges.map { RoutingRule(type: .cidr, value: $0, action: .direct) }
    }
}

/// A parsed IPv4/IPv6 address or CIDR range, compared as raw bytes so v4 and v6 share one implementation.
struct CIDRMatcher {
    let bytes: [UInt8]  // 4 (v4) or 16 (v6)
    let prefixLength: Int  // bits that must match; bytes.count * 8 for a bare address

    init?(_ text: String) {
        let parts = text.split(separator: "/", maxSplits: 1)
        guard parts.count == 1 || parts.count == 2 else { return nil }
        guard let addr = Self.parseAddress(String(parts[0])) else { return nil }
        bytes = addr
        if parts.count == 2 {
            guard let p = Int(parts[1]), (0...(addr.count * 8)).contains(p) else { return nil }
            prefixLength = p
        } else {
            prefixLength = addr.count * 8
        }
    }

    /// True when `other` (a bare address, as produced by parsing a literal with no "/prefix") falls inside this range.
    func contains(_ other: CIDRMatcher) -> Bool {
        guard bytes.count == other.bytes.count else { return false }
        var remaining = prefixLength
        for i in 0..<bytes.count {
            if remaining <= 0 { break }
            let bits = min(8, remaining)
            let mask: UInt8 = bits == 8 ? 0xFF : ~UInt8(0xFF >> bits)
            if (bytes[i] & mask) != (other.bytes[i] & mask) { return false }
            remaining -= bits
        }
        return true
    }

    private static func parseAddress(_ s: String) -> [UInt8]? {
        if let v4 = parseIPv4(s) { return v4 }
        return parseIPv6(s)
    }

    private static func parseIPv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var out = [UInt8]()
        for p in parts {
            guard !p.isEmpty, p.count <= 3, p.allSatisfy(\.isNumber), let v = Int(p), v <= 255 else { return nil }
            out.append(UInt8(v))
        }
        return out
    }

    /// Full and "::" compressed forms; no zone id, no embedded IPv4 (not needed for routing rules).
    private static func parseIPv6(_ s: String) -> [UInt8]? {
        guard s.contains(":"), !s.isEmpty else { return nil }
        let doubleColonParts = s.components(separatedBy: "::")
        guard doubleColonParts.count <= 2 else { return nil }
        func groups(_ part: String) -> [UInt16]? {
            if part.isEmpty { return [] }
            var out = [UInt16]()
            for g in part.split(separator: ":", omittingEmptySubsequences: false) {
                guard !g.isEmpty, g.count <= 4, let v = UInt16(g, radix: 16) else { return nil }
                out.append(v)
            }
            return out
        }
        var head: [UInt16], tail: [UInt16]
        if doubleColonParts.count == 2 {
            guard let h = groups(doubleColonParts[0]), let t = groups(doubleColonParts[1]) else { return nil }
            head = h; tail = t
            guard head.count + tail.count <= 8 else { return nil }
            head += [UInt16](repeating: 0, count: 8 - head.count - tail.count)
        } else {
            guard let g = groups(s), g.count == 8 else { return nil }
            head = g; tail = []
        }
        let all = head + tail
        guard all.count == 8 else { return nil }
        var out = [UInt8]()
        for g in all { out.append(UInt8(g >> 8)); out.append(UInt8(g & 0xFF)) }
        return out
    }
}
