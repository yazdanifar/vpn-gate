import Foundation

/// Validation for values that end up in privileged command lines or sockets.
public enum InputValidation {
    public static func isValidPort(_ p: Int?) -> Bool {
        guard let p = p else { return false }
        return (1...65535).contains(p)
    }

    public static func isIPv4Literal(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        return parts.count == 4 && parts.allSatisfy { p in
            !p.isEmpty && p.count <= 3 && p.allSatisfy(\.isASCII) && p.allSatisfy(\.isNumber) && (Int(p) ?? 256) <= 255
        }
    }

    /// IPv4 literal or RFC 1123 hostname. Never starts with '-' (would be parsed as an option).
    public static func isValidHost(_ s: String) -> Bool {
        guard !s.isEmpty, s.count <= 253 else { return false }
        if isIPv4Literal(s) { return true }
        if s.allSatisfy({ $0.isNumber || $0 == "." }) { return false }     // malformed dotted number, not a hostname
        if s.first == "-" || s.first == "." || s.last == "." || s.last == "-" { return false }
        return s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }
            && !s.contains("..")
    }

    /// Loopback (127/8) and link-local (169.254/16) hosts must never get a bypass route.
    public static func isLocalAddress(_ s: String) -> Bool {
        guard isIPv4Literal(s) else { return s.lowercased() == "localhost" }
        let o = s.split(separator: ".").compactMap { Int($0) }
        return o[0] == 127 || (o[0] == 169 && o[1] == 254) || o[0] == 0
    }

    /// Unspecified, loopback, link-local and RFC 1918 IPv4 literals: never a usable address to advertise to a remote client.
    public static func isNonPublicIPv4(_ s: String) -> Bool {
        guard isIPv4Literal(s) else { return false }
        let o = s.split(separator: ".").compactMap { Int($0) }
        return o[0] == 0 || o[0] == 10 || o[0] == 127 || (o[0] == 169 && o[1] == 254)
            || (o[0] == 172 && (16...31).contains(o[1])) || (o[0] == 192 && o[1] == 168)
    }

    /// A pinned server certificate fingerprint: SHA-1 (40) or SHA-256 (64) hex digits, ':' ' ' '-' separators allowed.
    /// Returns the bare lowercase hex, or nil when the text is not such a fingerprint.
    public static func normalizedFingerprint(_ s: String) -> String? {
        let hex = s.filter { !$0.isWhitespace && $0 != ":" && $0 != "-" }.lowercased()
        guard hex.count == 40 || hex.count == 64, hex.allSatisfy({ $0.isASCII && $0.isHexDigit }) else { return nil }
        return hex
    }

    /// A "Virtual Network Adapter" MAC address: 6 hex byte pairs, ':' or '-' separated. Returns the 6 bytes,
    /// or nil when the text is not such an address. The locally-administered bit (the account editor should set
    /// it) is not enforced here; whatever the user typed is passed through as-is.
    public static func parseMacAddress(_ s: String) -> [UInt8]? {
        let parts = s.split(whereSeparator: { $0 == ":" || $0 == "-" })
        guard parts.count == 6 else { return nil }
        let bytes = parts.compactMap { UInt8($0, radix: 16) }
        return bytes.count == 6 ? bytes : nil
    }

    /// hub and user names travel in the SoftEther handshake: at most 255 bytes, no NUL.
    public static func isValidIdentityField(_ s: String) -> Bool {
        s.utf8.count <= 255 && !s.utf8.contains(0)
    }
}
