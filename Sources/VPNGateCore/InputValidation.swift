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
}
