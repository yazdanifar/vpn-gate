import CryptoKit
import Foundation

/// Server certificate pin: SHA-1 (40 hex) or SHA-256 (64 hex) fingerprint of the DER leaf certificate,
/// as shown by SoftEther / openssl (colons and spaces allowed, any case).
public struct CertPin: Equatable {
    public let digest: [UInt8]

    public init?(_ text: String) {
        let hex = text.filter { !$0.isWhitespace && $0 != ":" }
        guard hex.count == 40 || hex.count == 64, hex.allSatisfy(\.isHexDigit) else { return nil }
        var out = [UInt8](); var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            out.append(UInt8(hex[i..<j], radix: 16)!)
            i = j
        }
        digest = out
    }

    public func matches(certDER: Data) -> Bool {
        let actual: [UInt8] = digest.count == 20 ? Array(Insecure.SHA1.hash(data: certDER)) : Array(SHA256.hash(data: certDER))
        return actual == digest
    }
}

/// What the TLS verify block should do for a given configuration.
public enum ServerCertPolicy: Equatable {
    case acceptAny  // VPN Gate relays: self-signed, unverified
    case pinned(CertPin)
    case invalidPin  // a fingerprint is configured but unparseable: fail closed
    case systemTrust  // "verify server certificate" without a pin

    public init(checkServerCert: Bool, fingerprint: String?) {
        let fp = fingerprint?.trimmingCharacters(in: .whitespaces) ?? ""
        if !fp.isEmpty { self = CertPin(fp).map(ServerCertPolicy.pinned) ?? .invalidPin } else { self = checkServerCert ? .systemTrust : .acceptAny }
    }

    /// nil when the presented leaf is acceptable, otherwise the reason it is not.
    public func rejection(leafDER: Data?) -> String? {
        switch self {
        case .acceptAny, .systemTrust: return nil
        case .invalidPin: return "Server certificate fingerprint is not a valid SHA-1/SHA-256 hex string"
        case .pinned(let pin):
            guard let der = leafDER else { return "Server presented no certificate to match the pinned fingerprint" }
            return pin.matches(certDER: der) ? nil : "Server certificate does not match the pinned fingerprint"
        }
    }
}
