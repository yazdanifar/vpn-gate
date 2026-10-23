import CryptoKit
import Foundation
import Security

/// A random value generated once per install and kept in a root-only file, so the `unique_id` the login pack
/// carries stays the same across sessions (the stock client sends a stable per-host hash). Deliberately not
/// derived from the hostname or any hardware identifier.
struct HostUniqueId {
    static let defaultPath = "/var/db/vpngate-mac.uid"
    /// Process-wide instance; falls back to a per-process random value when the file cannot be written (no root).
    static let shared = HostUniqueId.load(path: defaultPath)

    let key: Data

    /// Reads `path`; creates it with 32 random bytes (mode 0600) when missing or malformed. Never throws.
    static func load(path: String, random: (Int) -> Data = HostUniqueId.secureRandom) -> HostUniqueId {
        let url = URL(fileURLWithPath: path)
        if let d = try? Data(contentsOf: url), d.count == 32 { return HostUniqueId(key: d) }
        let fresh = random(32)
        if (try? fresh.write(to: url, options: .atomic)) != nil {
            chmod(path, 0o600)
        }
        return HostUniqueId(key: fresh)
    }

    static func secureRandom(_ n: Int) -> Data {
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }

    /// 20-byte login `unique_id` (SHA-1 sized, like the stock client's machine hash).
    var loginId: Data { Data(Insecure.SHA1.hash(data: Data("login".utf8) + key)) }
    /// 16-byte NodeInfo `UniqueId` (the stock client sends its random Cedar->UniqueId).
    var nodeId: Data { Data(SHA256.hash(data: Data("node".utf8) + key).prefix(16)) }
}
