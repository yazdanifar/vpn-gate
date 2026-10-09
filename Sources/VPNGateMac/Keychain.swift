import Foundation
import Security

/// Minimal generic-password wrapper for the proxy password.
enum Keychain {
    /// Only the test harness changes this (to keep tests out of the user's real Keychain items).
    static var service = "com.yazdanifar.VPNGateMac"

    private static func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    static func get(_ account: String) -> String? {
        getData(account).flatMap { String(data: $0, encoding: .utf8) }
    }

    static func set(_ value: String, account: String) {
        if value.isEmpty {
            delete(account)
        } else {
            setData(Data(value.utf8), account: account)
        }
    }

    static func getData(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return d
    }

    static func setData(_ data: Data, account: String) {
        SecItemDelete(query(account) as CFDictionary)
        guard !data.isEmpty else { return }
        var q = query(account)
        q[kSecValueData as String] = data
        SecItemAdd(q as CFDictionary, nil)
    }

    static func delete(_ account: String) {
        SecItemDelete(query(account) as CFDictionary)
    }
}
