import Foundation
import VPNGateCore

/// Manages persistence and secrets for custom SoftEther VPN Client Accounts.
/// Reference: SoftEther VPN Client Manager account list and settings storage.
@MainActor
public final class AccountManager: ObservableObject {
    @Published public var accounts: [ClientAccount] = []

    public static var accountsFileURL: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSupport.appendingPathComponent("VPNGateMac", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir.appendingPathComponent("accounts.json")
    }

    public init() {
        loadAccounts()
    }

    public func loadAccounts() {
        guard let data = try? Data(contentsOf: Self.accountsFileURL),
              let list = try? JSONDecoder().decode([ClientAccount].self, from: data) else {
            accounts = []
            return
        }
        accounts = list
    }

    public func saveAccounts() {
        guard let data = try? JSONEncoder().encode(accounts) else { return }
        try? data.write(to: Self.accountsFileURL, options: .atomic)
    }

    public func add(_ account: ClientAccount, password: String? = nil, certDer: Data? = nil) {
        accounts.append(account)
        saveSecrets(for: account, password: password, certDer: certDer)
        saveAccounts()
    }

    public func update(_ account: ClientAccount, password: String? = nil, certDer: Data? = nil) {
        if let idx = accounts.firstIndex(where: { $0.id == account.id }) {
            var updated = account
            updated.updatedAt = Date()
            accounts[idx] = updated
            saveSecrets(for: updated, password: password, certDer: certDer)
            saveAccounts()
        }
    }

    public func duplicate(_ account: ClientAccount) {
        var copy = account
        copy.id = UUID()
        copy.name = "\(account.name) (Copy)"
        copy.createdAt = Date()
        copy.updatedAt = Date()
        let pw = password(for: account)
        let cert = certificate(for: account)
        accounts.append(copy)
        saveSecrets(for: copy, password: pw, certDer: cert)
        saveAccounts()
    }

    public func delete(_ account: ClientAccount) {
        accounts.removeAll { $0.id == account.id }
        clearSecrets(for: account)
        saveAccounts()
    }

    // MARK: - Keychain Secrets

    private func keychainKey(for account: ClientAccount, suffix: String) -> String {
        "account-\(account.id.uuidString)-\(suffix)"
    }

    public func password(for account: ClientAccount) -> String? {
        Keychain.get(keychainKey(for: account, suffix: "pw"))
    }

    public func certificate(for account: ClientAccount) -> Data? {
        Keychain.getData(keychainKey(for: account, suffix: "cert"))
    }

    private func saveSecrets(for account: ClientAccount, password: String?, certDer: Data?) {
        let pwKey = keychainKey(for: account, suffix: "pw")
        if let pw = password, !pw.isEmpty {
            Keychain.set(pw, account: pwKey)
        }
        let certKey = keychainKey(for: account, suffix: "cert")
        if let cert = certDer, !cert.isEmpty {
            Keychain.setData(cert, account: certKey)
        }
    }

    private func clearSecrets(for account: ClientAccount) {
        Keychain.delete(keychainKey(for: account, suffix: "pw"))
        Keychain.delete(keychainKey(for: account, suffix: "cert"))
    }
}
