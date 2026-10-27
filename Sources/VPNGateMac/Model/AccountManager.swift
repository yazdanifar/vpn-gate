import Foundation

/// Manages persistence and secrets for custom SoftEther VPN Client Accounts.
/// Reference: SoftEther VPN Client Manager account list and settings storage.
/// Secrets (password, certificate, private key, proxy password) live in the Keychain only, never in accounts.json.
@MainActor
public final class AccountManager: ObservableObject {
    @Published public var accounts: [ClientAccount] = []
    /// Set when the accounts file could not be read completely (the original is kept next to it).
    @Published public var loadNotice: String?

    public static var accountsFileURL: URL {
        AppPaths.supportFile("accounts.json")
    }

    private let fileURL: URL

    public init(fileURL: URL? = nil) {
        self.fileURL = fileURL ?? Self.accountsFileURL
        loadAccounts()
    }

    /// Decodes one array element without letting a bad record fail the whole list.
    private struct Lossy: Decodable {
        let account: ClientAccount?
        init(from decoder: Decoder) throws { account = try? ClientAccount(from: decoder) }
    }

    /// Never overwrites what it cannot read: an unreadable file is moved to `accounts.json.corrupt-<date>`, a file with
    /// some unreadable records is copied there first, so the next save cannot destroy the originals.
    public func loadAccounts() {
        loadNotice = nil
        guard let data = try? Data(contentsOf: fileURL) else { accounts = []; return }
        guard let records = try? JSONDecoder().decode([Lossy].self, from: data) else {
            let kept = setAside(move: true)
            accounts = []
            loadNotice = "The saved connection settings could not be read" + (kept.map { " (kept as \($0))." } ?? ".")
            return
        }
        let list = records.compactMap(\.account)
        if list.count < records.count {
            let kept = setAside(move: false)
            loadNotice =
                "\(records.count - list.count) saved connection setting(s) could not be read and were skipped"
                + (kept.map { " (original kept as \($0))." } ?? ".")
        }
        accounts = list
        migrateProxyPasswords()
    }

    private func setAside(move: Bool) -> String? {
        let stamp = ISO8601DateFormatter().string(from: Date()).replacingOccurrences(of: ":", with: "-")
        let dest = fileURL.deletingLastPathComponent().appendingPathComponent(fileURL.lastPathComponent + ".corrupt-\(stamp)")
        try? FileManager.default.removeItem(at: dest)
        do {
            if move { try FileManager.default.moveItem(at: fileURL, to: dest) } else { try FileManager.default.copyItem(at: fileURL, to: dest) }
            return dest.lastPathComponent
        } catch { return nil }
    }

    /// An older file may still hold a proxy password in clear text: move it to the Keychain and rewrite the file.
    private func migrateProxyPasswords() {
        var changed = false
        for i in accounts.indices {
            guard let pw = accounts[i].proxy.password, !pw.isEmpty else { continue }
            Keychain.set(pw, account: keychainKey(for: accounts[i], suffix: "proxypw"))
            accounts[i].proxy.password = nil
            changed = true
        }
        if changed { saveAccounts() }
    }

    public func saveAccounts() {
        guard let data = try? JSONEncoder().encode(accounts) else { return }
        try? data.write(to: fileURL, options: .atomic)
    }

    public func add(_ account: ClientAccount, password: String? = nil, certDer: Data? = nil, privateKeyDer: Data? = nil) {
        var stored = account
        saveSecrets(for: &stored, password: password, certDer: certDer, privateKeyDer: privateKeyDer)
        accounts.append(stored)
        saveAccounts()
    }

    public func update(_ account: ClientAccount, password: String? = nil, certDer: Data? = nil, privateKeyDer: Data? = nil) {
        if let idx = accounts.firstIndex(where: { $0.id == account.id }) {
            var updated = account
            updated.updatedAt = Date()
            saveSecrets(for: &updated, password: password, certDer: certDer, privateKeyDer: privateKeyDer)
            accounts[idx] = updated
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
        let key = privateKey(for: account)
        copy.proxy.password = proxyPassword(for: account)
        saveSecrets(for: &copy, password: pw, certDer: cert, privateKeyDer: key)
        accounts.append(copy)
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

    /// PKCS#1 RSA private key (DER) for certificate login.
    public func privateKey(for account: ClientAccount) -> Data? {
        Keychain.getData(keychainKey(for: account, suffix: "key"))
    }

    public func proxyPassword(for account: ClientAccount) -> String? {
        Keychain.get(keychainKey(for: account, suffix: "proxypw"))
    }

    /// True when both halves of a certificate login are stored.
    public func hasCertificateIdentity(_ account: ClientAccount) -> Bool {
        certificate(for: account) != nil && privateKey(for: account) != nil
    }

    /// Stores what was given (nil keeps the stored value) and strips the proxy password from the in-memory account.
    private func saveSecrets(for account: inout ClientAccount, password: String?, certDer: Data?, privateKeyDer: Data?) {
        if let pw = password, !pw.isEmpty { Keychain.set(pw, account: keychainKey(for: account, suffix: "pw")) }
        if let cert = certDer, !cert.isEmpty { Keychain.setData(cert, account: keychainKey(for: account, suffix: "cert")) }
        if let key = privateKeyDer, !key.isEmpty { Keychain.setData(key, account: keychainKey(for: account, suffix: "key")) }
        if let ppw = account.proxy.password, !ppw.isEmpty { Keychain.set(ppw, account: keychainKey(for: account, suffix: "proxypw")) }
        account.proxy.password = nil
        if account.authType != .certificate {  // no stale key material for password accounts
            Keychain.delete(keychainKey(for: account, suffix: "cert"))
            Keychain.delete(keychainKey(for: account, suffix: "key"))
        }
    }

    private func clearSecrets(for account: ClientAccount) {
        for suffix in ["pw", "cert", "key", "proxypw"] { Keychain.delete(keychainKey(for: account, suffix: suffix)) }
    }
}
