import Foundation

/// Where the app keeps its files. The test harness replaces `supportDirectory` (and `Keychain.service`) with
/// throwaway locations, so running the tests can never touch the user's real accounts, history or cached list.
enum AppPaths {
    static var supportDirectory: URL = {
        // VPNGATE_SUPPORT_DIR points a run (screenshots, demos) at a scratch folder instead of the real data.
        if let override = ProcessInfo.processInfo.environment["VPNGATE_SUPPORT_DIR"], !override.isEmpty {
            return URL(fileURLWithPath: override, isDirectory: true)
        }
        return FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("VPNGateMac", isDirectory: true)
    }()

    /// The support directory, created on demand.
    static func supportFile(_ name: String) -> URL {
        try? FileManager.default.createDirectory(at: supportDirectory, withIntermediateDirectories: true)
        return supportDirectory.appendingPathComponent(name)
    }
}
