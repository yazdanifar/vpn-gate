import AppKit
import Foundation
import VPNGateCore

enum HelperInstaller {
    static let label = "com.yazdanifar.vpngate.helper"
    static let installedPath = "/Library/PrivilegedHelperTools/vpngate-helper"
    static let plistPath = "/Library/LaunchDaemons/\(label).plist"

    /// The helper installer shipped inside the app (`scripts/build-pkg.sh`); nil when running a development build.
    static var bundledInstaller: URL? {
        Bundle.main.resourceURL?.appendingPathComponent("VPN Gate Helper.pkg")
            .takeIfExists
    }

    static var isInstalled: Bool { FileManager.default.fileExists(atPath: plistPath) }

    /// Opens the standard macOS installer for the helper. The user clicks through it and enters their password
    /// in the system's own dialog — no scripts, no custom prompts. Returns false if there is no installer to open.
    @discardableResult
    static func openInstaller() -> Bool {
        guard let pkg = bundledInstaller else { return false }
        return NSWorkspace.shared.open(pkg)
    }

    private static func runAdmin(_ script: String) throws {
        let escaped = script.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        p.arguments = ["-e", "do shell script \"\(escaped)\" with administrator privileges"]
        let err = Pipe(); p.standardError = err; p.standardOutput = Pipe()
        try p.run(); p.waitUntilExit()
        if p.terminationStatus != 0 {
            let msg = String(decoding: err.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
            throw NSError(domain: "HelperInstaller", code: Int(p.terminationStatus),
                          userInfo: [NSLocalizedDescriptionKey: msg.isEmpty ? "Installation cancelled" : msg])
        }
    }

    /// Single-quotes `s` for /bin/sh, so paths with spaces or quotes cannot break out of their argument.
    static func shellQuote(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }

    static func uninstall() throws {
        try runAdmin("launchctl bootout system/\(label) 2>/dev/null; rm -f \(shellQuote(plistPath)) \(shellQuote(installedPath)) \(shellQuote(helperSocketPath)); true")
    }
}

private extension URL {
    var takeIfExists: URL? { FileManager.default.fileExists(atPath: path) ? self : nil }
}
