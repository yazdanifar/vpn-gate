import Foundation
import VPNGateCore

enum Fmt {
    static func speed(_ bps: Int) -> String { String(format: "%.1f Mbps", Double(bps) / 1_000_000) }
    static func bytes(_ n: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .binary) }
    static func traffic(_ n: Int) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .decimal) }
    static func duration(_ since: Date?) -> String {
        guard let since = since else { return "" }
        let s = Int(Date().timeIntervalSince(since))
        return String(format: "%d:%02d:%02d", s / 3600, s % 3600 / 60, s % 60)
    }
}

extension ConnectionState {
    var title: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting…"
        case .authenticating: return "Authenticating…"
        case .dhcp: return "Getting address…"
        case .connected: return "Connected"
        case .reconnecting: return "Reconnecting…"
        }
    }
    var symbol: String {
        switch self {
        case .connected: return "lock.shield.fill"
        case .disconnected: return "lock.open"
        default: return "arrow.triangle.2.circlepath"
        }
    }
}
