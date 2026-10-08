import Foundation
import CryptoKit
import VPNGateCore

/// VPN Gate anonymous statistics / telemetry uploader.
/// Reference: SoftEther Windows Client / VPN Gate Plugin client_exe.c:12600-12700.
@MainActor
public final class VGStatistics: ObservableObject {
    public static let sendInterval: TimeInterval = 600.0   // 10 minutes
    public static let retryInterval: TimeInterval = 60.0   // 1 minute

    @Published public var isEnabled: Bool {
        didSet {
            UserDefaults.standard.set(isEnabled, forKey: "telemetryEnabled")
            if isEnabled { start() } else { stop() }
        }
    }

    @Published public var lastSentAt: Date? = nil
    @Published public var lastStatus: String? = nil

    private var timer: Timer?
    private let urlSession: URLSession

    public init(session: URLSession = .shared) {
        self.urlSession = session
        // On by default matching Windows client
        if UserDefaults.standard.object(forKey: "telemetryEnabled") == nil {
            UserDefaults.standard.set(true, forKey: "telemetryEnabled")
        }
        self.isEnabled = UserDefaults.standard.bool(forKey: "telemetryEnabled")
        if isEnabled {
            start()
        }
    }

    public func start() {
        stop()
        scheduleNext(interval: 5.0) // initial attempt shortly after launch
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func scheduleNext(interval: TimeInterval) {
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor in
                await self?.sendStatistics()
            }
        }
    }

    nonisolated public static var hostKeyHex: String {
        let uuid = ProcessInfo.processInfo.hostName
        let hash = Insecure.SHA1.hash(data: Data(uuid.utf8))
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    nonisolated public static func telemetryURL(hostKey: String, baseURL: String? = nil) -> URL {
        if let base = baseURL, let url = URL(string: base) {
            return url
        }
        let chars = Array(hostKey)
        let c0 = chars.count > 0 ? chars[0] : "0"
        let c1 = chars.count > 1 ? chars[1] : "0"
        let rand = UInt64.random(in: 1...UInt64.max)
        let urlStr = "https://x\(c0).x\(c1).statistics.api.vpngate2.jp/api/statistics/?rand=\(rand)"
        return URL(string: urlStr) ?? URL(string: "https://www.vpngate.net/api/statistics/")!
    }

    nonisolated public static func makeTelemetryPack(hostKey: String) -> Pack {
        var p = Pack()
        p.addStr("HostKey", hostKey)
        p.addInt("Build", 9807)
        p.addInt("ClientVer", 444)
        p.addInt("ClientBuild", 9807)
        p.addStr("ClientOsName", "macOS")
        p.addInt("IsClient", 1)
        return p
    }

    public func sendStatistics(overrideURL: URL? = nil) async -> Bool {
        guard isEnabled else { return false }

        let hostKey = Self.hostKeyHex
        let targetURL = overrideURL ?? Self.telemetryURL(hostKey: hostKey)
        let pack = Self.makeTelemetryPack(hostKey: hostKey)
        let body = pack.serialize()

        var req = URLRequest(url: targetURL, timeoutInterval: 120)
        req.httpMethod = "POST"
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.setValue("SoftEther VPN Client (macOS)", forHTTPHeaderField: "User-Agent")
        req.httpBody = body

        do {
            let (_, resp) = try await urlSession.data(for: req)
            if let httpResp = resp as? HTTPURLResponse, httpResp.statusCode == 200 {
                lastSentAt = Date()
                lastStatus = "Successfully uploaded statistics"
                scheduleNext(interval: Self.sendInterval)
                return true
            } else {
                lastStatus = "Server error response"
                scheduleNext(interval: Self.retryInterval)
                return false
            }
        } catch {
            lastStatus = "Error: \(error.localizedDescription)"
            scheduleNext(interval: Self.retryInterval)
            return false
        }
    }
}
