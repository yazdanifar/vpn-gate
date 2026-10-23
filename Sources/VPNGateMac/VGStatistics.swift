import Foundation
import VPNGateCore

/// Mac-only, opt-in diagnostic upload (OFF by default, nothing is sent or scheduled until the user turns it on).
/// The Windows client does NOT send this for an ordinary client: its upload (client_exe.c ~12600-12700) only happens
/// when the machine hosts a VPN Gate relay and has per-session logs. The payload below is this app's own invention.
@MainActor
public final class VGStatistics: ObservableObject {
    public static let sendInterval: TimeInterval = 600.0  // 10 minutes
    public static let retryInterval: TimeInterval = 60.0  // 1 minute
    /// Opt-in key. Deliberately not the old `telemetryEnabled` key, which earlier builds set to true for everyone.
    static let optInKey = "telemetryOptIn"
    static let hostKeyKey = "telemetryHostKey"

    @Published public var isEnabled: Bool {
        didSet {
            defaults.set(isEnabled, forKey: Self.optInKey)
            if isEnabled { start() } else { stop() }
        }
    }

    @Published public var lastSentAt: Date? = nil
    @Published public var lastStatus: String? = nil

    private var timer: Timer?
    private let urlSession: URLSession
    private let defaults: UserDefaults
    /// Where uploads go; tests point this at a local server.
    var endpointOverride: URL?
    /// True while an upload is scheduled (nothing is scheduled while disabled).
    public var isScheduled: Bool { timer != nil }

    /// `startIfEnabled: false` (tests) never schedules anything even when the stored choice is on.
    public init(defaults: UserDefaults = .standard, session: URLSession = .shared, startIfEnabled: Bool = true) {
        self.urlSession = session
        self.defaults = defaults
        self.isEnabled = defaults.bool(forKey: Self.optInKey)  // absent = off
        if isEnabled && startIfEnabled { start() }
    }

    /// Random per-install identifier (not derived from the machine); `resetHostKey()` replaces it.
    public var hostKey: String {
        if let k = defaults.string(forKey: Self.hostKeyKey), !k.isEmpty { return k }
        return resetHostKey()
    }

    @discardableResult
    public func resetHostKey() -> String {
        let k = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        defaults.set(k, forKey: Self.hostKeyKey)
        return k
    }

    /// Exactly what an upload contains, for the Settings screen.
    nonisolated public static var payloadDescription: [String] {
        let p = makeTelemetryPack(hostKey: "<random per-install ID>")
        return [
            "HostKey: \(p.str("HostKey") ?? "")", "Build: \(p.int("Build") ?? 0)", "ClientVer: \(p.int("ClientVer") ?? 0)",
            "ClientBuild: \(p.int("ClientBuild") ?? 0)", "ClientOsName: \(p.str("ClientOsName") ?? "")", "IsClient: \(p.int("IsClient") ?? 0)",
        ]
    }

    public func start() {
        stop()
        guard isEnabled else { return }
        scheduleNext(interval: 5.0)  // first upload shortly after the user turned it on
    }

    public func stop() {
        timer?.invalidate()
        timer = nil
    }

    private func scheduleNext(interval: TimeInterval) {
        timer?.invalidate()
        guard isEnabled else { timer = nil; return }
        timer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor in
                _ = await self?.sendStatistics()
            }
        }
    }

    nonisolated public static func telemetryURL(hostKey: String, baseURL: String? = nil) -> URL {
        if let base = baseURL, let url = URL(string: base) {
            return url
        }
        // x%c.x%c are the hex digits at index 2 and 3 of the key (client_exe.c:12530-12535, 12623).
        let chars = Array(hostKey)
        let c0 = chars.count > 2 ? chars[2] : "0"
        let c1 = chars.count > 3 ? chars[3] : "0"
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

        let hostKey = self.hostKey
        let targetURL = overrideURL ?? endpointOverride ?? Self.telemetryURL(hostKey: hostKey)
        let pack = Self.makeTelemetryPack(hostKey: hostKey)
        let body = pack.serialize()

        var req = URLRequest(url: targetURL, timeoutInterval: 120)
        req.httpMethod = "POST"
        req.setValue("application/octet-stream", forHTTPHeaderField: "Content-Type")
        req.setValue("VPNGateMac (opt-in diagnostics)", forHTTPHeaderField: "User-Agent")
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
