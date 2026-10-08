import Foundation
import Network
import ServiceManagement
import SwiftUI
import VPNGateCore

@MainActor
final class AppModel: ObservableObject {
    @Published var servers: [VPNServer] = []
    @Published var loading = false
    @Published var loadError: String?
    @Published var event = HelperEvent(state: .disconnected)
    @Published var helperRunning = false
    @Published var helperInstalled = HelperInstaller.isInstalled
    @Published var logLines: [String] = []
    @Published var pings: [String: Int] = [:]          // measured TCP connect time, ms
    @Published var connectedAt: Date?
    @Published var notice: String?
    /// Set when Connect needs the helper installed or updated; the window shows a one-time setup alert.
    enum SetupPrompt { case install, update }
    @Published var setupPrompt: SetupPrompt?
    /// True from the moment the installer is opened until the helper answers.
    @Published var waitingForInstaller = false
    private var pendingServer: VPNServer?

    @Published var favorites: Set<String> { didSet { save("favorites", Array(favorites)) } }
    @Published var autoReconnect: Bool { didSet { defaults.set(autoReconnect, forKey: "autoReconnect") } }
    @Published var proxyKind: ProxySettings.Kind { didSet { defaults.set(proxyKind.rawValue, forKey: "proxyKind") } }
    @Published var proxyHost: String { didSet { defaults.set(proxyHost, forKey: "proxyHost") } }
    @Published var proxyPort: Int { didSet { defaults.set(proxyPort, forKey: "proxyPort") } }
    @Published var proxyUsername: String { didSet { defaults.set(proxyUsername, forKey: "proxyUsername") } }
    @Published var proxyPassword: String { didSet { Keychain.set(proxyPassword, account: "proxy") } }
    /// While connected, route IPv6 into the tunnel (and drop it) so dual-stack sites cannot bypass the VPN.
    @Published var blockIPv6: Bool { didSet { defaults.set(blockIPv6, forKey: "blockIPv6") } }
    @Published var lastServerID: String? { didSet { defaults.set(lastServerID, forKey: "lastServerID") } }
    /// Hide servers that keep logs longer than this many weeks (-1 = show all).
    @Published var maxLogWeeks: Int { didSet { defaults.set(maxLogWeeks, forKey: "maxLogWeeks") } }
    @Published var mirrorURL: String { didSet { defaults.set(mirrorURL, forKey: "mirrorURL") } }
    @Published var launchAtLogin: Bool {
        didSet {
            defaults.set(launchAtLogin, forKey: "launchAtLogin")
            updateLaunchAtLogin(launchAtLogin)
        }
    }
    @Published var listSource: ListSource = .bundle
    @Published var listTimestamp: Date? = nil
    @Published var listIsFresh: Bool = true
    @Published var activeAccount: ClientAccount? = nil
    @ObservedObject public var statistics = VGStatistics()
    public let accountManager = AccountManager()

    private let helper: HelperClient
    private let defaults: UserDefaults
    private let openInstaller: () -> Bool
    private var lastEventAt = Date.distantPast
    private var retry: Timer?
    private var pollTimer: Timer?
    private let datFetcher = VGDatFetcher()

    /// `autoStart: false` (tests) skips the background timer, the cache and the server-list download.
    init(socketPath: String = helperSocketPath, defaults: UserDefaults = .standard, autoStart: Bool = true,
         openInstaller: @escaping () -> Bool = { HelperInstaller.openInstaller() }) {
        self.helper = HelperClient(path: socketPath)
        self.defaults = defaults
        self.openInstaller = openInstaller
        let d = defaults
        favorites = Set(d.stringArray(forKey: "favorites") ?? [])
        autoReconnect = d.object(forKey: "autoReconnect") as? Bool ?? true
        proxyKind = ProxySettings.Kind(rawValue: d.string(forKey: "proxyKind") ?? "") ?? .none
        proxyHost = d.string(forKey: "proxyHost") ?? ""
        proxyPort = d.integer(forKey: "proxyPort")
        proxyUsername = d.string(forKey: "proxyUsername") ?? ""
        proxyPassword = autoStart ? (Keychain.get("proxy") ?? "") : ""
        blockIPv6 = d.object(forKey: "blockIPv6") as? Bool ?? true
        lastServerID = d.string(forKey: "lastServerID")
        maxLogWeeks = d.object(forKey: "maxLogWeeks") as? Int ?? -1
        mirrorURL = d.string(forKey: "mirrorURL") ?? ""
        launchAtLogin = d.bool(forKey: "launchAtLogin")
        if autoStart {
            if let cached = VGDatFetcher.loadCachedDat() {
                servers = cached.servers
                listSource = .cache
                listTimestamp = cached.timestamp
                listIsFresh = cached.isFresh
            } else if let bundled = VGDatFetcher.loadBundleDat() {
                servers = bundled.servers
                listSource = .bundle
                listTimestamp = bundled.timestamp
                listIsFresh = bundled.isFresh
            } else {
                servers = Self.loadCache()
            }
            migrateFavorites()
        }

        helper.onEvent = { [weak self] e in Task { @MainActor in self?.handle(e) } }
        helper.onDisconnect = { [weak self] in
            Task { @MainActor in self?.helperRunning = false; self?.event = HelperEvent(state: .disconnected) }
        }
        guard autoStart else { return }
        retry = Timer.scheduledTimer(withTimeInterval: 2, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.pollHelper() }
        }
        pollHelper()
        refresh()
    }

    private func save(_ key: String, _ v: [String]) { defaults.set(v, forKey: key) }

    // MARK: helper

    func pollHelper() {
        helperInstalled = HelperInstaller.isInstalled
        if !helper.isConnected { helperRunning = helper.connect() }
        resumeAfterSetup()
    }

    /// Confirmed in the setup alert: opens the standard installer; the pending connection resumes by itself.
    func beginSetup() {
        setupPrompt = nil
        if openInstaller() {
            waitingForInstaller = true
            notice = "Finish the installer, then VPN Gate connects automatically."
        } else {
            pendingServer = nil
            notice = "Installer not found. Reinstall VPN Gate from its installer package."
        }
    }

    func cancelSetup() { setupPrompt = nil; pendingServer = nil }

    /// The helper accepted connections and is current: continue what the user asked for.
    private func resumeAfterSetup() {
        guard waitingForInstaller || pendingServer != nil, helperRunning, !helperOutdated else { return }
        waitingForInstaller = false
        if notice?.hasPrefix("Finish the installer") == true { notice = nil }
        if let s = pendingServer { pendingServer = nil; connect(s) }
    }

    func uninstallHelper() {
        Task.detached {
            do { try HelperInstaller.uninstall() }
            catch { await MainActor.run { self.notice = "Uninstall failed: \(error.localizedDescription)" } }
            await MainActor.run { self.helperRunning = false; self.pollHelper() }
        }
    }

    private func handle(_ e: HelperEvent) {
        lastEventAt = Date()
        helperRunning = true
        if let l = e.log { appendLog(l) }
        if let err = e.error { appendLog("Error: \(err)"); notice = err }
        if e.state == .connected && connectedAt == nil { connectedAt = Date(); notice = nil }
        if e.state != .connected { connectedAt = nil }
        event = e
    }

    private func appendLog(_ l: String) {
        logLines.append(l)
        if logLines.count > 300 { logLines.removeFirst(logLines.count - 300) }
    }

    // MARK: connect

    var currentProxy: ProxySettings {
        var p = ProxySettings(); p.kind = proxyKind; p.host = proxyHost; p.port = proxyPort
        if proxyKind != .none && !proxyUsername.isEmpty { p.username = proxyUsername; p.password = proxyPassword }
        return p
    }

    var lastServer: VPNServer? { servers.first { $0.id == lastServerID } }

    var isConnected: Bool { event.state == .connected }

    /// True when the installed helper predates this app (it then lacks fixes or IPC fields).
    var helperOutdated: Bool { helperRunning && lastEventAt > .distantPast && (event.helperVersion ?? 0) < helperVersion }

    func connect(_ s: VPNServer) {
        pollHelper()
        // No helper (first run) or an older one: ask once, then continue automatically when the installer is done.
        if !helperRunning { pendingServer = s; setupPrompt = .install; return }
        if helperOutdated { pendingServer = s; setupPrompt = .update; return }
        notice = nil
        var r = HelperRequest(cmd: "connect")
        r.host = s.ip; r.port = s.connectPort
        if !s.sslPorts.isEmpty { r.ports = s.sslPorts.map(Int.init) }
        r.proxy = currentProxy; r.autoReconnect = autoReconnect; r.blockIPv6 = blockIPv6
        lastServerID = s.id
        let sentAt = Date()
        helper.send(r)
        event.state = .connecting; event.server = s.ip
        // A helper that accepts the socket but never answers (hung, or an outdated build) must not leave the UI
        // on "Connecting…" forever.
        Task {
            try? await Task.sleep(nanoseconds: Self.helperAnswerTimeoutNs)
            if self.lastEventAt < sentAt && self.event.state == .connecting {
                self.event = HelperEvent(state: .disconnected)
                self.notice = "The helper is not responding. Open Settings and choose “Reinstall helper…”."
                self.appendLog("No answer from the helper within \(Self.helperAnswerTimeoutNs / 1_000_000_000) s")
            }
        }
    }

    func connect(account: ClientAccount) {
        pollHelper()
        if !helperRunning { setupPrompt = .install; return }
        if helperOutdated { setupPrompt = .update; return }
        notice = nil
        let pw = accountManager.password(for: account)
        let cert = accountManager.certificate(for: account)
        let cfg = account.toConnectConfig(password: pw, certDer: cert, blockIPv6: blockIPv6)
        var r = HelperRequest(cmd: "connect")
        r.config = cfg
        activeAccount = account
        lastServerID = account.name
        let sentAt = Date()
        helper.send(r)
        event.state = .connecting; event.server = account.host
        Task {
            try? await Task.sleep(nanoseconds: Self.helperAnswerTimeoutNs)
            if self.lastEventAt < sentAt && self.event.state == .connecting {
                self.event = HelperEvent(state: .disconnected)
                self.notice = "The helper is not responding. Open Settings and choose “Reinstall helper…”."
                self.appendLog("No answer from the helper within \(Self.helperAnswerTimeoutNs / 1_000_000_000) s")
            }
        }
    }

    static let helperAnswerTimeoutNs: UInt64 = 8_000_000_000

    func disconnect() { helper.send(HelperRequest(cmd: "disconnect")) }

    /// Drops the current tunnel and connects again to the last server (new session, new address).
    func reconnect() {
        guard let s = lastServer else { return }
        connect(s)                                  // the helper tears the old session down before starting the new one
    }

    var connectedServer: VPNServer? {
        servers.first { $0.id == lastServerID && $0.ip == event.server } ?? servers.first { $0.ip == event.server }
    }

    // MARK: server list

    func refresh() {
        guard !loading else { return }
        loading = true; loadError = nil
        let mirror = URL(string: mirrorURL)
        Task {
            let res = await datFetcher.sync(currentServers: servers, proxy: currentProxy, mirror: mirror)
            if !res.servers.isEmpty {
                servers = res.servers
                listSource = res.source
                listTimestamp = res.timestamp
                listIsFresh = res.isFresh
                migrateFavorites()
                Self.saveCache(res.servers)
            } else if servers.isEmpty {
                loadError = "Failed to load servers"
            }
            loading = false
            scheduleNextPoll(success: !res.servers.isEmpty)
        }
    }

    private func scheduleNextPoll(success: Bool) {
        pollTimer?.invalidate()
        let interval = success ? VGDatFetcher.pollIntervalOk : VGDatFetcher.pollIntervalError
        pollTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    private func updateLaunchAtLogin(_ enabled: Bool) {
        if #available(macOS 13.0, *) {
            do {
                if enabled {
                    try SMAppService.mainApp.register()
                } else {
                    try SMAppService.mainApp.unregister()
                }
            } catch {
                print("SMAppService registration error: \(error)")
            }
        }
    }

    func toggleFavorite(_ s: VPNServer) {
        if favorites.contains(s.id) { favorites.remove(s.id) } else { favorites.insert(s.id) }
    }

    /// Favorites used to be keyed by IP; the same IP can host several servers, so they are keyed by host name now.
    func migrateFavorites() {
        let legacy = favorites.filter { InputValidation.isIPv4Literal($0) }
        guard !legacy.isEmpty, !servers.isEmpty else { return }
        var migrated = favorites.subtracting(legacy)
        for ip in legacy { servers.filter { $0.ip == ip }.forEach { migrated.insert($0.id) } }
        favorites = migrated
    }

    /// Measures TCP connect latency to the servers' SSL-VPN port.
    func measure(_ list: [VPNServer]) {
        for s in list.prefix(60) {
            let port = NWEndpoint.Port(rawValue: UInt16(s.connectPort ?? 443))!
            let conn = NWConnection(host: NWEndpoint.Host(s.ip), port: port, using: .tcp)
            let start = Date()
            let ip = s.id
            let done = Flag()
            conn.stateUpdateHandler = { [weak self] (st: NWConnection.State) in
                switch st {
                case .ready:
                    if done.set() {
                        let ms = Int(Date().timeIntervalSince(start) * 1000)
                        Task { @MainActor in self?.pings[ip] = ms }
                    }
                    conn.cancel()
                case .failed, .waiting:
                    if done.set() { Task { @MainActor in self?.pings[ip] = -1 } }
                    conn.cancel()
                default: break
                }
            }
            conn.start(queue: .global())
            DispatchQueue.global().asyncAfter(deadline: .now() + 4) { conn.cancel() }
        }
    }

    // MARK: cache

    private static var cacheURL: URL {
        let d = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask)[0].appendingPathComponent("VPNGateMac")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        return d.appendingPathComponent("servers.json")
    }
    private static func loadCache() -> [VPNServer] {
        (try? JSONDecoder().decode([VPNServer].self, from: Data(contentsOf: cacheURL))) ?? []
    }
    private static func saveCache(_ s: [VPNServer]) {
        if let d = try? JSONEncoder().encode(s) { try? d.write(to: cacheURL) }
    }
}

final class Flag {
    private let lock = NSLock(); private var v = false
    /// Returns true the first time only.
    func set() -> Bool { lock.lock(); defer { lock.unlock() }; if v { return false }; v = true; return true }
}
