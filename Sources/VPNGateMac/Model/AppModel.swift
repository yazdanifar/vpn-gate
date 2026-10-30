import Combine
import Foundation
import Network
import ServiceManagement
import SwiftUI

@MainActor
final class AppModel: ObservableObject {
    @Published var servers: [VPNServer] = []
    @Published var loading = false
    @Published var loadError: String?
    @Published var event = HelperEvent(state: .disconnected)
    /// Live byte counters, kept out of `event` so their once-a-second updates only redraw the views that show them.
    let traffic = TrafficCounter()
    @Published var helperRunning = false
    @Published var helperInstalled = HelperInstaller.isInstalled
    @Published var logLines: [String] = []
    @Published var probes: [String: ProbeOutcome] = [:]  // connectivity test results from this Mac
    private var probeTask: Task<Void, Never>?
    @Published var connectedAt: Date?
    @Published var notice: String?
    /// Set when Connect needs the helper installed or updated; the window shows a one-time setup alert.
    enum SetupPrompt { case install, update }
    @Published var setupPrompt: SetupPrompt?
    /// True from the moment the installer is opened until the helper answers.
    @Published var waitingForInstaller = false
    private var pendingServer: VPNServer?
    /// The list is asked for once per helper connection, as soon as a v9 helper has identified itself.
    private var listRequested = false

    @Published var favorites: Set<String> { didSet { save("favorites", Array(favorites)) } }
    @Published var autoReconnect: Bool { didSet { defaults.set(autoReconnect, forKey: "autoReconnect") } }
    @Published var proxyKind: ProxySettings.Kind { didSet { defaults.set(proxyKind.rawValue, forKey: "proxyKind") } }
    @Published var proxyHost: String { didSet { defaults.set(proxyHost, forKey: "proxyHost") } }
    @Published var proxyPort: Int { didSet { defaults.set(proxyPort, forKey: "proxyPort") } }
    @Published var proxyUsername: String { didSet { defaults.set(proxyUsername, forKey: "proxyUsername") } }
    @Published var proxyPassword: String { didSet { Keychain.set(proxyPassword, account: "proxy") } }
    /// While connected, route IPv6 into the tunnel (and drop it) so dual-stack sites cannot bypass the VPN.
    @Published var blockIPv6: Bool { didSet { defaults.set(blockIPv6, forKey: "blockIPv6") } }
    /// Full tunnel (the whole machine) or a local SOCKS5 proxy that only apps pointed at it use.
    @Published var tunnelMode: TunnelMode { didSet { defaults.set(tunnelMode.rawValue, forKey: "tunnelMode") } }
    @Published var socksPort: Int { didSet { defaults.set(socksPort, forKey: "socksPort") } }
    /// Global routing rules (domains/IPs to proxy, bypass or block); an account with its own rules ignores this.
    @Published var routingConfig: RoutingConfig {
        didSet { if let d = try? JSONEncoder().encode(routingConfig) { defaults.set(d, forKey: "routingConfig") } }
    }
    @Published var lastServerID: String? { didSet { defaults.set(lastServerID, forKey: "lastServerID") } }
    /// Hide servers that keep logs longer than this many weeks (-1 = show all).
    @Published var maxLogWeeks: Int { didSet { defaults.set(maxLogWeeks, forKey: "maxLogWeeks") } }
    @Published var mirrorURL: String { didSet { defaults.set(mirrorURL, forKey: "mirrorURL") } }
    @Published var launchAtLogin: Bool {
        didSet {
            guard !revertingLaunchAtLogin else { return }
            defaults.set(launchAtLogin, forKey: "launchAtLogin")
            updateLaunchAtLogin(launchAtLogin)
        }
    }
    /// The first-run disclaimer must be accepted before any connection starts (see `requireAgreement`).
    @Published var hasAgreedToDisclaimer: Bool
    @Published var showingDisclaimer = false
    private var pendingAfterAgreement: (() -> Void)?
    @Published var listSource: ListSource = .bundle
    @Published var listTimestamp: Date? = nil
    /// When a refresh last succeeded in downloading a list (not a cached/built-in fallback); kept across launches.
    @Published var listFetchedAt: Date? = nil
    @Published var listIsFresh: Bool = true
    @Published var activeAccount: ClientAccount? = nil
    /// Opt-in, Mac-only diagnostics (off until the user turns it on).
    var statistics: VGStatistics
    let accountManager: AccountManager
    let connectionLog: ConnectionLogStore
    private var historyEntry: UUID?
    private var historyBytes: (in: UInt64, out: UInt64) = (0, 0)
    private let loginItem: LoginItemControlling
    private var revertingLaunchAtLogin = false
    private var forwarded: [AnyCancellable] = []

    private let helper: HelperClient
    private let defaults: UserDefaults
    private let openInstaller: () -> Bool
    private var lastEventAt = Date.distantPast
    private var retry: Timer?
    private var pollTimer: Timer?
    /// Wait between reconnect attempts of a VPN Gate connection: the stock account's RetryInterval 0xF
    /// (client_exe.c:27590s). Tests shorten it.
    nonisolated static let reconnectInterval: TimeInterval = 15
    private let reconnectDelay: TimeInterval
    /// The old servers.json cache lives in ~/Library/Caches; tests (autoStart false) never write it.
    private let persistsServerCache: Bool
    /// Ask the helper for the list as soon as it identifies itself as v9 (tests opt in; they never write the cache file).
    private let listOnConnect: Bool
    /// Delay chosen for the pending list poll (seconds), for tests and the log.
    private(set) var scheduledPollDelay: TimeInterval?
    /// The VPN Gate server the user asked for and has not disconnected from (nil = nothing to keep alive).
    private var wantedServer: VPNServer?
    private var reconnectTask: Task<Void, Never>?
    /// Failed attempts since the last good connection (shown in the log only; there is no limit).
    private(set) var reconnectAttempts = 0

    /// `autoStart: false` (tests) skips the background timer, the cache and the server-list download.
    init(
        socketPath: String = helperSocketPath, defaults: UserDefaults = .standard, autoStart: Bool = true,
        openInstaller: @escaping () -> Bool = { HelperInstaller.openInstaller() },
        loginItem: LoginItemControlling = SMAppLoginItem(),
        accountManager: AccountManager? = nil, connectionLog: ConnectionLogStore? = nil,
        reconnectDelay: TimeInterval = 15, listOnConnect: Bool? = nil
    ) {
        self.helper = HelperClient(path: socketPath)
        self.reconnectDelay = reconnectDelay
        self.persistsServerCache = autoStart
        self.listOnConnect = listOnConnect ?? autoStart
        self.defaults = defaults
        self.openInstaller = openInstaller
        self.loginItem = loginItem
        self.accountManager = accountManager ?? AccountManager()
        self.connectionLog = connectionLog ?? ConnectionLogStore()
        self.statistics = VGStatistics(defaults: defaults, startIfEnabled: autoStart)
        hasAgreedToDisclaimer = defaults.bool(forKey: "hasAgreedToDisclaimer")
        let d = defaults
        favorites = Set(d.stringArray(forKey: "favorites") ?? [])
        autoReconnect = d.object(forKey: "autoReconnect") as? Bool ?? true
        proxyKind = ProxySettings.Kind(rawValue: d.string(forKey: "proxyKind") ?? "") ?? .none
        proxyHost = d.string(forKey: "proxyHost") ?? ""
        proxyPort = d.integer(forKey: "proxyPort")
        proxyUsername = d.string(forKey: "proxyUsername") ?? ""
        proxyPassword = autoStart ? (Keychain.get("proxy") ?? "") : ""
        blockIPv6 = d.object(forKey: "blockIPv6") as? Bool ?? true
        tunnelMode = d.string(forKey: "tunnelMode").flatMap(TunnelMode.init(rawValue:)) ?? .fullTunnel
        socksPort = d.object(forKey: "socksPort") as? Int ?? defaultSocksPort
        routingConfig = d.data(forKey: "routingConfig").flatMap { try? JSONDecoder().decode(RoutingConfig.self, from: $0) } ?? RoutingConfig()
        listFetchedAt = d.object(forKey: "listFetchedAt") as? Date
        lastServerID = d.string(forKey: "lastServerID")
        maxLogWeeks = d.object(forKey: "maxLogWeeks") as? Int ?? -1
        mirrorURL = d.string(forKey: "mirrorURL") ?? ""
        launchAtLogin = autoStart ? loginItem.status == .enabled : d.bool(forKey: "launchAtLogin")
        // Views observe the model only; relay changes of the nested stores so their screens refresh.
        forwarded = [statistics.objectWillChange, self.accountManager.objectWillChange, self.connectionLog.objectWillChange]
            .map { $0.sink { [weak self] _ in self?.objectWillChange.send() } }
        if autoStart {
            // Until the helper answers `listServers`, show what the last run saved.
            servers = Self.loadCache()
            migrateFavorites()
            if servers.isEmpty {
                // First launch, helper not installed yet: show the shipped list instead of an empty window.
                Task { @MainActor [weak self] in
                    if let r = await HelperClient.bundledList(), let self, self.servers.isEmpty { self.apply(r, downloaded: false) }
                }
            }
        }

        helper.onEvent = { [weak self] e in Task { @MainActor in self?.handle(e) } }
        helper.onDisconnect = { [weak self] in
            Task { @MainActor in
                self?.helperRunning = false
                self?.listRequested = false
                self?.cancelReconnect()
                self?.endHistory(error: nil)
                self?.event = HelperEvent(state: .disconnected)
            }
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
        // Assigning a @Published value republishes even when unchanged; that re-rendered the list view every 2 s
        // and dismissed the open Filter menu.
        let installed = HelperInstaller.isInstalled
        if helperInstalled != installed { helperInstalled = installed }
        if !helper.isConnected {
            let running = helper.connect()
            if helperRunning != running { helperRunning = running }
        }

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
            do { try HelperInstaller.uninstall() } catch { await MainActor.run { self.notice = "Uninstall failed: \(error.localizedDescription)" } }
            await MainActor.run {
                self.helperRunning = false; self.pollHelper()
            }
        }
    }

    private func handle(_ e: HelperEvent) {
        lastEventAt = Date()
        if !helperRunning { helperRunning = true }
        traffic.set(e.bytesIn, e.bytesOut)
        if let l = e.log { appendLog(l) }
        if let err = e.error { appendLog("Error: \(err)"); notice = err }
        if listOnConnect, !listRequested, (e.ipcVersion ?? 0) >= ipcVersion {
            listRequested = true
            loadListFromHelper()
        }
        if e.state == .connected && connectedAt == nil { connectedAt = Date(); notice = nil }
        if e.state != .connected { connectedAt = nil }
        trackHistory(e)
        // The helper reports the byte counters every second. Publishing each of those would re-render the whole
        // list window (and dismiss its open toolbar menu), so a counters-only event only updates `traffic`.
        if e.log == nil, e.error == nil, e.state == event.state, e.server == event.server, e.virtualIP == event.virtualIP,
            e.helperVersion == event.helperVersion
        {
            return
        }
        event = e
        considerReconnect(after: e)
    }

    // MARK: reconnect (VPN Gate connections)

    /// The Windows client's own account retries forever, every 15 s (NumRetry 0xFFFFFFFF, RetryInterval 0xF,
    /// client_exe.c:27590s): no attempt limit and no backoff. The helper is asked not to retry by itself for these
    /// connections; when it reports a dropped or failed connection and "Reconnect automatically" is on, this waits
    /// `reconnectDelay` and connects to the same server again, until the user disconnects or connects elsewhere.
    private func considerReconnect(after e: HelperEvent) {
        if e.state == .connected { reconnectAttempts = 0; return }
        guard e.state == .disconnected, e.error != nil, autoReconnect, let server = wantedServer, activeAccount == nil,
            reconnectTask == nil
        else { return }
        reconnectAttempts += 1
        appendLog("Reconnecting to \(server.hostName) in \(Int(reconnectDelay.rounded(.up))) s (attempt \(reconnectAttempts))")
        var waiting = HelperEvent(state: .reconnecting); waiting.server = server.ip; waiting.error = e.error
        event = waiting
        let delay = reconnectDelay
        reconnectTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            guard let self, !Task.isCancelled else { return }
            self.reconnectTask = nil
            guard self.wantedServer?.id == server.id, self.autoReconnect, self.event.state == .reconnecting, self.helperRunning else {
                if self.event.state == .reconnecting { self.event = HelperEvent(state: .disconnected) }
                return
            }
            self.sendConnect(server)
        }
    }

    private func cancelReconnect() { reconnectTask?.cancel(); reconnectTask = nil }

    // MARK: connection history

    /// One history entry per connected period: started when the helper reports `connected`, finished by the next
    /// event in any other state (or the helper going away) with the last byte counters seen while connected.
    private func trackHistory(_ e: HelperEvent) {
        if e.state == .connected {
            historyBytes = (e.bytesIn, e.bytesOut)
            if historyEntry == nil {
                let name = connectedServerName(for: e)
                historyEntry = connectionLog.recordStart(serverName: name, serverIP: e.server ?? "")
            }
        } else {
            endHistory(error: e.error)
        }
    }

    private func endHistory(error: String?) {
        guard let id = historyEntry else { return }
        historyEntry = nil
        connectionLog.recordEnd(id: id, bytesIn: historyBytes.in, bytesOut: historyBytes.out, error: error)
        historyBytes = (0, 0)
    }

    private func connectedServerName(for e: HelperEvent) -> String {
        if let a = activeAccount, a.host == e.server { return a.name }
        return servers.first { $0.ip == e.server }?.hostName ?? e.server ?? "unknown"
    }

    // MARK: disclaimer

    /// Every connection path goes through here: without the user's agreement the sheet is requested instead and the
    /// request is parked until they accept (or dropped if they decline).
    private func requireAgreement(_ action: @escaping () -> Void) -> Bool {
        if hasAgreedToDisclaimer { return true }
        pendingAfterAgreement = action
        showingDisclaimer = true
        return false
    }

    func agreeToDisclaimer() {
        hasAgreedToDisclaimer = true
        defaults.set(true, forKey: "hasAgreedToDisclaimer")
        showingDisclaimer = false
        let resume = pendingAfterAgreement
        pendingAfterAgreement = nil
        resume?()
    }

    func declineDisclaimer() { pendingAfterAgreement = nil }

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
    var helperOutdated: Bool {
        helperRunning && lastEventAt > .distantPast
            && ((event.helperVersion ?? 0) < helperVersion || (event.ipcVersion ?? 0) < ipcVersion)
    }

    func connect(_ s: VPNServer) {
        guard requireAgreement({ [weak self] in self?.connect(s) }) else { return }
        pollHelper()
        // No helper (first run) or an older one: ask once, then continue automatically when the installer is done.
        if !helperRunning { pendingServer = s; setupPrompt = .install; return }
        if helperOutdated { pendingServer = s; setupPrompt = .update; return }
        notice = nil
        cancelReconnect()
        wantedServer = s; reconnectAttempts = 0
        sendConnect(s)
    }

    private func sendConnect(_ s: VPNServer) {
        var r = HelperRequest(cmd: "connect")
        r.host = s.ip; r.port = s.connectPort
        if !s.sslPorts.isEmpty { r.ports = s.prioritizedSslPorts.map(Int.init) }
        // Retrying is done here (see considerReconnect), so the helper makes a single attempt.
        r.proxy = currentProxy; r.autoReconnect = false; r.blockIPv6 = blockIPv6
        if !routingConfig.isEmpty { r.routing = routingConfig }
        r.tunnelMode = tunnelMode; r.socksPort = socksPort
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
        guard requireAgreement({ [weak self] in self?.connect(account: account) }) else { return }
        pollHelper()
        if !helperRunning { setupPrompt = .install; return }
        if helperOutdated { setupPrompt = .update; return }
        notice = nil
        cancelReconnect(); wantedServer = nil
        let pw = accountManager.password(for: account)
        let cert = accountManager.certificate(for: account)
        let key = accountManager.privateKey(for: account)
        if account.authType == .certificate && (cert == nil || key == nil) {
            notice = "“\(account.name)” needs a certificate and RSA private key. Open its properties and import them."
            return
        }
        var acc = account
        if acc.proxy.kind != .none, acc.proxy.password == nil { acc.proxy.password = accountManager.proxyPassword(for: account) }
        let cfg = acc.toConnectConfig(
            password: pw, certDer: cert, privateKeyDer: key, blockIPv6: blockIPv6,
            globalRouting: routingConfig.isEmpty ? nil : routingConfig,
            tunnelMode: tunnelMode, socksPort: socksPort)
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

    func disconnect() {
        let waiting = reconnectTask != nil
        cancelReconnect(); wantedServer = nil
        helper.send(HelperRequest(cmd: "disconnect"))
        if waiting { event = HelperEvent(state: .disconnected) }  // between attempts the helper is idle already
    }

    /// Drops the current tunnel and connects again to the last server (new session, new address).
    func reconnect() {
        guard let s = lastServer else { return }
        connect(s)  // the helper tears the old session down before starting the new one
    }

    var connectedServer: VPNServer? {
        servers.first { $0.id == lastServerID && $0.ip == event.server } ?? servers.first { $0.ip == event.server }
    }

    // MARK: server list

    /// The cached or built-in list, no network: shown at once while `refresh` runs.
    private func loadListFromHelper() {
        Task {
            if let r = try? await helper.listServers(), !r.servers.isEmpty, servers.isEmpty || !loading { apply(r, downloaded: false) }
            refresh()
        }
    }

    private func apply(_ r: ServerListResult, downloaded: Bool) {
        servers = r.servers
        listSource = r.source
        listTimestamp = r.timestamp
        listIsFresh = r.isFresh
        if downloaded, r.source != .cache && r.source != .bundle {
            listFetchedAt = Date()
            if persistsServerCache { defaults.set(listFetchedAt, forKey: "listFetchedAt") }
        }
        migrateFavorites()
        if persistsServerCache { Self.saveCache(r.servers) }
    }

    func refresh() {
        guard !loading else { return }
        loading = true; loadError = nil
        let proxy = currentProxy, mirror = mirrorURL
        Task {
            var next: TimeInterval = Self.retryPollSeconds
            do {
                let r = try await helper.refreshServers(proxy: proxy, mirror: mirror)
                if !r.servers.isEmpty { apply(r, downloaded: true) } else if servers.isEmpty { loadError = "Failed to load servers" }
                next = r.nextPollSeconds ?? next
            } catch {
                if servers.isEmpty { loadError = "Failed to load servers: \(error.localizedDescription)" }
            }
            loading = false
            scheduleNextPoll(after: next)
        }
    }

    /// Wait before asking again when the helper could not be reached (the daemon picks the delay otherwise).
    nonisolated static let retryPollSeconds: TimeInterval = 600

    /// The daemon picks the delay (a random point of the interval for the outcome), the app owns the timer.
    private func scheduleNextPoll(after interval: TimeInterval) {
        pollTimer?.invalidate()
        scheduledPollDelay = interval
        pollTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: false) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }
    }

    /// Registers or unregisters the login item, then trusts what macOS reports: on an error, or when macOS still
    /// needs the user's approval, the toggle goes back and the reason is shown.
    private func updateLaunchAtLogin(_ enabled: Bool) {
        do {
            if enabled { try loginItem.register() } else { try loginItem.unregister() }
        } catch {
            revertLaunchAtLogin(to: !enabled, "Launch at login could not be \(enabled ? "enabled" : "disabled"): \(error.localizedDescription)")
            return
        }
        let status = loginItem.status
        if enabled && status != .enabled {
            try? loginItem.unregister()
            revertLaunchAtLogin(
                to: false,
                status == .requiresApproval
                    ? "Launch at login needs approval in System Settings → General → Login Items."
                    : "Launch at login is not available for this copy of the app (install it in /Applications).")
        }
    }

    private func revertLaunchAtLogin(to value: Bool, _ message: String) {
        revertingLaunchAtLogin = true; launchAtLogin = value; revertingLaunchAtLogin = false
        defaults.set(value, forKey: "launchAtLogin")
        notice = message
        appendLog(message)
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

    /// Tests every given server (all rows of the current view, in order) from this Mac with a real SoftEther handshake
    /// (not just a ping or a TCP connect). The daemon tests a few at a time; results land in `probes`, and a new run
    /// replaces earlier results for the same servers.
    func measure(_ list: [VPNServer]) {
        probeTask?.cancel()
        let targets = list
        for s in targets { probes[s.id] = .queued }
        let proxy = currentProxy
        probeTask = Task { [weak self] in
            guard let self else { return }
            // 200 relays per request is the daemon's cap.
            let chunks = stride(from: 0, to: targets.count, by: 200).map { Array(targets[$0..<min($0 + 200, targets.count)]) }
            for chunk in chunks {
                if Task.isCancelled { return }
                for s in chunk { probes[s.id] = .testing }
                do {
                    let entries = try await helper.probe(
                        chunk.map { ProbeTarget(host: $0.ip, ports: ServerProbe.ports(for: $0).map(Int.init)) }, proxy: proxy)
                    // A cancelled run must not overwrite the state of a newer one.
                    if Task.isCancelled { return }
                    for (s, e) in zip(chunk, entries) { probes[s.id] = e.outcome }
                } catch {
                    if Task.isCancelled { return }
                    for s in chunk { probes[s.id] = .failed(error.localizedDescription) }
                }
            }
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
