import Foundation
import Network
import Security
import VPNGateCore

public enum ListSource: String, Codable {
    case bundle = "Built-in"
    case cache = "Cached"
    case relaySync = "Relay P2P"
    case httpApi = "HTTP API"
    case csv = "CSV Mirror"
}

/// How a sync ended, which picks the next poll interval (client_exe.c FUN_00411140, 7366-7413).
public enum SyncOutcome {
    /// HTTP API or a relay delivered a fresh verified list: VGC_HTTP_POLL_INTERVAL_OK.
    case synced
    /// There were relays to ask, and none answered: VGC_UDP_POLL_INTERVAL_ERROR.
    case relaysFailed
    /// No source at all (no list to take relays from): VGC_HTTP_POLL_INTERVAL_ERROR.
    case noRelays
}

public struct ServerFetchResult {
    public let servers: [VPNServer]
    public let source: ListSource
    public let timestamp: Date?
    public let isFresh: Bool
    public let outcome: SyncOutcome

    public init(servers: [VPNServer], source: ListSource, timestamp: Date? = nil, isFresh: Bool = true,
                outcome: SyncOutcome = .synced) {
        self.servers = servers
        self.source = source
        self.timestamp = timestamp
        self.isFresh = isFresh
        self.outcome = outcome
    }
}

/// One relay to ask for the list: its address and the single port chosen for it.
public struct RelayTarget: Equatable {
    public let ip: String
    public let port: UInt16
    public init(ip: String, port: UInt16) { self.ip = ip; self.port = port }
}

/// Plain HTTP GET used for the project's list API. Production uses URLSession; tests inject a fake so nothing
/// ever touches the network. Must throw on a non-200 status or a body above `maxBytes`.
public typealias HTTPGet = @Sendable (_ url: URL, _ connectTimeout: TimeInterval, _ dataTimeout: TimeInterval,
                                      _ maxBytes: Int) async throws -> Data

/// Fetches and syncs VPNGate.dat from the project's HTTP API and peer-to-peer from relays.
/// Reference: SoftEther Windows Client / VPN Gate Plugin FUN_00411140 (scheduler), FUN_00414230 (HTTP API),
/// FUN_00411a00 / FUN_00411f20 / FUN_00412960 (relay download), FUN_00413140.
public final class VGDatFetcher {
    // Defaults of the client's tunables in milliseconds (client_exe.c 7366-7480, 8205-8300); a verified list's
    // DynList can override each of them within [default/5, default*50].
    static let httpPollOkMs: UInt64 = 3_600_000          // VGC_HTTP_POLL_INTERVAL_OK
    static let httpPollErrorMs: UInt64 = 600_000         // VGC_HTTP_POLL_INTERVAL_ERROR
    static let udpPollErrorMs: UInt64 = 600_000          // VGC_UDP_POLL_INTERVAL_ERROR (used when the relays all fail)
    static let tcpTargetHosts: UInt64 = 12               // VGC_NUM_TCP_TARGET_HOSTS
    static let tcpConnectMs: UInt64 = 1_000              // VGC_TCP_POLL_CONNECT_TIMEOUT
    static let tcpSslMs: UInt64 = 5_000                  // VGC_TCP_POLL_SSL_TIMEOUT
    static let dataMs: UInt64 = 60_000                   // VGC_HTTP_DATA_TIMEOUT
    static let httpConnectMs: UInt64 = 7_000             // VGC_HTTP_CONNECT_TIMEOUT
    /// Largest HTTP API body (0x2000000, client_exe.c:9040).
    static let httpMaxBytes = 32 * 1024 * 1024
    /// Timeout for the ack/junk/final-byte exchange (client_exe.c:8338, 10000 ms).
    public static let trailerTimeout: TimeInterval = 10.0
    static let lastGoodKey = "lastGoodRelay"

    private let makeStream: StreamFactory
    private let httpGet: HTTPGet
    private let now: () -> Date
    private let timeoutScale: Double
    private let defaults: UserDefaults
    private let shuffle: ([VPNServer]) -> [VPNServer]
    private let alternativeMode: Bool
    private let apiDigits: (Character, Character)
    private let tunableLock = NSLock()
    private var _tunables = VGTunables()
    public let cacheURL: URL
    private let bundleURLs: [URL]

    /// - Parameters:
    ///   - cacheURL: where the newest verified list is kept (tests pass a temporary file, never the user's).
    ///   - bundleURLs: the list shipped with the app; defaults to the app bundle's VPNGate.dat.
    ///   - now: clock for the 36 h freshness rule.
    ///   - timeoutScale: multiplies the original client's socket deadlines (tests use a tiny value).
    ///   - httpGet: the HTTP client of the list API (tests inject a fake).
    ///   - defaults: where the last relay that delivered a list is remembered (tests inject a throwaway suite).
    ///   - shuffle: relay order randomisation (tests make it deterministic).
    ///   - alternativeMode: the original's "alt mode" (client_exe.c:283074), which adds an https attempt of the API.
    ///   - apiDigits: the two hex digits of the API host name (`x?.x?`). The original takes characters 2 and 3 of a
    ///     hash of the machine; this app has no such id, so it uses random digits.
    public init(makeStream: @escaping StreamFactory = { TLSStream(host: $0, port: $1, proxy: $2) },
                httpGet: @escaping HTTPGet = VGDatFetcher.urlSessionGet,
                cacheURL: URL = VGDatFetcher.cachedDatURL,
                bundleURLs: [URL]? = nil,
                now: @escaping () -> Date = Date.init,
                timeoutScale: Double = 1,
                defaults: UserDefaults = .standard,
                shuffle: @escaping ([VPNServer]) -> [VPNServer] = { $0.shuffled() },
                alternativeMode: Bool = false,
                apiDigits: (Character, Character)? = nil) {
        self.makeStream = makeStream
        self.httpGet = httpGet
        self.cacheURL = cacheURL
        self.bundleURLs = bundleURLs ?? Bundle.main.url(forResource: "VPNGate", withExtension: "dat").map { [$0] } ?? []
        self.now = now
        self.timeoutScale = timeoutScale
        self.defaults = defaults
        self.shuffle = shuffle
        self.alternativeMode = alternativeMode
        let hex = Array("0123456789abcdef")
        self.apiDigits = apiDigits ?? (hex.randomElement()!, hex.randomElement()!)
    }

    // MARK: - Tunables (DynList)

    public var tunables: VGTunables { tunableLock.lock(); defer { tunableLock.unlock() }; return _tunables }

    /// Takes over the tunables of a verified list, like the original does for every list it parses, fresh or not.
    public func adopt(_ file: VGDatFile) { adoptTunables(file.tunables) }

    public func adoptTunables(_ t: VGTunables) {
        tunableLock.lock(); _tunables.merge(t); tunableLock.unlock()
    }

    private func ms(_ name: String, _ d: UInt64) -> TimeInterval { tunables.seconds(name, defaultMs: d) }

    /// Next poll = now + Rand % interval, i.e. uniformly random in [0, interval) (client_exe.c:7366-7413), with the
    /// interval of the outcome. `random` is injectable for tests.
    public func nextPollDelay(after outcome: SyncOutcome, random: UInt64 = UInt64.random(in: 0...UInt64.max)) -> TimeInterval {
        let intervalMs: UInt64
        switch outcome {
        case .synced: intervalMs = tunables.value("VGC_HTTP_POLL_INTERVAL_OK", default: Self.httpPollOkMs)
        case .relaysFailed: intervalMs = tunables.value("VGC_UDP_POLL_INTERVAL_ERROR", default: Self.udpPollErrorMs)
        case .noRelays: intervalMs = tunables.value("VGC_HTTP_POLL_INTERVAL_ERROR", default: Self.httpPollErrorMs)
        }
        return Double(random % intervalMs) / 1000.0
    }

    // MARK: - App Support & Bundle paths

    public static var appSupportDir: URL {
        let dir = AppPaths.supportDirectory
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var cachedDatURL: URL {
        appSupportDir.appendingPathComponent("VPNGate.dat")
    }

    public func loadCached() -> VGDatFile? {
        guard let data = try? Data(contentsOf: cacheURL) else { return nil }
        return try? VGDat.parse(data: data, now: now())
    }

    public func loadBundleDat() -> VGDatFile? {
        for url in bundleURLs {
            if let data = try? Data(contentsOf: url), let file = try? VGDat.parse(data: data, now: now()) { return file }
        }
        return nil
    }

    private func saveCached(_ data: Data, replacing existing: VGDatFile?, with new: VGDatFile) {
        // Never let an older (but validly signed) list overwrite a newer one.
        if let existing, existing.timestampMs >= new.timestampMs { return }
        try? FileManager.default.createDirectory(at: cacheURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? data.write(to: cacheURL, options: .atomic)
    }

    // MARK: - HTTP API

    /// `http(s)://x<h2>.x<h3>.client.api.vpngate2.jp/api/?session_id=<random u64>` (client_exe.c:9438-9440,
    /// 9020). The X-Transaction header of the original (an RC4-obscured copy of the OS name and LAN address) is
    /// deliberately not sent; whether the server insists on it is unknown, in which case this step fails and the
    /// relays are used.
    func apiURL(https: Bool, sessionID: UInt64 = UInt64.random(in: 0...UInt64.max)) -> URL {
        URL(string: "\(https ? "https" : "http")://x\(apiDigits.0).x\(apiDigits.1).client.api.vpngate2.jp/api/?session_id=\(sessionID)")!
    }

    /// Asks the project's API for the list. The reply is the same signed VPNGate.dat; it is only used when it
    /// verifies and is fresh. Plain http first, then (alternative mode only) https, as the original does.
    public func fetchFromHTTPApi() async throws -> VGDatFile {
        var last: Error = StreamError.protocolError("HTTP API unavailable")
        for url in [apiURL(https: false)] + (alternativeMode ? [apiURL(https: true)] : []) {
            do {
                let body = try await httpGet(url, ms("VGC_HTTP_CONNECT_TIMEOUT", Self.httpConnectMs) * timeoutScale,
                                             ms("VGC_HTTP_DATA_TIMEOUT", Self.dataMs) * timeoutScale, Self.httpMaxBytes)
                return try accept(body)
            } catch { last = error }
        }
        throw last
    }

    /// Verifies a downloaded list, adopts its tunables, and keeps it when it is fresh.
    private func accept(_ payload: Data) throws -> VGDatFile {
        let datFile = try VGDat.parse(data: payload, now: now())        // RSA signature
        adopt(datFile)                                                  // the original applies DynList before the age check
        guard datFile.isFresh else {
            throw StreamError.protocolError("Served a stale VPNGate.dat (\(datFile.timestamp))")
        }
        saveCached(payload, replacing: loadCached(), with: datFile)
        return datFile
    }

    /// Production HTTP client: no cache, no cookies, status 200 only, body capped.
    public static let urlSessionGet: HTTPGet = { url, connectTimeout, dataTimeout, maxBytes in
        let cfg = URLSessionConfiguration.ephemeral
        cfg.urlCache = nil; cfg.httpCookieStorage = nil; cfg.httpShouldSetCookies = false
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        cfg.timeoutIntervalForRequest = max(connectTimeout, dataTimeout)      // idle gap; URLSession has no separate connect timeout
        cfg.timeoutIntervalForResource = connectTimeout + dataTimeout
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        let (bytes, resp) = try await session.bytes(from: url)
        guard let http = resp as? HTTPURLResponse, http.statusCode == 200 else {
            throw StreamError.protocolError("HTTP status \((resp as? HTTPURLResponse)?.statusCode ?? 0)")
        }
        if resp.expectedContentLength > Int64(maxBytes) { throw StreamError.protocolError("HTTP body too large") }
        var body = Data()
        for try await byte in bytes {
            body.append(byte)
            if body.count > maxBytes { throw StreamError.protocolError("HTTP body too large") }
        }
        return body
    }

    // MARK: - Peer-to-peer Relay Fetch

    /// Relay choice of FUN_00411a00 (client_exe.c:7641-7745): shuffle; pass 1 takes hosts offering 443 (port 443),
    /// pass 2 the remaining hosts that have SSL ports, each on the first port of its priority order; each pass
    /// admits at most VGC_NUM_TCP_TARGET_HOSTS + 1 hosts (the original's post-increment `count <= N` test).
    /// Lists without SSL ports at all (the CSV mirror) fall back to the port from the OpenVPN config.
    static func selectTargets(from servers: [VPNServer], limit: Int, shuffle: ([VPNServer]) -> [VPNServer]) -> [RelayTarget] {
        let shuffled = shuffle(servers)
        let cap = limit + 1
        var targets = shuffled.filter { $0.sslPorts.contains(443) }.prefix(cap).map { RelayTarget(ip: $0.ip, port: 443) }
        targets += shuffled.filter { !$0.sslPorts.contains(443) && !$0.sslPorts.isEmpty }.prefix(cap)
            .map { RelayTarget(ip: $0.ip, port: $0.prioritizedSslPorts[0]) }
        if targets.isEmpty {
            targets = shuffled.prefix(limit).map { RelayTarget(ip: $0.ip, port: UInt16($0.connectPort ?? 443)) }
        }
        return targets
    }

    /// The relay that delivered the last list, tried first next time (client_exe.c FUN_00411f20, 7848-7900).
    var lastGoodRelay: RelayTarget? {
        get {
            guard let s = defaults.string(forKey: Self.lastGoodKey), let colon = s.lastIndex(of: ":"),
                  let port = UInt16(s[s.index(after: colon)...]) else { return nil }
            return RelayTarget(ip: String(s[..<colon]), port: port)
        }
        set { defaults.set(newValue.map { "\($0.ip):\($0.port)" }, forKey: Self.lastGoodKey) }
    }

    /// Asks the last-good relay, then up to 13 hosts with port 443 and 13 others, for the verified VPNGate.dat.
    public func fetchFromRelays(candidates: [VPNServer], proxy: ProxySettings) async throws -> VGDatFile {
        var targets = Self.selectTargets(from: candidates, limit: Int(clamping: tunables.value("VGC_NUM_TCP_TARGET_HOSTS", default: Self.tcpTargetHosts)),
                                         shuffle: shuffle)
        let lastGood = lastGoodRelay
        if let lastGood { targets.removeAll { $0 == lastGood }; targets.insert(lastGood, at: 0) }
        guard !targets.isEmpty else {
            throw StreamError.protocolError("No target relay hosts available")
        }

        var lastError: Error = StreamError.protocolError("All relay hosts failed")
        for target in targets {
            do {
                let file = try await downloadFromHost(host: target.ip, port: target.port, proxy: proxy)
                lastGoodRelay = target
                return file
            } catch {
                lastError = error
                if target == lastGood { lastGoodRelay = nil }      // the original forgets a cached relay that failed
                if Task.isCancelled { break }
            }
        }

        throw lastError
    }

    /// Runs `op`, cancelling `stream` (which fails whatever it is waiting on) if it takes longer than `seconds`.
    private func guarded<T>(_ stream: ByteStream, _ seconds: TimeInterval, _ op: () async throws -> T) async throws -> T {
        let box = DeadlineFlag()
        let watchdog = Task {
            try? await Task.sleep(nanoseconds: UInt64(seconds * timeoutScale * 1_000_000_000))
            if !Task.isCancelled { box.fire(); stream.cancel() }
        }
        defer { watchdog.cancel() }
        do { return try await op() } catch { throw box.fired ? StreamError.timeout : error }
    }

    /// Single host download implementation (GET /vgc_download_dat/ + probe + ack).
    /// Like the original, a list that is older than VG_ALLOW_TIME_DIFF is discarded so the next relay is tried.
    public func downloadFromHost(host: String, port: UInt16, proxy: ProxySettings) async throws -> VGDatFile {
        let stream = makeStream(host, port, proxy)
        defer { stream.cancel() }
        try await guarded(stream, ms("VGC_TCP_POLL_CONNECT_TIMEOUT", Self.tcpConnectMs) + ms("VGC_TCP_POLL_SSL_TIMEOUT", Self.tcpSslMs)) { try await stream.start() }

        let payload: Data = try await guarded(stream, ms("VGC_HTTP_DATA_TIMEOUT", Self.dataMs)) {
            // Send HTTP request + 16-byte probe
            let reqHead = "GET /vgc_download_dat/ HTTP/1.1\r\nHOST: vpngate\r\n\r\n"
            var reqData = Data(reqHead.utf8)
            reqData.append(contentsOf: VGDat.generateProbe(timestampMs: UInt64(max(0, now().timeIntervalSince1970 * 1000.0))))
            try await stream.send(reqData)

            // Read 4-byte big-endian payload length, then the payload
            let len = try await stream.recvU32()
            guard len > 0 && len <= 32 * 1024 * 1024 else {
                throw StreamError.protocolError("Invalid download_dat payload length: \(len)")
            }
            return try await stream.recv(Int(len))
        }

        // Ack (17 bytes, first = 1), 512 bytes of padding, then a best-effort 1-byte reply.
        try await guarded(stream, Self.trailerTimeout) {
            var ack = [UInt8](repeating: 0, count: 17)
            ack[0] = 1
            try await stream.send(Data(ack))
            var randomJunk = [UInt8](repeating: 0, count: 512)
            _ = SecRandomCopyBytes(kSecRandomDefault, 512, &randomJunk)
            try await stream.send(Data(randomJunk))
        }
        _ = try? await guarded(stream, Self.trailerTimeout) { try await stream.recv(1) }

        // Parse, verify the RSA signature, then require freshness before adopting it.
        return try accept(payload)
    }

    // MARK: - Sync pipeline

    /// Executes the full fallback sync pipeline:
    /// 1. The project's HTTP API (skipped when an app proxy is set: URLSession would not go through it)
    /// 2. P2P Relay fetch (if candidate servers exist; only fresh, verified lists are accepted)
    /// 3. The newer of the cached and the bundled VPNGate.dat
    /// 4. CSV Mirror fallback, only when no verified .dat exists at all
    /// A stored .dat older than 36 h is still returned (it is signed, and its SSL ports are worth more than the
    /// CSV list), but flagged `isFresh == false` so the UI can say so.
    public func sync(currentServers: [VPNServer], proxy: ProxySettings, mirror: URL? = nil) async -> ServerFetchResult {
        if proxy.kind == .none, let dat = try? await fetchFromHTTPApi() {
            return ServerFetchResult(servers: dat.servers, source: .httpApi, timestamp: dat.timestamp, isFresh: dat.isFresh)
        }
        var outcome = SyncOutcome.noRelays
        if !currentServers.isEmpty {
            outcome = .relaysFailed
            if let dat = try? await fetchFromRelays(candidates: currentServers, proxy: proxy) {
                return ServerFetchResult(servers: dat.servers, source: .relaySync, timestamp: dat.timestamp, isFresh: dat.isFresh)
            }
        }

        let stored: [(VGDatFile, ListSource)] = [(loadCached(), .cache), (loadBundleDat(), .bundle)]
            .compactMap { file, source in file.map { ($0, source) } }
        if let best = stored.max(by: { $0.0.timestampMs < $1.0.timestampMs }) {
            adopt(best.0)
            return ServerFetchResult(servers: best.0.servers, source: best.1, timestamp: best.0.timestamp,
                                     isFresh: best.0.isFresh, outcome: outcome)
        }

        if let csvServers = try? await ServerList.fetch(mirror: mirror), !csvServers.isEmpty {
            return ServerFetchResult(servers: csvServers, source: .csv, timestamp: nil, isFresh: true, outcome: outcome)
        }

        return ServerFetchResult(servers: currentServers, source: .cache, timestamp: nil, isFresh: false, outcome: outcome)
    }
}

/// Set by a deadline watchdog so `guarded` can tell a timeout from an ordinary failure.
private final class DeadlineFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var _fired = false
    var fired: Bool { lock.lock(); defer { lock.unlock() }; return _fired }
    func fire() { lock.lock(); _fired = true; lock.unlock() }
}
