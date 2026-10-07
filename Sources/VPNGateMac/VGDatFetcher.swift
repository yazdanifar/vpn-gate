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

public struct ServerFetchResult {
    public let servers: [VPNServer]
    public let source: ListSource
    public let timestamp: Date?
    public let isFresh: Bool

    public init(servers: [VPNServer], source: ListSource, timestamp: Date? = nil, isFresh: Bool = true) {
        self.servers = servers
        self.source = source
        self.timestamp = timestamp
        self.isFresh = isFresh
    }
}

/// Fetches and syncs VPNGate.dat peer-to-peer from relays, replacing the legacy CSV API.
/// Reference: SoftEther Windows Client / VPN Gate Plugin FUN_00412960 and FUN_00413140.
public final class VGDatFetcher {
    public static let numTcpTargetHosts = 12
    public static let tcpPollConnectTimeout: TimeInterval = 1.0
    public static let tcpPollSslTimeout: TimeInterval = 5.0
    public static let httpDataTimeout: TimeInterval = 60.0

    public static let pollIntervalOk: TimeInterval = 3600.0       // 1 hour
    public static let pollIntervalError: TimeInterval = 600.0     // 10 minutes

    private let makeStream: StreamFactory

    public init(makeStream: @escaping StreamFactory = { TLSStream(host: $0, port: $1, proxy: $2) }) {
        self.makeStream = makeStream
    }

    // MARK: - App Support & Bundle paths

    public static var appSupportDir: URL {
        let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let dir = appSupport.appendingPathComponent("VPNGateMac", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    public static var cachedDatURL: URL {
        appSupportDir.appendingPathComponent("VPNGate.dat")
    }

    public static func loadCachedDat() -> VGDatFile? {
        guard let data = try? Data(contentsOf: cachedDatURL) else { return nil }
        return try? VGDat.parse(data: data, verifySignature: true)
    }

    public static func loadBundleDat() -> VGDatFile? {
        // Try app bundle
        if let url = Bundle.main.url(forResource: "VPNGate", withExtension: "dat"),
           let data = try? Data(contentsOf: url),
           let file = try? VGDat.parse(data: data, verifySignature: true) {
            return file
        }
        // Try assets directory
        let assetsUrl = URL(fileURLWithPath: "assets/VPNGate.dat")
        if let data = try? Data(contentsOf: assetsUrl),
           let file = try? VGDat.parse(data: data, verifySignature: true) {
            return file
        }
        // Try fixture directory
        let fixtureUrl = URL(fileURLWithPath: "Tests/Fixtures/VPNGate.dat")
        if let data = try? Data(contentsOf: fixtureUrl),
           let file = try? VGDat.parse(data: data, verifySignature: true) {
            return file
        }
        return nil
    }

    public static func saveCachedDat(_ data: Data) {
        try? data.write(to: cachedDatURL, options: .atomic)
    }

    // MARK: - Peer-to-peer Relay Fetch

    /// Connects to up to 12 relays and downloads the verified VPNGate.dat.
    public func fetchFromRelays(candidates: [VPNServer], proxy: ProxySettings) async throws -> VGDatFile {
        // Pick servers that have SSL ports or connect ports
        let withPorts = candidates.filter { !$0.sslPorts.isEmpty || $0.connectPort != nil }
        let pool = withPorts.isEmpty ? candidates : withPorts
        let shuffled = pool.shuffled()
        let targets = Array(shuffled.prefix(Self.numTcpTargetHosts))

        guard !targets.isEmpty else {
            throw StreamError.protocolError("No target relay hosts available")
        }

        var lastError: Error = StreamError.protocolError("All relay hosts failed")

        for target in targets {
            let port: UInt16
            if let firstSsl = target.sslPorts.first {
                port = firstSsl
            } else if let cp = target.connectPort {
                port = UInt16(cp)
            } else {
                port = 443
            }

            do {
                let datFile = try await downloadFromHost(host: target.ip, port: port, proxy: proxy)
                return datFile
            } catch {
                lastError = error
                continue
            }
        }

        throw lastError
    }

    /// Single host download implementation (GET /vgc_download_dat/ + probe + ack).
    public func downloadFromHost(host: String, port: UInt16, proxy: ProxySettings) async throws -> VGDatFile {
        let stream = makeStream(host, port, proxy)
        try await stream.start()

        // Send HTTP request + 16-byte probe
        let reqHead = "GET /vgc_download_dat/ HTTP/1.1\r\nHOST: vpngate\r\n\r\n"
        var reqData = Data(reqHead.utf8)
        let probe = VGDat.generateProbe()
        reqData.append(contentsOf: probe)
        try await stream.send(reqData)

        // Read 4-byte big-endian payload length
        let len = try await stream.recvU32()
        guard len > 0 && len <= 32 * 1024 * 1024 else {
            stream.cancel()
            throw StreamError.protocolError("Invalid download_dat payload length: \(len)")
        }

        // Read payload bytes
        let payload = try await stream.recv(Int(len))

        // Send ACK: 17 bytes (byte 1 + 16 zero bytes)
        var ack = [UInt8](repeating: 0, count: 17)
        ack[0] = 1
        try await stream.send(Data(ack))

        // Send 512 random bytes
        var randomJunk = [UInt8](repeating: 0, count: 512)
        _ = SecRandomCopyBytes(kSecRandomDefault, 512, &randomJunk)
        try await stream.send(Data(randomJunk))

        // Read 1-byte reply (best-effort)
        _ = try? await stream.recv(1)
        stream.cancel()

        // Parse & verify signature
        let datFile = try VGDat.parse(data: payload, verifySignature: true)
        Self.saveCachedDat(payload)
        return datFile
    }

    // MARK: - Sync pipeline

    /// Executes the full fallback sync pipeline:
    /// 1. P2P Relay fetch (if candidate servers exist)
    /// 2. Cached VPNGate.dat
    /// 3. Bundled VPNGate.dat
    /// 4. CSV Mirror fallback
    public func sync(currentServers: [VPNServer], proxy: ProxySettings, mirror: URL? = nil) async -> ServerFetchResult {
        // 1. Try P2P relay sync if we already have candidate relays
        if !currentServers.isEmpty {
            if let dat = try? await fetchFromRelays(candidates: currentServers, proxy: proxy) {
                return ServerFetchResult(servers: dat.servers, source: .relaySync, timestamp: dat.timestamp, isFresh: dat.isFresh)
            }
        }

        // 2. Try App Support cache
        if let cached = Self.loadCachedDat() {
            return ServerFetchResult(servers: cached.servers, source: .cache, timestamp: cached.timestamp, isFresh: cached.isFresh)
        }

        // 3. Try bundled VPNGate.dat
        if let bundled = Self.loadBundleDat() {
            return ServerFetchResult(servers: bundled.servers, source: .bundle, timestamp: bundled.timestamp, isFresh: bundled.isFresh)
        }

        // 4. Try legacy CSV API as last resort
        if let csvServers = try? await ServerList.fetch(mirror: mirror), !csvServers.isEmpty {
            return ServerFetchResult(servers: csvServers, source: .csv, timestamp: nil, isFresh: true)
        }

        return ServerFetchResult(servers: currentServers, source: .cache, timestamp: nil, isFresh: false)
    }
}
