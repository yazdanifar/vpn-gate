// Mirrors of the daemon's JSON (crates/vpngate-core/src/ipc.rs, docs/cross-platform/IPC.md). The app no longer links
// the engine; these shapes are pinned by the golden vectors in Tests/Fixtures/golden/ipc.json.
import Foundation

public let helperSocketPath = "/var/run/vpngate-mac.sock"
/// Bumped whenever the helper's behaviour or IPC changes; the app offers to reinstall an outdated helper.
public let helperVersion = 8
/// The request/reply protocol (`listServers`, `refreshServers`, `probe`, ...). A daemon reports it as `ipcVersion` in
/// every snapshot; an older one is offered a reinstall.
public let ipcVersion = 9

public enum ConnectionState: String, Codable {
    case disconnected, connecting, authenticating, dhcp, connected, reconnecting
}

public struct ProxySettings: Codable, Equatable, Hashable {
    public enum Kind: String, Codable { case none, http, socks5 }
    public var kind: Kind = .none
    public var host = ""
    public var port = 0
    public var username: String?
    public var password: String?
    public init() {}
}

/// How a connection exposes the VPN: capture the whole machine, or only serve a local SOCKS5 proxy.
public enum TunnelMode: String, Codable, Equatable {
    /// Default route, DNS and routing rules are pointed at the tunnel (the original behaviour).
    case fullTunnel
    /// The system's routes and DNS are left alone; the helper listens for SOCKS5 on `127.0.0.1:socksPort` and sends
    /// only the connections made through it into the tunnel.
    case socksProxy
}

public let defaultSocksPort = 1080

/// Full configuration for establishing a SoftEther session (general accounts or VPN Gate relays).
public struct ConnectConfig: Codable, Equatable {
    public var host: String
    public var ports: [Int]
    public var hubName: String
    public var userName: String
    public var authType: String  // anonymous, password, plain, cert, ticket
    public var password: String?
    public var certDer: Data?
    /// PKCS#1 RSAPrivateKey DER (PKCS#8 also accepted) for certificate auth; the helper signs the server challenge with it.
    /// Travels over the uid-restricted IPC socket only and is never logged.
    public var privateKeyDer: Data?
    public var ticket: Data?
    public var proxy: ProxySettings
    public var maxConnection: Int
    public var useCompress: Bool
    public var useUdpAccel: Bool
    /// SoftEther "Disable QoS" (login `qos` = !disableQoS). False = QoS on, like the stock Client Manager;
    /// the VPN Gate server-connect path sets it (the real VPN Gate client does).
    public var disableQoS: Bool
    /// SoftEther half connection: client-to-server and server-to-client traffic go over separate TCP sockets.
    /// Requires at least 4 connections; the helper enforces that minimum itself when this is set.
    public var halfConnection: Bool
    public var autoReconnect: Bool
    /// Seconds between reconnect attempts; nil keeps the helper's own default (3 s, the stock Client Manager's
    /// setting). VPN Gate connections never set this: the app does their retrying itself (see AppModel).
    public var reconnectInterval: TimeInterval?
    /// How many consecutive failures before giving up; nil keeps the helper's own default (8).
    public var reconnectCount: Int?
    public var blockIPv6: Bool
    public var checkServerCert: Bool
    public var serverCertFingerprint: String?
    /// Overrides the tunnel MTU; nil (the default) leaves it to the DHCP lease.
    public var mtu: Int?
    /// "Virtual Network Adapter" MAC override ("aa:bb:cc:dd:ee:ff"); nil (the default) uses a random one.
    public var virtualMacAddress: String?
    /// User-defined routing rules (domains/IPs to proxy, bypass or block); nil or empty means "everything
    /// through the tunnel", the pre-existing behaviour.
    public var routing: RoutingConfig?
    /// `.socksProxy` serves a local SOCKS5 proxy instead of capturing the machine's traffic (routing rules and
    /// IPv6 blocking do not apply then, as nothing is captured).
    public var tunnelMode: TunnelMode
    /// Loopback port of the SOCKS5 proxy in `.socksProxy` mode.
    public var socksPort: Int

    public init(
        host: String,
        ports: [Int] = [443, 992, 5555, 1194],
        hubName: String = "VPNGATE",
        userName: String = "vpn",
        authType: String = "anonymous",
        password: String? = nil,
        certDer: Data? = nil,
        privateKeyDer: Data? = nil,
        ticket: Data? = nil,
        proxy: ProxySettings = ProxySettings(),
        maxConnection: Int = 1,
        useCompress: Bool = false,
        useUdpAccel: Bool = true,
        disableQoS: Bool = false,
        halfConnection: Bool = false,
        autoReconnect: Bool = true,
        reconnectInterval: TimeInterval? = nil,
        reconnectCount: Int? = nil,
        blockIPv6: Bool = true,
        checkServerCert: Bool = false,
        serverCertFingerprint: String? = nil,
        mtu: Int? = nil,
        virtualMacAddress: String? = nil,
        routing: RoutingConfig? = nil,
        tunnelMode: TunnelMode = .fullTunnel,
        socksPort: Int = defaultSocksPort
    ) {
        self.host = host
        self.ports = ports
        self.hubName = hubName
        self.userName = userName
        self.authType = authType
        self.password = password
        self.certDer = certDer
        self.privateKeyDer = privateKeyDer
        self.ticket = ticket
        self.proxy = proxy
        self.maxConnection = maxConnection
        self.useCompress = useCompress
        self.useUdpAccel = useUdpAccel
        self.disableQoS = disableQoS
        self.halfConnection = halfConnection
        self.autoReconnect = autoReconnect
        self.reconnectInterval = reconnectInterval
        self.reconnectCount = reconnectCount
        self.blockIPv6 = blockIPv6
        self.checkServerCert = checkServerCert
        self.serverCertFingerprint = serverCertFingerprint
        self.mtu = mtu
        self.virtualMacAddress = virtualMacAddress
        self.routing = routing
        self.tunnelMode = tunnelMode
        self.socksPort = socksPort
    }

    /// Tolerant like the account file: a request from an older app (without `disableQoS`) still decodes.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(
            host: try c.decode(String.self, forKey: .host),
            ports: try c.decodeIfPresent([Int].self, forKey: .ports) ?? [443, 992, 5555, 1194],
            hubName: try c.decodeIfPresent(String.self, forKey: .hubName) ?? "VPNGATE",
            userName: try c.decodeIfPresent(String.self, forKey: .userName) ?? "vpn",
            authType: try c.decodeIfPresent(String.self, forKey: .authType) ?? "anonymous",
            password: try c.decodeIfPresent(String.self, forKey: .password),
            certDer: try c.decodeIfPresent(Data.self, forKey: .certDer),
            privateKeyDer: try c.decodeIfPresent(Data.self, forKey: .privateKeyDer),
            ticket: try c.decodeIfPresent(Data.self, forKey: .ticket),
            proxy: try c.decodeIfPresent(ProxySettings.self, forKey: .proxy) ?? ProxySettings(),
            maxConnection: try c.decodeIfPresent(Int.self, forKey: .maxConnection) ?? 1,
            useCompress: try c.decodeIfPresent(Bool.self, forKey: .useCompress) ?? false,
            useUdpAccel: try c.decodeIfPresent(Bool.self, forKey: .useUdpAccel) ?? true,
            disableQoS: try c.decodeIfPresent(Bool.self, forKey: .disableQoS) ?? false,
            halfConnection: try c.decodeIfPresent(Bool.self, forKey: .halfConnection) ?? false,
            autoReconnect: try c.decodeIfPresent(Bool.self, forKey: .autoReconnect) ?? true,
            reconnectInterval: try c.decodeIfPresent(TimeInterval.self, forKey: .reconnectInterval),
            reconnectCount: try c.decodeIfPresent(Int.self, forKey: .reconnectCount),
            blockIPv6: try c.decodeIfPresent(Bool.self, forKey: .blockIPv6) ?? true,
            checkServerCert: try c.decodeIfPresent(Bool.self, forKey: .checkServerCert) ?? false,
            serverCertFingerprint: try c.decodeIfPresent(String.self, forKey: .serverCertFingerprint),
            mtu: try c.decodeIfPresent(Int.self, forKey: .mtu),
            virtualMacAddress: try c.decodeIfPresent(String.self, forKey: .virtualMacAddress),
            routing: try c.decodeIfPresent(RoutingConfig.self, forKey: .routing),
            tunnelMode: try c.decodeIfPresent(TunnelMode.self, forKey: .tunnelMode) ?? .fullTunnel,
            socksPort: try c.decodeIfPresent(Int.self, forKey: .socksPort) ?? defaultSocksPort
        )
    }
}

public struct HelperRequest: Codable {
    public var cmd: String  // connect | disconnect | status
    public var host: String?
    public var port: Int?
    public var ports: [Int]?
    public var proxy: ProxySettings?
    public var autoReconnect: Bool?
    public var blockIPv6: Bool?
    public var routing: RoutingConfig?
    public var tunnelMode: TunnelMode?
    public var socksPort: Int?
    public var config: ConnectConfig?
    // IPC v9
    public var id: Int?
    public var mirror: String?
    public var targets: [ProbeTarget]?
    public var timeout: Double?
    public var account: ClientAccount?
    public init(cmd: String) { self.cmd = cmd }
}

public struct HelperEvent: Codable {
    public var state: ConnectionState
    public var server: String?
    public var virtualIP: String?
    public var bytesIn: UInt64 = 0
    public var bytesOut: UInt64 = 0
    public var log: String?
    public var error: String?
    public var helperVersion: Int?
    public var ipcVersion: Int?
    public init(state: ConnectionState) { self.state = state }
}

// MARK: IPC v9 replies

/// One answer to a request that carried an `id`. Event lines have `state`, replies have `reply`.
public struct HelperReply: Codable {
    public var reply: String
    public var id: Int?
    public var ok: Bool
    public var error: String?
    public var result: JSONValue?

    public func decode<T: Decodable>(_ type: T.Type) throws -> T {
        guard let result else { throw HelperRequestError.failed("The helper sent no result") }
        return try JSONDecoder().decode(T.self, from: JSONEncoder().encode(result))
    }
}

/// Minimal JSON tree so `HelperReply.result` can stay untyped until the caller knows what it asked for.
public enum JSONValue: Codable, Equatable {
    case null, bool(Bool), number(Double), string(String), array([JSONValue]), object([String: JSONValue])

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() {
            self = .null
        } else if let v = try? c.decode(Bool.self) {
            self = .bool(v)
        } else if let v = try? c.decode(Double.self) {
            self = .number(v)
        } else if let v = try? c.decode(String.self) {
            self = .string(v)
        } else if let v = try? c.decode([JSONValue].self) {
            self = .array(v)
        } else {
            self = .object(try c.decode([String: JSONValue].self))
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .null: try c.encodeNil()
        case .bool(let v): try c.encode(v)
        case .number(let v): try c.encode(v)
        case .string(let v): try c.encode(v)
        case .array(let v): try c.encode(v)
        case .object(let v): try c.encode(v)
        }
    }
}

public enum HelperRequestError: Error, Equatable, LocalizedError {
    /// The daemon answered `ok:false`.
    case failed(String)
    case timeout
    /// The socket is not connected, or dropped while the request was open.
    case disconnected
    /// The daemon predates IPC v9.
    case unsupported

    public var errorDescription: String? {
        switch self {
        case .failed(let m): return m
        case .timeout: return "The helper did not answer in time"
        case .disconnected: return "The helper is not running"
        case .unsupported: return "The installed helper is too old for this app. Reinstall it from Settings."
        }
    }
}

public enum ListSource: String, Codable {
    case bundle = "Built-in"
    case cache = "Cached"
    case relaySync = "Relay P2P"
    case httpApi = "HTTP API"
    case csv = "CSV Mirror"
}

public enum SyncOutcome: String, Codable {
    case synced, relaysFailed, noRelays
}

public struct ProbeTarget: Codable, Equatable {
    public var host: String
    public var ports: [Int]?
    public init(host: String, ports: [Int]? = nil) { self.host = host; self.ports = ports }
}

public struct ServerListResult: Codable {
    public var servers: [VPNServer]
    public var source: ListSource
    public var timestampMs: UInt64?
    public var isFresh: Bool
    public var outcome: SyncOutcome
    public var nextPollSeconds: Double?

    public var timestamp: Date? { timestampMs.map { Date(timeIntervalSince1970: Double($0) / 1000) } }
}

public struct ProbeEntry: Codable, Equatable {
    public var host: String
    public var ok: Bool
    public var port: Int?
    public var connectMs: Int?
    public var helloMs: Int?
    public var build: Int?
    public var error: String?

    /// The row state the list shows.
    public var outcome: ProbeOutcome {
        if ok, let port, let connectMs, let helloMs {
            return .ok(port: UInt16(clamping: port), connectMs: connectMs, helloMs: helloMs, build: build)
        }
        return .failed(error ?? "Test failed")
    }
}

public struct ProbeResultList: Codable { public var results: [ProbeEntry] }

/// What a connectivity test of one relay found, measured from this Mac.
public enum ProbeOutcome: Equatable {
    /// Chosen for the run but not started yet.
    case queued
    case testing
    /// A SoftEther server answered the protocol hello on `port`.
    case ok(port: UInt16, connectMs: Int, helloMs: Int, build: Int?)
    case failed(String)

    /// Ascending order = best first: working relays by connect time, then untested/in progress, then failed.
    public static func sortRank(_ o: ProbeOutcome?) -> Int {
        switch o {
        case .ok(_, let connectMs, _, _)?: return connectMs
        case .failed?: return Int.max
        case .queued?, .testing?, nil: return Int.max - 1
        }
    }

    public var isOK: Bool { if case .ok = self { return true }; return false }
}
