import Foundation

public let helperSocketPath = "/var/run/vpngate-mac.sock"
/// Bumped whenever the helper's behaviour or IPC changes; the app offers to reinstall an outdated helper.
public let helperVersion = 6

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

/// Full configuration for establishing a SoftEther session (general accounts or VPN Gate relays).
public struct ConnectConfig: Codable, Equatable {
    public var host: String
    public var ports: [Int]
    public var hubName: String
    public var userName: String
    public var authType: String              // anonymous, password, plain, cert, ticket
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
        virtualMacAddress: String? = nil
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
            virtualMacAddress: try c.decodeIfPresent(String.self, forKey: .virtualMacAddress)
        )
    }
}

public struct HelperRequest: Codable {
    public var cmd: String            // connect | disconnect | status
    public var host: String?
    public var port: Int?
    public var ports: [Int]?
    public var proxy: ProxySettings?
    public var autoReconnect: Bool?
    public var blockIPv6: Bool?
    public var config: ConnectConfig?
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
    public init(state: ConnectionState) { self.state = state }
}
