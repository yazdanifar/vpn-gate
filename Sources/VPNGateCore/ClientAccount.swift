import Foundation

public enum AccountAuthType: String, Codable, CaseIterable {
    case anonymous = "Anonymous"
    case password = "Standard Password (SHA-0)"
    case plainPassword = "Plain Password"
    case certificate = "User Certificate"
}

/// SoftEther VPN Client account configuration (Connection Setting).
/// Reference: SoftEther VPN Client Manager / Windows client settings.
public struct ClientAccount: Identifiable, Codable, Equatable, Hashable {
    public var id: UUID
    public var name: String
    public var host: String
    public var portList: [UInt16]
    public var hub: String
    public var username: String
    public var authType: AccountAuthType
    public var proxy: ProxySettings
    public var checkServerCert: Bool
    public var serverCertFingerprint: String?
    public var maxConnection: Int
    /// Reserved: stored for compatibility with SoftEther account files but not used by the helper (not shown in the UI).
    public var halfConnection: Bool
    public var compression: Bool
    public var udpAcceleration: Bool
    /// "Disable QoS" of the SoftEther Client Manager; false (default) = QoS on, as the stock client.
    public var disableQoS: Bool
    public var autoReconnect: Bool
    /// Seconds between reconnect attempts, and how many consecutive failures before giving up, for this
    /// connection (the SoftEther Client Manager's own per-setting policy). VPN Gate connections ignore both:
    /// the app retries those itself, forever, every 15 s (AppModel.considerReconnect).
    public var reconnectInterval: TimeInterval
    public var reconnectCount: Int
    public var virtualMacAddress: String?
    /// Reserved: the tunnel MTU comes from the DHCP lease (option 26), not from here.
    public var mtu: Int?
    public var createdAt: Date
    public var updatedAt: Date

    public init(
        id: UUID = UUID(),
        name: String,
        host: String,
        portList: [UInt16] = [443, 992, 5555, 1194],
        hub: String = "DEFAULT",
        username: String = "",
        authType: AccountAuthType = .password,
        proxy: ProxySettings = ProxySettings(),
        checkServerCert: Bool = false,
        serverCertFingerprint: String? = nil,
        maxConnection: Int = 1,
        halfConnection: Bool = false,
        compression: Bool = false,
        udpAcceleration: Bool = true,
        disableQoS: Bool = false,
        autoReconnect: Bool = true,
        reconnectInterval: TimeInterval = 3.0,
        reconnectCount: Int = 8,
        virtualMacAddress: String? = nil,
        mtu: Int? = 1500,
        createdAt: Date = Date(),
        updatedAt: Date = Date()
    ) {
        self.id = id
        self.name = name
        self.host = host
        self.portList = portList.isEmpty ? [443] : portList
        self.hub = hub
        self.username = username
        self.authType = authType
        self.proxy = proxy
        self.checkServerCert = checkServerCert
        self.serverCertFingerprint = serverCertFingerprint
        self.maxConnection = max(1, min(maxConnection, 32))
        self.halfConnection = halfConnection
        self.compression = compression
        self.udpAcceleration = udpAcceleration
        self.disableQoS = disableQoS
        self.autoReconnect = autoReconnect
        self.reconnectInterval = reconnectInterval
        self.reconnectCount = reconnectCount
        self.virtualMacAddress = virtualMacAddress
        self.mtu = mtu
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    // MARK: Codable (tolerant: older or newer files must load; the proxy password never reaches the file).
    // Old files may still carry the invented `hideFromVpnGateList` key (the Windows client has no such field):
    // it is simply ignored on load and never written.

    private enum CodingKeys: String, CodingKey {
        case id, name, host, portList, hub, username, authType, proxy, checkServerCert, serverCertFingerprint
        case maxConnection, halfConnection, compression, udpAcceleration, disableQoS, autoReconnect, reconnectInterval
        case reconnectCount, virtualMacAddress, mtu, createdAt, updatedAt
    }

    /// Only `id`, `name` and `host` are required; every other field falls back to its default when missing.
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let now = Date()
        self.init(
            id: try c.decode(UUID.self, forKey: .id),
            name: try c.decode(String.self, forKey: .name),
            host: try c.decode(String.self, forKey: .host),
            portList: try c.decodeIfPresent([UInt16].self, forKey: .portList) ?? [443, 992, 5555, 1194],
            hub: try c.decodeIfPresent(String.self, forKey: .hub) ?? "DEFAULT",
            username: try c.decodeIfPresent(String.self, forKey: .username) ?? "",
            authType: try c.decodeIfPresent(AccountAuthType.self, forKey: .authType) ?? .password,
            proxy: try c.decodeIfPresent(ProxySettings.self, forKey: .proxy) ?? ProxySettings(),
            checkServerCert: try c.decodeIfPresent(Bool.self, forKey: .checkServerCert) ?? false,
            serverCertFingerprint: try c.decodeIfPresent(String.self, forKey: .serverCertFingerprint),
            maxConnection: try c.decodeIfPresent(Int.self, forKey: .maxConnection) ?? 1,
            halfConnection: try c.decodeIfPresent(Bool.self, forKey: .halfConnection) ?? false,
            compression: try c.decodeIfPresent(Bool.self, forKey: .compression) ?? false,
            udpAcceleration: try c.decodeIfPresent(Bool.self, forKey: .udpAcceleration) ?? true,
            disableQoS: try c.decodeIfPresent(Bool.self, forKey: .disableQoS) ?? false,
            autoReconnect: try c.decodeIfPresent(Bool.self, forKey: .autoReconnect) ?? true,
            reconnectInterval: try c.decodeIfPresent(TimeInterval.self, forKey: .reconnectInterval) ?? 3.0,
            reconnectCount: try c.decodeIfPresent(Int.self, forKey: .reconnectCount) ?? 8,
            virtualMacAddress: try c.decodeIfPresent(String.self, forKey: .virtualMacAddress),
            mtu: try c.decodeIfPresent(Int.self, forKey: .mtu) ?? 1500,
            createdAt: try c.decodeIfPresent(Date.self, forKey: .createdAt) ?? now,
            updatedAt: try c.decodeIfPresent(Date.self, forKey: .updatedAt) ?? now
        )
    }

    /// The proxy password is a secret: the app keeps it in the Keychain and it is never written to the accounts file.
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id); try c.encode(name, forKey: .name); try c.encode(host, forKey: .host)
        try c.encode(portList, forKey: .portList); try c.encode(hub, forKey: .hub)
        try c.encode(username, forKey: .username); try c.encode(authType, forKey: .authType)
        var safeProxy = proxy; safeProxy.password = nil
        try c.encode(safeProxy, forKey: .proxy)
        try c.encode(checkServerCert, forKey: .checkServerCert)
        try c.encodeIfPresent(serverCertFingerprint, forKey: .serverCertFingerprint)
        try c.encode(maxConnection, forKey: .maxConnection); try c.encode(halfConnection, forKey: .halfConnection)
        try c.encode(compression, forKey: .compression); try c.encode(udpAcceleration, forKey: .udpAcceleration)
        try c.encode(disableQoS, forKey: .disableQoS)
        try c.encode(autoReconnect, forKey: .autoReconnect)
        try c.encode(reconnectInterval, forKey: .reconnectInterval); try c.encode(reconnectCount, forKey: .reconnectCount)
        try c.encodeIfPresent(virtualMacAddress, forKey: .virtualMacAddress)
        try c.encodeIfPresent(mtu, forKey: .mtu)
        try c.encode(createdAt, forKey: .createdAt); try c.encode(updatedAt, forKey: .updatedAt)
    }

    /// Converts this account into a ConnectConfig suitable for IPC transmission to the helper.
    public func toConnectConfig(
        password: String? = nil,
        certDer: Data? = nil,
        privateKeyDer: Data? = nil,
        blockIPv6: Bool = true
    ) -> ConnectConfig {
        ConnectConfig(
            host: host,
            ports: portList.map(Int.init),
            hubName: hub,
            userName: username,
            authType: authType.rawValue,
            password: password,
            certDer: certDer,
            privateKeyDer: privateKeyDer,
            ticket: nil,
            proxy: proxy,
            maxConnection: maxConnection,
            useCompress: compression,
            useUdpAccel: udpAcceleration,
            disableQoS: disableQoS,
            autoReconnect: autoReconnect,
            reconnectInterval: reconnectInterval,
            reconnectCount: reconnectCount,
            blockIPv6: blockIPv6,
            checkServerCert: checkServerCert,
            serverCertFingerprint: serverCertFingerprint,
            mtu: mtu
        )
    }
}
