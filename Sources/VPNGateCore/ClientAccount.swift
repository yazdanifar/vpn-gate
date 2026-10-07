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
    public var halfConnection: Bool
    public var compression: Bool
    public var udpAcceleration: Bool
    public var autoReconnect: Bool
    public var reconnectInterval: TimeInterval
    public var reconnectCount: Int
    public var hideFromVpnGateList: Bool
    public var virtualMacAddress: String?
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
        maxConnection: Int = 8,
        halfConnection: Bool = false,
        compression: Bool = false,
        udpAcceleration: Bool = true,
        autoReconnect: Bool = true,
        reconnectInterval: TimeInterval = 3.0,
        reconnectCount: Int = 8,
        hideFromVpnGateList: Bool = false,
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
        self.autoReconnect = autoReconnect
        self.reconnectInterval = reconnectInterval
        self.reconnectCount = reconnectCount
        self.hideFromVpnGateList = hideFromVpnGateList
        self.virtualMacAddress = virtualMacAddress
        self.mtu = mtu
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }

    /// Converts this account into a ConnectConfig suitable for IPC transmission to the helper.
    public func toConnectConfig(
        password: String? = nil,
        certDer: Data? = nil,
        certSignData: Data? = nil,
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
            certSignData: certSignData,
            ticket: nil,
            proxy: proxy,
            maxConnection: maxConnection,
            useCompress: compression,
            useUdpAccel: udpAcceleration,
            autoReconnect: autoReconnect,
            blockIPv6: blockIPv6,
            checkServerCert: checkServerCert,
            serverCertFingerprint: serverCertFingerprint,
            mtu: mtu
        )
    }
}
