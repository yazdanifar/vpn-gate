import Foundation

public let helperSocketPath = "/var/run/vpngate-mac.sock"
/// Bumped whenever the helper's behaviour or IPC changes; the app offers to reinstall an outdated helper.
public let helperVersion = 4

public enum ConnectionState: String, Codable {
    case disconnected, connecting, authenticating, dhcp, connected, reconnecting
}

public struct ProxySettings: Codable, Equatable {
    public enum Kind: String, Codable { case none, http, socks5 }
    public var kind: Kind = .none
    public var host = ""
    public var port = 0
    public var username: String?
    public var password: String?
    public init() {}
}

public struct HelperRequest: Codable {
    public var cmd: String            // connect | disconnect | status
    public var host: String?
    public var port: Int?
    public var proxy: ProxySettings?
    public var autoReconnect: Bool?
    public var blockIPv6: Bool?
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
