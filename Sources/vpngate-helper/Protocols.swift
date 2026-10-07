import Foundation
import VPNGateCore

/// An established-or-establishing link to a VPN Gate relay, as seen by the session.
protocol VPNTransport: AnyObject {
    var onFrame: (([UInt8]) -> Void)? { get set }
    var onClose: ((Error?) -> Void)? { get set }
    var bytesIn: UInt64 { get }
    var bytesOut: UInt64 { get }
    func connect(log: (String) -> Void) async throws -> Welcome
    func sendFrame(_ frame: [UInt8])
    func close(_ error: Error?)
}

extension VPNTransport {
    func close() { close(nil) }
}

protocol TunDevice: AnyObject {
    var name: String { get }
    var onPacket: (([UInt8]) -> Void)? { get set }
    func startReading()
    func write(ipv4 packet: [UInt8])
    func close()
}

protocol CommandRunner {
    @discardableResult
    func run(_ path: String, _ args: [String]) -> (status: Int32, out: String)
}

protocol DNSConfigurator {
    /// Makes the tunnel the primary DNS resolver while connected.
    func set(servers: [String], iface: String, address: String, router: String) -> Bool
    func remove()
}

protocol NetConfiguring: AnyObject {
    func apply(iface: String, lease: Lease, bypassHost: String, blockIPv6: Bool) throws
    func teardown()
}

/// What the IPC layer needs from a session.
protocol SessionControlling: AnyObject {
    var emit: ((HelperEvent) -> Void)? { get set }
    var snapshot: HelperEvent { get }
    func connect(config: ConnectConfig)
    func connect(host: String, port: Int?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool)
    func connect(host: String, port: Int?, ports: [Int]?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool)
    func disconnect()
}
