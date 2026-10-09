import Foundation
import VPNGateCore

/// An established-or-establishing link to a VPN Gate relay, as seen by the session.
protocol VPNTransport: AnyObject {
    var onFrame: (([UInt8]) -> Void)? { get set }
    var onClose: ((Error?) -> Void)? { get set }
    var bytesIn: UInt64 { get }
    var bytesOut: UInt64 { get }
    func connect(log: (String) -> Void) async throws -> Welcome
    /// Peers the data path talks to directly (after cluster redirects, plus the UDP endpoint); they need routes around a full tunnel.
    var bypassHosts: [String] { get }
    /// IPv4 address of the TCP/TLS peer the data really flows to (nil behind a proxy or when unknown).
    var remoteIPv4: String? { get }
    func sendFrame(_ frame: [UInt8])
    func close(_ error: Error?)
}

extension VPNTransport {
    var bypassHosts: [String] { [] }
    var remoteIPv4: String? { nil }
    func close() { close(nil) }
}

protocol TunDevice: AnyObject {
    var name: String { get }
    var onPacket: (([UInt8]) -> Void)? { get set }
    func startReading()
    func write(ipv4 packet: [UInt8])
    func write(ipv6 packet: [UInt8])
    /// Hand IPv6 packets from the host to `onPacket` as well (they are dropped otherwise). Set before `startReading()`.
    var forwardIPv6: Bool { get set }
    func close()
}

extension TunDevice {
    func write(ipv6 packet: [UInt8]) {}
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
    /// Adds a host route around the tunnel for a further peer (redirect target, UDP acceleration endpoint); removed by `teardown()`.
    func addBypass(host: String)
    /// Puts the SLAAC address learned from a Router Advertisement on the tunnel interface (only used when IPv6 is not blocked).
    func configureIPv6(address: [UInt8], prefixLength: Int)
    func teardown()
}

extension NetConfiguring {
    func addBypass(host: String) {}
    func configureIPv6(address: [UInt8], prefixLength: Int) {}
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
