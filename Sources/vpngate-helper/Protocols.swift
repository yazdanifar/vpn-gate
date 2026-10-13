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
    /// The resolver(s) in effect right before `set()` overrides them (the physical network's own DNS); used to
    /// resolve domains a routing rule marks `.direct` without ever asking the tunnel's resolver.
    func currentServers() -> [String]
}

extension DNSConfigurator {
    func currentServers() -> [String] { [] }
}

protocol NetConfiguring: AnyObject {
    /// `dnsProxyAddress`, when given, is published as the system's resolver instead of the DHCP lease's own DNS
    /// (the caller has a `DNSProxy` already listening there; domain routing rules need one to work at all).
    func apply(iface: String, lease: Lease, bypassHost: String, blockIPv6: Bool, mtuOverride: Int?, routing: RoutingConfig?,
              dnsProxyAddress: String?) throws
    /// Adds a host route around the tunnel for a further peer (redirect target, UDP acceleration endpoint); removed by `teardown()`.
    func addBypass(host: String)
    /// Puts the SLAAC address learned from a Router Advertisement on the tunnel interface (only used when IPv6 is not blocked).
    func configureIPv6(address: [UInt8], prefixLength: Int)
    /// Routes one resolved address according to a domain rule's action (called by the DNS proxy once it has an
    /// answer); overrides whatever the static capture set up by `apply` would otherwise do with it.
    func applyDynamicRule(ip: String, action: RoutingAction)
    /// The physical network's own DNS servers, captured just before `apply` pointed the system at the tunnel's
    /// resolver; used to resolve `.direct` domains without ever asking the tunnel's (or the hub's) resolver.
    func directDNSServers() -> [String]
    /// SOCKS mode: gives the tunnel interface its address and a default route that only sockets bound to that
    /// interface can use (`route -ifscope`). The system's own default route, DNS and IPv6 are left untouched.
    func applySocks(iface: String, lease: Lease, mtuOverride: Int?) throws
    func teardown()
}

extension NetConfiguring {
    func applySocks(iface: String, lease: Lease, mtuOverride: Int?) throws {}
    func addBypass(host: String) {}
    func configureIPv6(address: [UInt8], prefixLength: Int) {}
    func applyDynamicRule(ip: String, action: RoutingAction) {}
    func directDNSServers() -> [String] { [] }
}

/// What the IPC layer needs from a session.
protocol SessionControlling: AnyObject {
    var emit: ((HelperEvent) -> Void)? { get set }
    var snapshot: HelperEvent { get }
    func connect(config: ConnectConfig)
    func connect(host: String, port: Int?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool)
    func connect(host: String, port: Int?, ports: [Int]?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool, routing: RoutingConfig?)
    func connect(host: String, port: Int?, ports: [Int]?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool, routing: RoutingConfig?,
                 tunnelMode: TunnelMode, socksPort: Int)
    func disconnect()
}

extension SessionControlling {
    func connect(host: String, port: Int?, ports: [Int]?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool, routing: RoutingConfig?,
                 tunnelMode: TunnelMode, socksPort: Int) {
        connect(host: host, port: port, ports: ports, proxy: proxy, autoReconnect: autoReconnect, blockIPv6: blockIPv6, routing: routing)
    }
}
