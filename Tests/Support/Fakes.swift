import Foundation
import VPNGateCore
import Darwin

final class FakeTun: TunDevice {
    let name: String
    var onPacket: (([UInt8]) -> Void)?
    var forwardIPv6 = false
    private let state = Locked((written: [[UInt8]](), closed: false, reading: false))
    var written: [[UInt8]] { state.value.written }
    var closed: Bool { state.value.closed }
    var reading: Bool { state.value.reading }
    init(name: String) { self.name = name }
    func startReading() { state.update { $0.reading = true } }
    func write(ipv4 packet: [UInt8]) { state.update { $0.written.append(packet) } }
    func close() { state.update { $0.closed = true } }
    func inject(_ packet: [UInt8]) { onPacket?(packet) }
}

final class RecordingRunner: CommandRunner {
    struct Rule { var contains: String; var status: Int32; var out: String }
    private let lock = NSLock()
    private var _log: [String] = []
    var rules: [Rule] = [Rule(contains: "route -n get default", status: 0,
                              out: "   route to: default\n    gateway: 192.168.1.1\n  interface: en0\n")]
    var log: [String] { lock.lock(); defer { lock.unlock() }; return _log }

    func run(_ path: String, _ args: [String]) -> (status: Int32, out: String) {
        let cmd = ([path] + args).joined(separator: " ")
        lock.lock(); _log.append(cmd)
        let rule = rules.first { cmd.contains($0.contains) }
        lock.unlock()
        return (rule?.status ?? 0, rule?.out ?? "")
    }

    /// Commands that start with the given prefix, e.g. "/sbin/route -n add".
    func commands(_ prefix: String) -> [String] { log.filter { $0.hasPrefix(prefix) } }
}

final class FakeDNS: DNSConfigurator {
    private let state = Locked((set: [[String]](), removed: 0))
    var setCalls: [[String]] { state.value.set }
    var removeCalls: Int { state.value.removed }
    private let ifaces = Locked([String]())
    var setInterfaces: [String] { ifaces.value }
    /// What `currentServers()` returns, i.e. the physical network's resolver(s) before the tunnel overrides them.
    var physicalServers: [String] = []
    func set(servers: [String], iface: String, address: String, router: String) -> Bool {
        state.update { $0.set.append(servers) }; ifaces.update { $0.append(iface) }; return true
    }
    func remove() { state.update { $0.removed += 1 } }
    func currentServers() -> [String] { physicalServers }
}

/// Transport double for session tests: handshake is instant unless gated, and DHCP/ARP is answered by `network`.
final class FakeTransport: VPNTransport {
    var onFrame: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?
    let host: String, port: UInt16
    var gate: Gate?
    var connectError: Error?
    var network: FakeNetworkServer
    var bypassHosts: [String] = []
    var remoteIPv4: String?
    private let state = Locked((closes: 0, sent: [[UInt8]](), connects: 0, bytesIn: UInt64(0), bytesOut: UInt64(0)))
    var closeCalls: Int { state.value.closes }
    var sent: [[UInt8]] { state.value.sent }
    var bytesIn: UInt64 { state.value.bytesIn }
    var bytesOut: UInt64 { state.value.bytesOut }

    init(host: String, port: UInt16, network: FakeNetworkServer) { self.host = host; self.port = port; self.network = network }

    func connect(log: (String) -> Void) async throws -> Welcome {
        state.update { $0.connects += 1 }
        if let g = gate { await g.wait() }
        if let e = connectError { throw e }
        return Welcome(sessionName: "SID-FAKE", connectionName: "CID", timeoutMs: 20000, message: nil)
    }

    func sendFrame(_ frame: [UInt8]) {
        state.update { $0.sent.append(frame); $0.bytesOut += UInt64(frame.count) }
        for r in network.handle(frame) {
            DispatchQueue.global().async { [weak self] in self?.onFrame?(r) }
        }
    }

    func close(_ error: Error?) {
        state.update { $0.closes += 1 }
        onClose?(error)
    }

    /// Simulates the server dropping the link.
    func drop(_ error: Error = StreamError.closed) { onClose?(error) }
}

/// Collects transports/tuns/nets that a session creates.
final class SessionHarness {
    let network = FakeNetworkServer()
    let transports = Locked([FakeTransport]())
    let tuns = Locked([FakeTun]())
    let nets = Locked([FakeNet]())
    let dnsProxies = Locked([DNSProxy]())
    let socksServers = Locked([SocksServer]())
    var gateFor: ((String) -> Gate?)?
    var connectErrorFor: ((String, UInt16) -> Error?)?
    var tunError: Error?
    var bypassHostsFor: [String] = []
    var remoteIPv4For: ((String) -> String?)?

    func deps() -> SessionDependencies {
        var d = SessionDependencies()
        d.makeTransport = { [unowned self] host, port, _ in
            let t = FakeTransport(host: host, port: port, network: self.network)
            t.gate = self.gateFor?(host)
            t.connectError = self.connectErrorFor?(host, port)
            t.bypassHosts = self.bypassHostsFor
            t.remoteIPv4 = self.remoteIPv4For?(host)
            self.transports.update { $0.append(t) }
            return t
        }
        d.makeTun = { [unowned self] in
            if let e = self.tunError { throw e }
            let t = FakeTun(name: "utunF\(self.tuns.value.count)")
            self.tuns.update { $0.append(t) }
            return t
        }
        d.makeNet = { [unowned self] in
            let n = FakeNet(); self.nets.update { $0.append(n) }; return n
        }
        // Port 0: the OS picks an unused, unprivileged port, so the proxy can really bind/listen without root.
        d.makeDNSProxy = { [unowned self] net in
            let p = DNSProxy(net: net, settings: DNSProxy.Settings(listenAddress: "127.0.0.1", port: 0))
            self.dnsProxies.update { $0.append(p) }
            return p
        }
        d.makeSocks = { [unowned self] port, _, _ in
            let s = SocksServer(port: port, connector: LoopbackConnector())
            self.socksServers.update { $0.append(s) }
            return s
        }
        return d
    }

    var fastTiming: SessionTiming {
        var t = SessionTiming()
        t.reconnectDelay = 0.05
        t.bridge = BridgeTiming(dhcpTimeout: 0.5, dhcpRetries: 2)
        return t
    }
}

final class FakeNet: NetConfiguring {
    private let state = Locked((applied: [(iface: String, host: String)](), torn: 0, ipv6: [Bool](), mtuOverrides: [Int?]()))
    var applied: [(iface: String, host: String)] { state.value.applied }
    var ipv6Flags: [Bool] { state.value.ipv6 }
    var mtuOverrides: [Int?] { state.value.mtuOverrides }
    var tornDown: Int { state.value.torn }
    private let routingApplied = Locked([RoutingConfig?]())
    var routingConfigsApplied: [RoutingConfig?] { routingApplied.value }
    func apply(iface: String, lease: Lease, bypassHost: String, blockIPv6: Bool, mtuOverride: Int?, routing: RoutingConfig?,
              dnsProxyAddress: String?) throws {
        state.update { $0.applied.append((iface, bypassHost)); $0.ipv6.append(blockIPv6); $0.mtuOverrides.append(mtuOverride) }
        routingApplied.update { $0.append(routing) }
    }
    func teardown() { state.update { $0.torn += 1 } }
    private let socksApplied = Locked([String]())
    var socksIfaces: [String] { socksApplied.value }
    func applySocks(iface: String, lease: Lease, mtuOverride: Int?) throws { socksApplied.update { $0.append(iface) } }
    private let extra = Locked([String]())
    var bypassed: [String] { extra.value }
    func addBypass(host: String) { extra.update { $0.append(host) } }
    private let v6 = Locked([[UInt8]]())
    var ipv6Addresses: [[UInt8]] { v6.value }
    func configureIPv6(address: [UInt8], prefixLength: Int) { v6.update { $0.append(address) } }
    private let dynamicRules = Locked([(ip: String, action: RoutingAction)]())
    var dynamicRulesApplied: [(ip: String, action: RoutingAction)] { dynamicRules.value }
    func applyDynamicRule(ip: String, action: RoutingAction) { dynamicRules.update { $0.append((ip, action)) } }
}

final class FakeSession: SessionControlling, @unchecked Sendable {
    var emit: ((HelperEvent) -> Void)?
    var snapshot = HelperEvent(state: .disconnected)
    private let state = Locked((connects: [(host: String, port: Int?)](), disconnects: 0, blockIPv6: [Bool](), configs: [ConnectConfig](), autoReconnects: [Bool](), portLists: [[Int]?]()))
    var connects: [(host: String, port: Int?)] { state.value.connects }
    var blockIPv6Flags: [Bool] { state.value.blockIPv6 }
    var autoReconnects: [Bool] { state.value.autoReconnects }
    var portLists: [[Int]?] { state.value.portLists }
    var disconnects: Int { state.value.disconnects }
    var configs: [ConnectConfig] { state.value.configs }

    func connect(config: ConnectConfig) {
        state.update {
            $0.connects.append((config.host, config.ports.first))
            $0.blockIPv6.append(config.blockIPv6)
            $0.configs.append(config)
        }
    }
    func connect(host: String, port: Int?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool) {
        connect(host: host, port: port, ports: nil, proxy: proxy, autoReconnect: autoReconnect, blockIPv6: blockIPv6, routing: nil)
    }
    func connect(host: String, port: Int?, ports: [Int]?, proxy: ProxySettings, autoReconnect: Bool, blockIPv6: Bool, routing: RoutingConfig?) {
        state.update { $0.connects.append((host, port)); $0.blockIPv6.append(blockIPv6); $0.autoReconnects.append(autoReconnect); $0.portLists.append(ports) }
    }
    func disconnect() { state.update { $0.disconnects += 1 } }
}

// MARK: helpers

func threadCount() -> Int {
    var list: thread_act_array_t?
    var count = mach_msg_type_number_t(0)
    guard task_threads(mach_task_self_, &list, &count) == KERN_SUCCESS, let l = list else { return -1 }
    vm_deallocate(mach_task_self_, vm_address_t(UInt(bitPattern: l)), vm_size_t(Int(count) * MemoryLayout<thread_t>.size))
    return Int(count)
}

func tempPath(_ name: String) -> String {
    let dir = NSTemporaryDirectory() + "vpngate-tests-\(getpid())"
    try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
    return dir + "/" + name
}

func fixture(_ name: String, file: String = #filePath) -> String {
    let root = URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
    return (try? String(contentsOf: root.appendingPathComponent("Fixtures/" + name), encoding: .utf8)) ?? ""
}

func fixtureData(_ name: String, file: String = #filePath) -> Data {
    let root = URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
    return (try? Data(contentsOf: root.appendingPathComponent("Fixtures/" + name))) ?? Data()
}

/// Runs a DHCP exchange through the fake network and returns the lease.
func wire(_ bridge: EthernetBridge, to net: FakeNetworkServer) {
    bridge.sendFrame = { [weak bridge] f in
        for r in net.handle(f) { bridge?.fromHub(r) }
    }
}

// UserDefaults is documented thread-safe but older SDKs do not say so; the tests hand throwaway suites to @Sendable closures.
extension UserDefaults: @unchecked @retroactive Sendable {}
// UdpAccel guards all of its state with its own lock; the concurrency tests call it from several threads on purpose.
extension UdpAccel: @unchecked Sendable {}
