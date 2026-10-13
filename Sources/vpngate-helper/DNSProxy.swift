import Foundation
import Darwin
import VPNGateCore

/// Sends one DNS query to one upstream server and waits for the reply. A protocol so `DNSProxy`'s routing
/// decision can be tested without a real socket.
protocol DNSUpstream {
    func query(_ message: [UInt8], server: String, timeoutMs: Int32) -> [UInt8]?
}

/// A plain UDP DNS client: one query, one answer, no retries (the OS resolver that's asking us will retry).
struct SystemDNSUpstream: DNSUpstream {
    /// When set, the query leaves through this interface only (`IP_BOUND_IF`), whatever the routing table says.
    var boundInterface: UInt32?

    func query(_ message: [UInt8], server: String, timeoutMs: Int32) -> [UInt8]? {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { return nil }
        defer { Darwin.close(fd) }
        if var idx = boundInterface {
            guard setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0 else { return nil }
        }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = in_port_t(53).bigEndian
        guard inet_pton(AF_INET, server, &addr.sin_addr) == 1 else { return nil }
        let sent = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                message.withUnsafeBytes { buf in sendto(fd, buf.baseAddress, buf.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        }
        guard sent > 0 else { return nil }
        var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&pfd, 1, timeoutMs) > 0, pfd.revents & Int16(POLLIN) != 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = recv(fd, &buf, buf.count, 0)
        guard n > 0 else { return nil }
        return Array(buf[0..<n])
    }
}

/// Resolves DNS the way the user's routing rules say to: a domain explicitly marked `.direct` is asked of the
/// physical network's own resolver (never the tunnel's), `.block` gets NXDOMAIN with no query sent anywhere,
/// and everything else (the default, `.proxy`) goes to the tunnel's own resolver — so nothing but `.direct`
/// domains ever reaches an ISP-controlled resolver. Every resolved address is also handed to `NetConfiguring`
/// so the matching route exists before the answer reaches the asking app.
final class DNSProxy {
    struct Settings { var listenAddress = "127.0.0.1"; var port: UInt16 = 53; var timeoutMs: Int32 = 4000 }

    private let upstream: DNSUpstream
    private let net: NetConfiguring
    private let settings: Settings
    private let lock = NSLock()
    private var listenFD: Int32 = -1
    private var running = false

    var routing = RoutingConfig()
    var tunnelDNSServers: [String] = []
    var directDNSServers: [String] = []

    init(net: NetConfiguring, upstream: DNSUpstream = SystemDNSUpstream(), settings: Settings = Settings()) {
        self.net = net; self.upstream = upstream; self.settings = settings
    }

    /// The decision-and-forward logic for one query, with no socket involved — the part that is unit-tested.
    func handle(_ query: [UInt8]) -> [UInt8] {
        // A query this helper cannot even parse the name of must never be guessed at: fail closed.
        guard let name = DNSMessage.queryName(query) else { return DNSMessage.servfailResponse(for: query) }
        let rule = RoutingMatcher.match(domain: name, in: routing)
        if rule?.action == .block { return DNSMessage.blockedResponse(for: query) }
        let servers = rule?.action == .direct ? directDNSServers : tunnelDNSServers
        guard let server = servers.first else { return DNSMessage.servfailResponse(for: query) }
        guard let response = upstream.query(query, server: server, timeoutMs: settings.timeoutMs) else {
            return DNSMessage.servfailResponse(for: query)
        }
        // Only for an address a rule explicitly decided on — the structural routes (full capture, or its
        // absence with `defaultAction: .direct`) already do the right thing for everything else.
        if let rule = rule {
            for ip in DNSMessage.resolvedIPv4Addresses(response) { net.applyDynamicRule(ip: ip, action: rule.action) }
        }
        return response
    }

    var isListening: Bool { lock.lock(); defer { lock.unlock() }; return running }

    func start() throws {
        let fd = socket(AF_INET, SOCK_DGRAM, 0)
        guard fd >= 0 else { throw UtunError.failed("dns proxy socket") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = settings.port.bigEndian
        guard inet_pton(AF_INET, settings.listenAddress, &addr.sin_addr) == 1 else {
            Darwin.close(fd); throw UtunError.failed("dns proxy: bad listen address")
        }
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else {
            let msg = String(cString: strerror(errno)); Darwin.close(fd)
            throw UtunError.failed("dns proxy bind \(settings.listenAddress):\(settings.port): \(msg)")
        }
        lock.lock(); listenFD = fd; running = true; lock.unlock()
        Thread.detachNewThread { [self] in serve(fd) }
    }

    private func serve(_ fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 4096)
        while isListening {
            var clientAddr = sockaddr_in()
            var len = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &clientAddr) { p in
                p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in recvfrom(fd, &buf, buf.count, 0, sa, &len) }
            }
            guard n > 0 else { if isListening { continue } else { return } }
            let query = Array(buf[0..<n])
            Thread.detachNewThread { [self] in
                let response = handle(query)
                var addr = clientAddr
                _ = withUnsafePointer(to: &addr) { p in
                    p.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                        response.withUnsafeBytes { b in sendto(fd, b.baseAddress, b.count, 0, sa, socklen_t(MemoryLayout<sockaddr_in>.size)) }
                    }
                }
            }
        }
    }

    func stop() {
        lock.lock(); running = false; let fd = listenFD; listenFD = -1; lock.unlock()
        if fd >= 0 { Darwin.shutdown(fd, SHUT_RDWR); Darwin.close(fd) }
    }
}
