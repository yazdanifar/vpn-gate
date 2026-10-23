import Darwin
import Foundation
import VPNGateCore

/// Opens the outbound half of a proxied connection. A protocol so the SOCKS server can be tested on loopback.
protocol SocksConnector {
    /// A connected, blocking TCP socket to `host:port`, or the SOCKS5 reply code (RFC 1928 §6) explaining why not.
    func connect(host: String, port: UInt16) -> Result<Int32, SocksServer.Failure>
}

/// Connects through the VPN without touching the system's routes: each socket is bound to the utun interface
/// (`IP_BOUND_IF`), so only it follows the interface-scoped default route `NetConfig.applySocks` installed. Host
/// names are resolved by the VPN's own resolver over the same bound path, so a name is never looked up outside it.
struct TunnelConnector: SocksConnector {
    var interfaceIndex: UInt32
    var dnsServers: [String]
    var upstream: DNSUpstream
    var connectTimeoutMs: Int32 = 10_000

    func connect(host: String, port: UInt16) -> Result<Int32, SocksServer.Failure> {
        let address: String
        if InputValidation.isIPv4Literal(host) {
            address = host
        } else {
            guard let resolved = resolve(host) else { return .failure(.hostUnreachable) }
            address = resolved
        }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        guard inet_pton(AF_INET, address, &addr.sin_addr) == 1 else { return .failure(.addressTypeUnsupported) }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return .failure(.generalFailure) }
        var idx = interfaceIndex
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        guard setsockopt(fd, IPPROTO_IP, IP_BOUND_IF, &idx, socklen_t(MemoryLayout<UInt32>.size)) == 0 else {
            Darwin.close(fd); return .failure(.generalFailure)
        }
        return SocksServer.connect(fd, to: &addr, timeoutMs: connectTimeoutMs)
    }

    private func resolve(_ name: String) -> String? {
        for server in dnsServers {
            let query = DNSMessage.aQuery(name: name, id: UInt16.random(in: 1...UInt16.max))
            if let response = upstream.query(query, server: server, timeoutMs: 4000),
                let first = DNSMessage.resolvedIPv4Addresses(response).first
            {
                return first
            }
        }
        return nil
    }
}

/// A minimal SOCKS5 server (RFC 1928): no authentication, CONNECT only, IPv4 and host-name destinations. It listens
/// on loopback only; any process on this Mac can use it while it runs.
final class SocksServer {
    enum Failure: UInt8, Error {
        case generalFailure = 1, networkUnreachable = 3, hostUnreachable = 4, connectionRefused = 5
        case commandUnsupported = 7, addressTypeUnsupported = 8
    }

    static let maxClients = 256
    static let handshakeTimeoutSeconds = 15

    private let connector: SocksConnector
    private let port: UInt16
    private let lock = NSLock()
    private var listenFD: Int32 = -1
    private var running = false
    private var live = Set<Int32>()
    private let loopExited = DispatchSemaphore(value: 0)

    init(port: UInt16, connector: SocksConnector) { self.port = port; self.connector = connector }

    var isListening: Bool { lock.withLock { running } }

    /// Port actually bound (differs from `port` only when that was 0, which tests use for an ephemeral port).
    private(set) var boundPort: UInt16 = 0

    func start() throws {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw UtunError.failed("socks proxy socket") }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = UInt32(INADDR_LOOPBACK).bigEndian
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0, listen(fd, 64) == 0 else {
            let msg = String(cString: strerror(errno)); Darwin.close(fd)
            throw UtunError.failed("SOCKS proxy cannot listen on 127.0.0.1:\(port): \(msg)")
        }
        var bound = sockaddr_in(); var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &bound) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) } }
        boundPort = UInt16(bigEndian: bound.sin_port)
        _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK)
        lock.withLock {
            listenFD = fd; running = true
        }
        Thread.detachNewThread { [self] in acceptLoop(fd) }
    }

    /// Returns once the listening socket is closed (the accept loop owns and closes it), so the port can be re-bound.
    func stop() {
        let wasRunning: Bool = lock.withLock {
            let w = running; running = false; listenFD = -1
            // Under the lock, so a finishing relay cannot close and recycle a descriptor between snapshot and shutdown.
            for c in live { Darwin.shutdown(c, SHUT_RDWR) }  // the relay threads notice and close their own sockets
            return w
        }
        if wasRunning { _ = loopExited.wait(timeout: .now() + 2) }
    }

    private func acceptLoop(_ fd: Int32) {
        defer { Darwin.close(fd); loopExited.signal() }
        while isListening {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            if poll(&pfd, 1, 100) <= 0 { continue }  // wakes regularly to notice stop()
            let c = accept(fd, nil, nil)
            if c < 0 { continue }
            _ = fcntl(c, F_SETFL, fcntl(c, F_GETFL) & ~O_NONBLOCK)
            let admitted: Bool = lock.withLock {
                guard running, live.count < Self.maxClients else { return false }
                live.insert(c); return true
            }
            guard admitted else { Darwin.close(c); continue }
            Thread.detachNewThread { [self] in
                serve(c)
                lock.withLock { _ = live.remove(c) }
                Darwin.close(c)
            }
        }
    }

    // MARK: one client

    private func serve(_ c: Int32) {
        var one: Int32 = 1
        setsockopt(c, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: Self.handshakeTimeoutSeconds, tv_usec: 0)
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        guard let (host, port) = negotiate(c) else { return }
        switch connector.connect(host: host, port: port) {
        case .failure(let f):
            _ = reply(c, f.rawValue)
        case .success(let out):
            defer { Darwin.close(out) }
            guard reply(c, 0) else { return }
            var none = timeval(tv_sec: 0, tv_usec: 0)  // an idle established connection is fine
            setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &none, socklen_t(MemoryLayout<timeval>.size))
            lock.withLock { _ = live.insert(out) }
            relay(c, out)
            lock.withLock { _ = live.remove(out) }
        }
    }

    /// Greeting + request. Returns the destination, or nil after answering with the right failure.
    private func negotiate(_ c: Int32) -> (String, UInt16)? {
        guard let head = Self.readExactly(c, 2), head[0] == 5, head[1] > 0,
            let methods = Self.readExactly(c, Int(head[1]))
        else { return nil }
        guard methods.contains(0) else { _ = Self.writeAll(c, [5, 0xFF]); return nil }
        guard Self.writeAll(c, [5, 0]) else { return nil }
        guard let req = Self.readExactly(c, 4), req[0] == 5 else { return nil }
        guard req[1] == 1 else { _ = reply(c, Failure.commandUnsupported.rawValue); return nil }
        let host: String
        switch req[3] {
        case 1:
            guard let a = Self.readExactly(c, 4) else { return nil }
            host = a.map(String.init).joined(separator: ".")
        case 3:
            guard let n = Self.readExactly(c, 1), n[0] > 0, let name = Self.readExactly(c, Int(n[0])) else { return nil }
            host = String(decoding: name, as: UTF8.self)
            // Only a plain DNS name may continue: it ends up in a resolver query.
            guard InputValidation.isValidHost(host) else { _ = reply(c, Failure.hostUnreachable.rawValue); return nil }
        default:
            _ = reply(c, Failure.addressTypeUnsupported.rawValue); return nil  // IPv6 is not carried
        }
        guard let p = Self.readExactly(c, 2) else { return nil }
        return (host, UInt16(p[0]) << 8 | UInt16(p[1]))
    }

    private func reply(_ c: Int32, _ code: UInt8) -> Bool { Self.writeAll(c, [5, code, 0, 1, 0, 0, 0, 0, 0, 0]) }

    /// Copies both ways until each side has finished (one thread per direction, so a full buffer in one direction
    /// never stalls the other); a half-close on one side is passed on to the other.
    private func relay(_ a: Int32, _ b: Int32) {
        let done = DispatchSemaphore(value: 0)
        Thread.detachNewThread {
            Self.pump(from: b, to: a); done.signal()
        }
        Self.pump(from: a, to: b)
        done.wait()
    }

    private static func pump(from src: Int32, to dst: Int32) {
        var buf = [UInt8](repeating: 0, count: 32 * 1024)
        while true {
            let n = recv(src, &buf, buf.count, 0)
            if n < 0 && errno == EINTR { continue }
            if n <= 0 {
                Darwin.shutdown(dst, n == 0 ? SHUT_WR : SHUT_RDWR)
                if n < 0 { Darwin.shutdown(src, SHUT_RDWR) }
                return
            }
            if !writeAll(dst, Array(buf[0..<n])) {
                Darwin.shutdown(src, SHUT_RDWR); Darwin.shutdown(dst, SHUT_RDWR); return
            }
        }
    }

    // MARK: socket helpers

    static func readExactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
        var out = [UInt8](repeating: 0, count: count), got = 0
        while got < count {
            let n = out.withUnsafeMutableBytes { recv(fd, $0.baseAddress! + got, count - got, 0) }
            if n <= 0 { if n < 0 && errno == EINTR { continue }; return nil }
            got += n
        }
        return out
    }

    static func writeAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var sent = 0
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { send(fd, $0.baseAddress! + sent, bytes.count - sent, 0) }
            if n <= 0 { if n < 0 && errno == EINTR { continue }; return false }
            sent += n
        }
        return true
    }

    /// Non-blocking connect with a deadline; on success the socket is returned to blocking mode.
    static func connect(_ fd: Int32, to addr: inout sockaddr_in, timeoutMs: Int32) -> Result<Int32, Failure> {
        let flags = fcntl(fd, F_GETFL)
        _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        var err: Int32 = rc == 0 ? 0 : errno
        if rc != 0 && err == EINPROGRESS {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            if poll(&pfd, 1, timeoutMs) <= 0 { Darwin.close(fd); return .failure(.hostUnreachable) }
            var soerr: Int32 = 0; var len = socklen_t(MemoryLayout<Int32>.size)
            getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &len)
            err = soerr
        }
        guard err == 0 else {
            Darwin.close(fd)
            switch err {
            case ECONNREFUSED: return .failure(.connectionRefused)
            case ENETUNREACH: return .failure(.networkUnreachable)
            case EHOSTUNREACH, ETIMEDOUT: return .failure(.hostUnreachable)
            default: return .failure(.generalFailure)
            }
        }
        _ = fcntl(fd, F_SETFL, flags)
        return .success(fd)
    }
}
