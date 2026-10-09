import Foundation
import Darwin
import VPNGateCore

/// One connected app. Writes go through a bounded outbox drained on the client's own queue with a
/// non-blocking socket, so a client that stops reading can never stall the VPN session or other clients.
private final class IPCClient {
    let fd: Int32
    private let queue = DispatchQueue(label: "vpngate.ipc.client")
    private let lock = NSLock()
    private var outbox: [Data] = []
    private var draining = false
    private var closed = false
    static let maxQueued = 256
    static let stallTimeoutMs: Int32 = 2000

    init(fd: Int32) {
        self.fd = fd
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
    }

    var isClosed: Bool { lock.lock(); defer { lock.unlock() }; return closed }

    func send(_ d: Data) {
        lock.lock()
        if closed { lock.unlock(); return }
        if outbox.count >= Self.maxQueued { outbox.removeFirst() }       // events are state snapshots: newest wins
        outbox.append(d)
        let start = !draining
        draining = true
        lock.unlock()
        if start { queue.async { self.drain() } }
    }

    private func next() -> Data? {
        lock.lock(); defer { lock.unlock() }
        if outbox.isEmpty { draining = false; return nil }
        return outbox.removeFirst()
    }

    private func drain() {
        while let d = next() {
            var off = 0
            while off < d.count {
                let n = d.withUnsafeBytes { write(fd, $0.baseAddress! + off, d.count - off) }
                if n > 0 { off += n; continue }
                if n < 0 && (errno == EAGAIN || errno == EINTR) {
                    var p = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                    if poll(&p, 1, Self.stallTimeoutMs) > 0 { continue }
                }
                close()                                                  // stalled or broken: drop this client only
                return
            }
        }
    }

    /// Closes the socket exactly once; the descriptor is never touched afterwards.
    func close() {
        lock.lock()
        if closed { lock.unlock(); return }
        closed = true; outbox.removeAll()
        lock.unlock()
        Darwin.shutdown(fd, SHUT_RDWR)
        Darwin.close(fd)
    }
}

/// Newline-delimited JSON over a Unix socket, restricted to a single user.
final class IPCServer {
    private let path: String
    private let allowedUID: uid_t?
    /// Owner of the login session, looked up per connection so fast user switching works. nil = not used.
    private let consoleUID: () -> uid_t?
    private let session: SessionControlling
    private var clients: [IPCClient] = []
    private let lock = NSLock()
    private var listenFD: Int32 = -1
    private var running = false

    init(path: String, allowedUID: uid_t?, consoleUID: @escaping () -> uid_t? = { nil }, session: SessionControlling) {
        self.path = path; self.allowedUID = allowedUID; self.consoleUID = consoleUID; self.session = session
        session.emit = { [weak self] e in self?.broadcast(e) }
    }

    func start() throws {
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw UtunError.failed("socket") }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        guard rc == 0, listen(fd, 4) == 0 else { throw UtunError.failed("bind \(path): \(String(cString: strerror(errno)))") }
        lock.lock(); listenFD = fd; running = true; lock.unlock()
        // The socket is group/world-inaccessible; clients are authenticated by uid in accept(), so make it
        // connectable by any user and let isAllowed() decide (the console user is not known at install time).
        chmod(path, allowedUID == nil ? 0o666 : 0o600)
        if let u = allowedUID { chown(path, u, gid_t.max) }
        // Strong references on purpose: a running server must stay alive until stop(), even if its owner drops it.
        Thread.detachNewThread { [self] in
            while isRunning {
                let c = accept(fd, nil, nil)
                if c < 0 {
                    if errno != EINTR && errno != ECONNABORTED { Thread.sleep(forTimeInterval: 0.05) }   // e.g. EMFILE: don't spin
                    continue
                }
                var uid: uid_t = 0, gid: gid_t = 0
                if getpeereid(c, &uid, &gid) != 0 || !isAllowed(uid) { Darwin.close(c); continue }
                let client = IPCClient(fd: c)
                lock.lock(); clients.append(client); lock.unlock()
                Thread.detachNewThread { [self] in serve(client) }
            }
        }
    }

    /// root, the explicitly configured user, or whoever is logged in at the console.
    private func isAllowed(_ uid: uid_t) -> Bool {
        uid == 0 || uid == allowedUID || (consoleUID().map { $0 == uid && $0 != 0 } ?? false)
    }

    private var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return running }

    /// Stops listening and drops all clients.
    func stop() {
        lock.lock(); running = false; let cs = clients; clients = []; let l = listenFD; listenFD = -1; lock.unlock()
        if l >= 0 { Darwin.shutdown(l, SHUT_RDWR); Darwin.close(l) }
        cs.forEach { $0.close() }
        unlink(path)
    }

    private func serve(_ client: IPCClient) {
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        send(client, session.snapshot)
        while !client.isClosed {
            var p = pollfd(fd: client.fd, events: Int16(POLLIN), revents: 0)
            if poll(&p, 1, 500) <= 0 { continue }
            let n = read(client.fd, &chunk, chunk.count)
            if n == 0 || (n < 0 && errno != EAGAIN && errno != EINTR) { break }
            if n < 0 { continue }
            buf.append(contentsOf: chunk[0..<n])
            if buf.count > 1 << 20 { break }                             // runaway line: drop the client
            while let nl = buf.firstIndex(of: 10) {
                let line = buf[buf.startIndex..<nl]
                buf = Data(buf[buf.index(after: nl)...])
                if let req = try? JSONDecoder().decode(HelperRequest.self, from: line) { handle(req, client) }
            }
        }
        lock.lock(); clients.removeAll { $0 === client }; lock.unlock()
        client.close()
    }

    /// Everything that reaches `route`/the network stack from here must pass validation first.
    static func validate(_ r: HelperRequest) -> String? {
        let host = r.config?.host ?? r.host
        guard let host = host, InputValidation.isValidHost(host) else { return "invalid host" }
        if let port = r.port, !InputValidation.isValidPort(port) { return "invalid port" }
        if let config = r.config {
            for p in config.ports where !InputValidation.isValidPort(p) { return "invalid port \(p)" }
            if (config.certDer?.count ?? 0) > CertAuth.maxCertBytes { return "certificate too large" }
            if (config.privateKeyDer?.count ?? 0) > CertAuth.maxKeyBytes { return "private key too large" }
            if let t = config.ticket, t.count > 1024 { return "ticket too large" }
            if !InputValidation.isValidIdentityField(config.hubName) { return "invalid hub name" }
            if !InputValidation.isValidIdentityField(config.userName) { return "invalid user name" }
        }
        let p = r.config?.proxy ?? r.proxy
        if let p = p, p.kind != .none {
            if !InputValidation.isValidHost(p.host) { return "invalid proxy host" }
            if !InputValidation.isValidPort(p.port) { return "invalid proxy port" }
        }
        return nil
    }

    private func handle(_ r: HelperRequest, _ client: IPCClient) {
        switch r.cmd {
        case "connect":
            if let problem = Self.validate(r) {
                var e = session.snapshot
                e.log = nil; e.error = "Rejected connect request: \(problem)"
                send(client, e)
                return
            }
            if let cfg = r.config {
                session.connect(config: cfg)
            } else {
                session.connect(host: r.host!, port: r.port, ports: r.ports, proxy: r.proxy ?? ProxySettings(),
                                autoReconnect: r.autoReconnect ?? true, blockIPv6: r.blockIPv6 ?? true)
            }
        case "disconnect": session.disconnect()
        default: send(client, session.snapshot)
        }
    }

    private func send(_ client: IPCClient, _ e: HelperEvent) {
        guard var d = try? JSONEncoder().encode(e) else { return }
        d.append(10)
        client.send(d)
    }

    private func broadcast(_ e: HelperEvent) {
        lock.lock(); let cs = clients; lock.unlock()
        for c in cs { send(c, e) }
    }
}
