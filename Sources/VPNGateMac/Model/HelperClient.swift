import Darwin
import Foundation

/// Talks to the privileged helper over its Unix socket. Mutable state (`fd`, `pending`, `nextID`) is guarded by `lock`;
/// the two callbacks are set before `connect()` and only read afterwards.
final class HelperClient: @unchecked Sendable {
    private var fd: Int32 = -1
    private let path: String

    init(path: String = helperSocketPath) { self.path = path }
    private let lock = NSLock()
    var onEvent: ((HelperEvent) -> Void)?
    var onDisconnect: (() -> Void)?

    /// Open v9 requests by id; failed all at once when the socket drops.
    private var pending: [Int: CheckedContinuation<HelperReply, Error>] = [:]
    private var nextID = 1

    var isConnected: Bool { lock.lock(); defer { lock.unlock() }; return fd >= 0 }

    func connect() -> Bool {
        if isConnected { return true }
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return false }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard rc == 0 else { Darwin.close(s); return false }
        lock.lock(); fd = s; lock.unlock()
        Thread.detachNewThread { [weak self] in self?.readLoop(s) }
        return true
    }

    private func readLoop(_ s: Int32) {
        var buf = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        while true {
            let n = read(s, &chunk, chunk.count)
            if n <= 0 { break }
            buf.append(contentsOf: chunk[0..<n])
            while let nl = buf.firstIndex(of: 10) {
                let line = buf[buf.startIndex..<nl]
                buf = Data(buf[buf.index(after: nl)...])
                // Replies have `reply`, events have `state`; a line is only ever one of them.
                if let r = try? JSONDecoder().decode(HelperReply.self, from: line) {
                    lock.lock(); let waiter = r.id.flatMap { pending.removeValue(forKey: $0) }; lock.unlock()
                    waiter?.resume(returning: r)
                } else if let e = try? JSONDecoder().decode(HelperEvent.self, from: line) {
                    onEvent?(e)
                }
            }
        }
        lock.lock()
        if fd == s { fd = -1 }
        let waiting = pending; pending = [:]
        lock.unlock()
        Darwin.close(s)
        for w in waiting.values { w.resume(throwing: HelperRequestError.disconnected) }
        onDisconnect?()
    }

    func send(_ req: HelperRequest) { _ = write(req) }

    @discardableResult
    private func write(_ req: HelperRequest) -> Bool {
        guard connect(), var d = try? JSONEncoder().encode(req) else { return false }
        d.append(10)
        lock.lock(); let s = fd; lock.unlock()
        return d.withUnsafeBytes { Darwin.write(s, $0.baseAddress, d.count) } == d.count
    }

    /// Sends a v9 request and waits for the reply with the same `id`. Throws `.failed` for `ok:false`, `.timeout` when the
    /// daemon stays silent, `.disconnected` when the socket drops first.
    func request(_ req: HelperRequest, timeout: TimeInterval = 90) async throws -> HelperReply {
        var req = req
        let id = takeID()
        req.id = id
        let reply: HelperReply = try await withCheckedThrowingContinuation { cont in
            lock.lock(); pending[id] = cont; lock.unlock()
            if !write(req) {
                lock.lock(); let c = pending.removeValue(forKey: id); lock.unlock()
                c?.resume(throwing: HelperRequestError.disconnected)
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { [weak self] in
                guard let self else { return }
                self.lock.lock(); let c = self.pending.removeValue(forKey: id); self.lock.unlock()
                c?.resume(throwing: HelperRequestError.timeout)
            }
        }
        guard reply.ok else { throw HelperRequestError.failed(reply.error ?? "The helper refused the request") }
        return reply
    }

    private func takeID() -> Int { lock.lock(); defer { lock.unlock() }; nextID += 1; return nextID - 1 }

    /// The shipped list straight from the helper binary inside the app (`--list`: no daemon, no root, no network). Used
    /// before the helper is installed, when `listServers` has nobody to ask. Nil when the binary is missing or fails.
    static func bundledList(
        binary: URL? = Bundle.main.resourceURL?.appendingPathComponent("vpngate-helper"),
        list: URL? = Bundle.main.resourceURL?.appendingPathComponent("VPNGate.dat"),
        cache: URL = FileManager.default.temporaryDirectory.appendingPathComponent("vpngate-list-\(getpid()).dat")
    ) async -> ServerListResult? {
        guard let binary, FileManager.default.isExecutableFile(atPath: binary.path) else { return nil }
        return await Task.detached {
            let p = Process()
            p.executableURL = binary
            p.arguments = ["--list", "--cache", cache.path] + (list.map { ["--bundle", $0.path] } ?? [])
            let out = Pipe()
            p.standardOutput = out
            p.standardError = FileHandle.nullDevice
            do { try p.run() } catch { return nil }
            let data = out.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            guard p.terminationStatus == 0 else { return nil }
            return try? JSONDecoder().decode(ServerListResult.self, from: data)
        }.value
    }

    func listServers() async throws -> ServerListResult {
        try await request(HelperRequest(cmd: "listServers"), timeout: 30).decode(ServerListResult.self)
    }

    func refreshServers(proxy: ProxySettings, mirror: String?) async throws -> ServerListResult {
        var r = HelperRequest(cmd: "refreshServers")
        r.proxy = proxy
        if let mirror, !mirror.isEmpty { r.mirror = mirror }
        return try await request(r, timeout: 180).decode(ServerListResult.self)
    }

    func probe(_ targets: [ProbeTarget], proxy: ProxySettings, timeout: TimeInterval = 5) async throws -> [ProbeEntry] {
        var r = HelperRequest(cmd: "probe")
        r.targets = targets; r.proxy = proxy; r.timeout = timeout
        // 8 relays at a time, so a full batch of 200 needs up to 25 rounds of the per-relay timeout.
        let budget = Double((targets.count + 7) / 8) * timeout * 3 + 30
        return try await request(r, timeout: budget).decode(ProbeResultList.self).results
    }

    func validateAccount(_ account: ClientAccount) async throws -> String? {
        var r = HelperRequest(cmd: "validateAccount")
        r.account = account
        struct V: Decodable { var valid: Bool; var error: String? }
        let v = try await request(r, timeout: 15).decode(V.self)
        return v.valid ? nil : (v.error ?? "Invalid account")
    }
}
