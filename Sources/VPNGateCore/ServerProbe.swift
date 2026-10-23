import Foundation

/// What a connectivity test of one relay found, measured from this Mac.
public enum ProbeOutcome: Equatable {
    /// Chosen for the run but not started yet (only a few relays are tested at a time).
    case queued
    case testing
    /// A SoftEther server answered the protocol hello on `port`. `connectMs` is TCP + TLS set-up, `helloMs` the whole
    /// test including the server's hello, so a relay that merely accepts TCP (a firewall, a captive proxy) is not "ok".
    case ok(port: UInt16, connectMs: Int, helloMs: Int, build: Int?)
    case failed(String)

    /// Ascending order = best first: working relays by connect time, then untested/in progress, then failed.
    public static func sortRank(_ o: ProbeOutcome?) -> Int {
        switch o {
        case .ok(_, let connectMs, _, _)?: return connectMs
        case .failed?: return Int.max
        case .queued?, .testing?, nil: return Int.max - 1
        }
    }

    public var isOK: Bool { if case .ok = self { return true }; return false }
}

/// Goes beyond a ping: opens TLS to the relay's SSL-VPN port and performs the first step of the real SoftEther
/// handshake (the signature upload that makes the server send its hello), without logging in or creating any tunnel.
public enum ServerProbe {
    /// How many of a relay's ports are tried before giving up (in the Windows client's priority order).
    public static let maxPorts = 3

    public static func ports(for server: VPNServer) -> [UInt16] {
        var out = server.prioritizedSslPorts
        if out.isEmpty, let p = server.connectPort { out = [UInt16(p)] }
        if out.isEmpty { out = [443] }
        return Array(out.prefix(maxPorts))
    }

    public static func run(
        host: String, ports: [UInt16], proxy: ProxySettings = ProxySettings(),
        timeout: TimeInterval = 5, factory: StreamFactory
    ) async -> ProbeOutcome {
        var lastError = "No port to test"
        for port in ports {
            switch await attempt(host: host, port: port, proxy: proxy, timeout: timeout, factory: factory) {
            case .success(let ok): return ok
            case .failure(let e): lastError = ports.count > 1 ? "\(e.message) (port \(port))" : e.message
            }
        }
        return .failed(lastError)
    }

    private struct Failure: Error { var message: String }

    private static func attempt(
        host: String, port: UInt16, proxy: ProxySettings, timeout: TimeInterval,
        factory: StreamFactory
    ) async -> Result<ProbeOutcome, Failure> {
        let stream = factory(host, port, proxy)
        defer { stream.cancel() }
        return await withTaskGroup(of: Result<ProbeOutcome, Failure>.self) { group in
            group.addTask { await handshake(stream, host: host, port: port) }
            group.addTask {
                try? await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                stream.cancel()
                return .failure(Failure(message: "No answer in \(Int(timeout)) s"))
            }
            let first = await group.next() ?? .failure(Failure(message: "Cancelled"))
            group.cancelAll()
            return first
        }
    }

    private static func handshake(_ s: ByteStream, host: String, port: UInt16) async -> Result<ProbeOutcome, Failure> {
        let t0 = Date()
        func ms(_ d: Date) -> Int { max(1, Int(Date().timeIntervalSince(d) * 1000)) }
        do { try await s.start() } catch {
            return .failure(Failure(message: (error as? StreamError).map { $0 == .timeout ? "No answer" : $0.localizedDescription } ?? "Cannot connect"))
        }
        let connectMs = ms(t0)
        // The plain marker is accepted by every SoftEther server, which is all that is needed to make it say hello.
        let body = Data("VPNCONNECT".utf8)
        var req = "POST /vpnsvc/connect.cgi HTTP/1.1\r\nHost: \(host)\r\n"
        req += "Content-Type: image/jpeg\r\nConnection: Keep-Alive\r\nContent-Length: \(body.count)\r\n\r\n"
        do {
            try await s.send(Data(req.utf8) + body)
            let head = try await s.recvHTTPHead()
            guard head.statusCode == 200 else { return .failure(Failure(message: "Not a VPN server (HTTP \(head.statusCode ?? 0))")) }
            guard let len = head.headers["content-length"].flatMap(Int.init), len > 0, len < 1 << 20 else {
                return .failure(Failure(message: "Not a VPN server"))
            }
            let pack = try Pack(parsing: try await s.recv(len))
            guard let random = pack.data("random"), random.count == 20 else {
                return .failure(Failure(message: "Not a SoftEther server"))
            }
            return .success(.ok(port: port, connectMs: connectMs, helloMs: ms(t0), build: pack.int("build").map(Int.init)))
        } catch {
            return .failure(Failure(message: "Connected, but no VPN handshake"))
        }
    }
}

extension StreamError: Equatable {
    public static func == (a: StreamError, b: StreamError) -> Bool {
        switch (a, b) {
        case (.closed, .closed), (.timeout, .timeout): return true
        case (.protocolError(let x), .protocolError(let y)): return x == y
        default: return false
        }
    }
}
