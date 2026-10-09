import Foundation
import VPNGateCore

/// Scripted in-memory SoftEther server speaking the real wire format (HTTP+PACK, then data phase).
final class FakeSoftEtherServer {
    struct Request { var path: String; var contentType: String; var body: [UInt8] }

    // behaviour knobs
    var rejectWatermark = false
    var omitRandom = false
    var loginError: UInt32 = 0
    var redirect = false
    var redirectHost = "5.6.7.8"
    var redirectPort: UInt32 = 443
    /// If set, the redirect offers this whole port list instead of `redirectPort`.
    var redirectPorts: [UInt32]?
    var redirectTicket = Data(repeating: 0x42, count: 20)
    /// If set, the redirect `Ip` is sent as SoftEther's pack integer instead of a string.
    var redirectIpInt: UInt32?
    /// If set, replaces the whole (non-error, non-redirect) welcome pack.
    var welcomeOverride: Pack?
    /// The next N additional_connect requests are answered with an error.
    var failAdditionalConnects = 0
    var useCompress = false
    var maxConnections: UInt32 = 1
    var sessionKey = Data(repeating: 0x11, count: 20)
    var useUdpAccel = false
    var udpServerPort: UInt16 = 40001
    var udpServerCookie: UInt32 = 0x12345678
    var udpClientCookie: UInt32 = 0x87654321
    var udpServerKey = Data(repeating: 0x99, count: 128)
    var helloStatus = 200
    var welcomeTimeoutMs: UInt32 = 20000
    var failStart: Error?
    /// What every stream reports as the peer it really connected to.
    var remoteIPv4: String?
    /// Bytes sent right after the welcome (same TCP segment).
    var trailingAfterWelcome: [UInt8] = []
    /// If set, server→client bytes are delivered in chunks of this size.
    var chunkSize: Int?
    /// Called for every Ethernet frame the client sends in the data phase.
    var onFrame: (([UInt8]) -> Void)?

    // observations
    private let lock = NSLock()
    private var _requests: [Request] = []
    private var _logins: [Pack] = []
    private var _additionalConnects: [Pack] = []
    private var _frames: [[UInt8]] = []
    private var _keepAlives = 0
    private var _streams: [FakeStream] = []
    var requests: [Request] { lock.lock(); defer { lock.unlock() }; return _requests }
    var logins: [Pack] { lock.lock(); defer { lock.unlock() }; return _logins }
    var additionalConnects: [Pack] { lock.lock(); defer { lock.unlock() }; return _additionalConnects }
    var framesReceived: [[UInt8]] { lock.lock(); defer { lock.unlock() }; return _frames }
    var keepAlivesReceived: Int { lock.lock(); defer { lock.unlock() }; return _keepAlives }
    var streamsCreated: Int { lock.lock(); defer { lock.unlock() }; return _streams.count }
    var lastStream: FakeStream? { lock.lock(); defer { lock.unlock() }; return _streams.last }

    var factory: StreamFactory {
        { [unowned self] _, _, _ in
            let s = FakeStream(server: self)
            self.lock.lock(); self._streams.append(s); self.lock.unlock()
            return s
        }
    }

    // MARK: per-connection protocol state
    fileprivate func connectionClosedByClient() {}

    fileprivate func record(_ r: Request) { lock.lock(); _requests.append(r); lock.unlock() }
    fileprivate func record(login: Pack) { lock.lock(); _logins.append(login); lock.unlock() }
    fileprivate func record(additionalConnect: Pack) { lock.lock(); _additionalConnects.append(additionalConnect); lock.unlock() }
    fileprivate func record(frame: [UInt8]) { lock.lock(); _frames.append(frame); lock.unlock() }
    fileprivate func takeAdditionalFailure() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if failAdditionalConnects > 0 { failAdditionalConnects -= 1; return true }
        return false
    }
    fileprivate func recordKeepAlive() { lock.lock(); _keepAlives += 1; lock.unlock() }

    static func http(_ status: Int, _ body: [UInt8]) -> [UInt8] {
        Array("HTTP/1.1 \(status) OK\r\nContent-Type: application/octet-stream\r\nContent-Length: \(body.count)\r\n\r\n".utf8) + body
    }

    func helloPack() -> Pack {
        var p = Pack()
        p.addStr("hello", "SoftEther VPN Server")
        p.addInt("version", 432); p.addInt("build", 9729)
        if !omitRandom { p.addData("random", Data((0..<20).map { UInt8($0) })) }
        return p
    }

    func welcomePack() -> Pack {
        var p = Pack()
        if loginError != 0 { p.addInt("error", loginError); return p }
        if redirect {
            p.addInt("Redirect", 1)
            if let ip = redirectIpInt { p.addInt("Ip", ip) } else { p.addStr("Ip", redirectHost) }
            if let ports = redirectPorts { p.addInts("Port", ports) } else { p.addInt("Port", redirectPort) }
            p.addData("Ticket", redirectTicket)
            return p
        }
        if let o = welcomeOverride { return o }
        p.addStr("session_name", "SID-VPN-TEST-1")
        p.addStr("connection_name", "CID-1")
        p.addInt("timeout", welcomeTimeoutMs)
        p.addData("session_key", sessionKey)
        p.addInt("max_connection", maxConnections)
        p.addBool("use_compress", useCompress)
        if useUdpAccel {
            p.addBool("use_udp_acceleration", true)
            p.addInt("udp_acceleration_version", 2)
            p.addStr("udp_acceleration_server_ip", "127.0.0.1")
            p.addInt("udp_acceleration_server_port", UInt32(udpServerPort))
            p.addInt("udp_acceleration_server_cookie", udpServerCookie)
            p.addInt("udp_acceleration_client_cookie", udpClientCookie)
            p.addData("udp_acceleration_server_key_v2", udpServerKey)
        }
        return p
    }
}

final class FakeStream: ByteStream {
    var buffer = ByteBuffer()
    private let server: FakeSoftEtherServer
    private let incoming = AsyncQueue()
    private var rx: [UInt8] = []
    private var mode = Mode.http
    private var decoder = DataPhaseDecoder()
    private let lock = NSLock()
    private(set) var cancelled = false
    private enum Mode { case http, data }

    init(server: FakeSoftEtherServer) { self.server = server }

    func start() async throws { if let e = server.failStart { throw e } }

    var remoteIPv4: String? { server.remoteIPv4 }

    func readChunk() async throws -> Data { try await incoming.next() }

    func cancel() {
        lock.lock(); cancelled = true; lock.unlock()
        incoming.finish()
    }

    var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }

    // server → client
    func deliver(_ bytes: [UInt8]) {
        if let n = server.chunkSize, n > 0 {
            var i = 0
            while i < bytes.count { incoming.push(Data(bytes[i..<min(i + n, bytes.count)])); i += n }
        } else { incoming.push(Data(bytes)) }
    }
    func closeFromServer() { incoming.finish() }
    func failFromServer(_ e: Error) { incoming.finish(e) }

    // client → server
    func send(_ data: Data) async throws {
        if isCancelled { throw StreamError.closed }
        lock.lock()
        rx.append(contentsOf: data)
        lock.unlock()
        process()
    }

    private func process() {
        lock.lock(); defer { lock.unlock() }
        while true {
            switch mode {
            case .http:
                guard let end = findHeaderEnd() else { return }
                let head = HTTPHead.parse(Array(rx[0..<end]))
                let len = head.headers["content-length"].flatMap(Int.init) ?? 0
                guard rx.count >= end + 4 + len else { return }
                let body = Array(rx[(end + 4)..<(end + 4 + len)])
                rx.removeFirst(end + 4 + len)
                let path = head.status.split(separator: " ").dropFirst().first.map(String.init) ?? ""
                respond(path: path, contentType: head.headers["content-type"] ?? "", body: body)
            case .data:
                let chunk = rx; rx.removeAll()
                do {
                    for item in try decoder.feed(chunk) {
                        switch item {
                        case .frame(let f): server.record(frame: f); server.onFrame?(f)
                        case .keepAlive: server.recordKeepAlive()
                        }
                    }
                } catch { incoming.finish(error) }
                return
            }
        }
    }

    private func findHeaderEnd() -> Int? {
        guard rx.count >= 4 else { return nil }
        for i in 0...(rx.count - 4) where rx[i] == 13 && rx[i+1] == 10 && rx[i+2] == 13 && rx[i+3] == 10 { return i }
        return nil
    }

    private func respond(path: String, contentType: String, body: [UInt8]) {
        server.record(.init(path: path, contentType: contentType, body: body))
        switch path {
        case "/vpnsvc/connect.cgi":
            let plain = body == Array("VPNCONNECT".utf8)
            if server.helloStatus != 200 || (server.rejectWatermark && !plain) {
                deliver(Array("HTTP/1.1 \(server.helloStatus == 200 ? 403 : server.helloStatus) Forbidden\r\nContent-Length: 0\r\n\r\n".utf8))
                return
            }
            deliver(FakeSoftEtherServer.http(200, [UInt8](server.helloPack().serialize())))
        case "/vpnsvc/vpn.cgi":
            guard let p = try? Pack(parsing: Data(body)) else {
                var e = Pack(); e.addInt("error", 4)
                deliver(FakeSoftEtherServer.http(200, [UInt8](e.serialize()))); return
            }

            if p.str("method") == "additional_connect" {
                server.record(additionalConnect: p)
                if server.takeAdditionalFailure() {
                    var e = Pack(); e.addInt("error", 3)
                    deliver(FakeSoftEtherServer.http(200, [UInt8](e.serialize()))); return
                }
                decoder.useCompress = server.useCompress
                deliver(FakeSoftEtherServer.http(200, [UInt8](Pack().serialize())))
                mode = .data
                return
            }

            server.record(login: p)
            // Real servers reject packs with duplicate (case-insensitive) element names.
            let names = p.elements.map { $0.name.lowercased() }
            if Set(names).count != names.count {
                var e = Pack(); e.addInt("error", 3)
                deliver(FakeSoftEtherServer.http(200, [UInt8](e.serialize()))); return
            }
            decoder.useCompress = server.useCompress
            deliver(FakeSoftEtherServer.http(200, [UInt8](server.welcomePack().serialize())) + server.trailingAfterWelcome)
            if server.loginError == 0 && !server.redirect { mode = .data }
        default:
            deliver(Array("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n".utf8))
        }
    }
}
