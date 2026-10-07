import Foundation
import VPNGateCore

struct Welcome {
    var sessionName: String
    var connectionName: String
    var timeoutMs: Int
    var message: String?
}

/// SoftEther SSL-VPN client (anonymous login to the VPN Gate hub, single TCP connection, no compression).
/// Protocol reference: SoftEtherVPN src/Cedar/Protocol.c and Connection.c.
final class SoftEtherClient: VPNTransport {
    static let hubName = "VPNGATE"
    static let userName = "vpn"
    static let maxBlock = DataPhase.maxBlock

    private let host: String
    private let port: UInt16
    private let proxy: ProxySettings
    private let makeStream: StreamFactory
    private var _stream: ByteStream?
    private var stream: ByteStream? {
        get { sendLock.lock(); defer { sendLock.unlock() }; return _stream }
        set { sendLock.lock(); _stream = newValue; sendLock.unlock() }
    }
    private var tasks: [Task<Void, Never>] = []
    private let sendLock = NSLock()
    private var pending: [[UInt8]] = []
    private var flushing = false
    private var closed = false

    var onFrame: (([UInt8]) -> Void)?
    var onClose: ((Error?) -> Void)?
    private(set) var welcome: Welcome?
    private let statsLock = NSLock()
    private var _bytesIn: UInt64 = 0
    private var _bytesOut: UInt64 = 0
    var bytesIn: UInt64 { statsLock.lock(); defer { statsLock.unlock() }; return _bytesIn }
    var bytesOut: UInt64 { statsLock.lock(); defer { statsLock.unlock() }; return _bytesOut }
    private func add(in n: Int) { statsLock.lock(); _bytesIn += UInt64(n); statsLock.unlock() }
    private func add(out n: Int) { statsLock.lock(); _bytesOut += UInt64(n); statsLock.unlock() }

    init(host: String, port: UInt16, proxy: ProxySettings,
         makeStream: @escaping StreamFactory = { TLSStream(host: $0, port: $1, proxy: $2) }) {
        self.host = host; self.port = port; self.proxy = proxy; self.makeStream = makeStream
    }

    // MARK: handshake

    func connect(log: (String) -> Void) async throws -> Welcome {
        let s = makeStream(host, port, proxy)
        stream = s
        try await s.start()
        if isClosed { s.cancel(); throw StreamError.closed }
        log("TLS established with \(host):\(port)")

        // 1. signature upload; fall back to the plain "VPNCONNECT" body for servers that reject the image
        var hello: Pack
        do {
            hello = try await uploadSignature(s, body: softEtherWaterMark + randomBytes(Int.random(in: 0..<2000)))
        } catch {
            log("Signature rejected (\(error.localizedDescription)); retrying plain")
            s.cancel()
            let s2 = makeStream(host, port, proxy)
            stream = s2
            try await s2.start()
            hello = try await uploadSignature(s2, body: Data("VPNCONNECT".utf8))
        }
        let st = stream!
        guard let random = hello.data("random"), random.count == 20 else {
            throw StreamError.protocolError("Server hello missing random (not a SoftEther server?)")
        }
        log("Server: \(hello.str("hello") ?? "?") v\(hello.int("version") ?? 0) build \(hello.int("build") ?? 0)")

        // 2. login
        try await st.send(httpPost(path: "/vpnsvc/vpn.cgi", type: "application/octet-stream",
                                   body: withDummy(loginPack()).serialize()))
        let w = try await readPack(st)
        if let err = w.int("error"), err != 0 { throw StreamError.protocolError("Server refused login (error \(err))") }
        if (w.int("Redirect") ?? 0) != 0 { throw StreamError.protocolError("Server requested a cluster redirect (unsupported)") }
        let wel = Welcome(sessionName: w.str("session_name") ?? "",
                          connectionName: w.str("connection_name") ?? "",
                          timeoutMs: Int(w.int("timeout") ?? 20000),
                          message: w.data("Msg").map { String(decoding: $0, as: UTF8.self) })
        welcome = wel
        log("Session \(wel.sessionName) established")
        startDataPhase(st, timeoutMs: max(wel.timeoutMs, 5000))
        return wel
    }

    private func uploadSignature(_ s: ByteStream, body: Data) async throws -> Pack {
        try await s.send(httpPost(path: "/vpnsvc/connect.cgi", type: "image/jpeg", body: body))
        return try await readPack(s)
    }

    private func readPack(_ s: ByteStream) async throws -> Pack {
        let head = try await s.recvHTTPHead()
        guard head.statusCode == 200 else { throw StreamError.protocolError("HTTP: \(head.status)") }
        guard let len = head.headers["content-length"].flatMap(Int.init), len > 0, len < 1 << 20 else {
            throw StreamError.protocolError("Bad response length")
        }
        return try Pack(parsing: try await s.recv(len))
    }

    private func httpPost(path: String, type: String, body: Data) -> Data {
        var h = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\n"
        h += "Content-Type: \(type)\r\nConnection: Keep-Alive\r\nContent-Length: \(body.count)\r\n\r\n"
        return Data(h.utf8) + body
    }

    private func withDummy(_ p: Pack) -> Pack {
        var p = p
        p.addData("pencore", randomBytes(Int.random(in: 0..<1000)))
        return p
    }

    func loginPack() -> Pack {
        var p = Pack()
        let clientVer: UInt32 = 443, build: UInt32 = 9799
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osVer = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let hostname = ProcessInfo.processInfo.hostName
        let uid = randomBytes(20)

        p.addStr("method", "login")
        p.addStr("hubname", Self.hubName)
        p.addStr("username", Self.userName)
        p.addInt("authtype", 0)                       // anonymous
        p.addStr("client_str", "SoftEther VPN Client")
        p.addInt("client_ver", clientVer)
        p.addInt("client_build", build)
        p.addInt("protocol", 0)                       // TCP
        p.addStr("hello", "SoftEther VPN Client")
        p.addInt("version", clientVer)
        p.addInt("build", build)
        p.addInt("client_id", 0)
        p.addInt("max_connection", 1)
        p.addBool("use_encrypt", true)
        p.addBool("use_compress", false)
        p.addBool("half_connection", false)
        p.addBool("require_bridge_routing_mode", false)
        p.addBool("require_monitor_mode", false)
        p.addBool("qos", false)
        p.addBool("support_bulk_on_rudp", false)
        p.addBool("support_hmac_on_bulk_of_rudp", false)
        p.addBool("support_udp_recovery", false)
        p.addData("unique_id", uid)
        // node info
        p.addStr("ClientProductName", "SoftEther VPN Client")
        p.addStr("ServerProductName", "")
        p.addStr("ClientOsName", "macOS")
        p.addStr("ClientOsVer", osVer)
        p.addStr("ClientOsProductId", "")
        p.addStr("ClientHostname", hostname)
        p.addStr("ServerHostname", host)
        p.addStr("ProxyHostname", proxy.kind == .none ? "" : proxy.host)
        p.addData("UniqueId", uid)
        p.addInt("ClientProductVer", clientVer)
        p.addInt("ClientProductBuild", build)
        p.addInt("ServerProductVer", 0)
        p.addInt("ServerProductBuild", 0)
        p.addInt("ClientPort", 0)
        p.addInt("ServerPort2", UInt32(port))
        p.addInt("ProxyPort", UInt32(clamping: max(0, proxy.port)))
        p.addIPv4("ClientIpAddress", 0)
        p.addIPv4("ServerIpAddress", 0)
        p.addIPv4("ProxyIpAddress", 0)
        return p
    }

    // MARK: data phase

    private func startDataPhase(_ s: ByteStream, timeoutMs: Int) {
        let reader = Task.detached { [weak self] in
            do {
                var decoder = DataPhaseDecoder()
                var chunk = s.buffer.takeAll()          // anything that arrived together with the welcome
                while true {
                    for item in try decoder.feed(chunk) {
                        if case .frame(let d) = item {
                            self?.add(in: d.count)
                            self?.onFrame?(d)
                        }
                    }
                    chunk = [UInt8](try await s.readChunk())
                }
            } catch { self?.close(error) }
        }
        let keepAlive = Task.detached { [weak self] in
            while !Task.isCancelled {
                let lo = max(timeoutMs / 5, 1000), hi = max(timeoutMs / 2, lo + 1)
                try? await Task.sleep(nanoseconds: UInt64(Int.random(in: lo...hi)) * 1_000_000)
                guard let self = self, !Task.isCancelled else { return }
                let junk = self.randomBytes(Int.random(in: 0..<512))
                self.enqueue(Data(DataPhase.encodeKeepAlive(junk: [UInt8](junk))))
            }
        }
        sendLock.lock(); tasks = [reader, keepAlive]; let alreadyClosed = closed; sendLock.unlock()
        if alreadyClosed { reader.cancel(); keepAlive.cancel() }
    }

    /// Queue an Ethernet frame for the hub. Frames are batched into one write when the socket is busy.
    func sendFrame(_ frame: [UInt8]) {
        guard frame.count <= Self.maxBlock else { return }
        sendLock.lock()
        pending.append(frame)
        sendLock.unlock()
        enqueue(nil)
    }

    private func enqueue(_ raw: Data?) {
        sendLock.lock()
        if let raw = raw { rawQueue.append(raw) }
        if flushing || closed { sendLock.unlock(); return }
        flushing = true
        sendLock.unlock()
        Task.detached { [weak self] in await self?.flush() }
    }
    private var rawQueue: [Data] = []

    private func takeBatch() -> (frames: [[UInt8]], raws: [Data])? {
        sendLock.lock(); defer { sendLock.unlock() }
        let frames = Array(pending.prefix(64)); pending.removeFirst(frames.count)
        let raws = rawQueue; rawQueue.removeAll()
        if frames.isEmpty && raws.isEmpty { flushing = false; return nil }
        return (frames, raws)
    }

    private func flush() async {
        while true {
            guard let (frames, raws) = takeBatch() else { return }
            var out = Data()
            for r in raws { out.append(r) }
            if !frames.isEmpty {
                out.append(contentsOf: DataPhase.encode(frames: frames))
                add(out: frames.reduce(0) { $0 + $1.count })
            }
            do { try await stream?.send(out) } catch { close(error); return }
        }
    }

    func close(_ error: Error?) {
        sendLock.lock()
        if closed { sendLock.unlock(); return }
        closed = true
        let ts = tasks
        sendLock.unlock()
        ts.forEach { $0.cancel() }
        stream?.cancel()
        onClose?(error)
    }

    private var isClosed: Bool { sendLock.lock(); defer { sendLock.unlock() }; return closed }

    func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }
}
