import Foundation
import VPNGateCore

public enum ClientAuth {
    case anonymous
    case plainPassword(String)
    case hashedPassword(String)
    case certificate(certDer: Data, sign: (Data) throws -> Data)
    case ticket(Data)
}

public struct Welcome {
    public var sessionName: String
    public var connectionName: String
    public var timeoutMs: Int
    public var message: String?
    public var sessionKey: Data?
    public var maxConnection: Int
    public var useCompress: Bool
    public var useEncrypt: Bool
    public var halfConnection: Bool
    public var qos: Bool

    // UDP acceleration
    public var useUdpAcceleration: Bool
    public var udpAccelVersion: Int
    public var udpServerIp: String?
    public var udpServerPort: UInt16?
    public var udpServerCookie: UInt32?
    public var udpClientCookie: UInt32?
    public var udpServerKey: Data?
    public var udpFastDisconnect: Bool

    public init(
        sessionName: String,
        connectionName: String,
        timeoutMs: Int = 20000,
        message: String? = nil,
        sessionKey: Data? = nil,
        maxConnection: Int = 1,
        useCompress: Bool = false,
        useEncrypt: Bool = true,
        halfConnection: Bool = false,
        qos: Bool = false,
        useUdpAcceleration: Bool = false,
        udpAccelVersion: Int = 1,
        udpServerIp: String? = nil,
        udpServerPort: UInt16? = nil,
        udpServerCookie: UInt32? = nil,
        udpClientCookie: UInt32? = nil,
        udpServerKey: Data? = nil,
        udpFastDisconnect: Bool = false
    ) {
        self.sessionName = sessionName
        self.connectionName = connectionName
        self.timeoutMs = timeoutMs
        self.message = message
        self.sessionKey = sessionKey
        self.maxConnection = maxConnection
        self.useCompress = useCompress
        self.useEncrypt = useEncrypt
        self.halfConnection = halfConnection
        self.qos = qos
        self.useUdpAcceleration = useUdpAcceleration
        self.udpAccelVersion = udpAccelVersion
        self.udpServerIp = udpServerIp
        self.udpServerPort = udpServerPort
        self.udpServerCookie = udpServerCookie
        self.udpClientCookie = udpClientCookie
        self.udpServerKey = udpServerKey
        self.udpFastDisconnect = udpFastDisconnect
    }
}

/// SoftEther SSL-VPN client with full protocol parity (multi-TCP pool, compression, UDP acceleration v2, auth, cluster redirect).
/// Protocol reference: SoftEtherVPN src/Cedar/Protocol.c, Connection.c, and UdpAccel.c.
final class SoftEtherClient: VPNTransport {
    static let defaultHubName = "VPNGATE"
    static let defaultUserName = "vpn"
    static let maxBlock = DataPhase.maxBlock

    private var host: String
    private var port: UInt16
    private let hubName: String
    private let userName: String
    private var auth: ClientAuth
    private let proxy: ProxySettings
    private let maxConnectionsConfig: Int
    private let useCompressConfig: Bool
    private let useUdpAccelConfig: Bool
    private let makeStream: StreamFactory

    private let pool = ConnectionPool()
    private var udpAccel: UdpAccel?
    private var additionalTasks: [Task<Void, Never>] = []
    private var keepAliveTask: Task<Void, Never>?

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

    init(
        host: String,
        port: UInt16,
        hubName: String = defaultHubName,
        userName: String = defaultUserName,
        auth: ClientAuth = .anonymous,
        proxy: ProxySettings,
        maxConnections: Int = 8,
        useCompress: Bool = false,
        useUdpAccel: Bool = true,
        makeStream: @escaping StreamFactory = { TLSStream(host: $0, port: $1, proxy: $2) }
    ) {
        self.host = host
        self.port = port
        self.hubName = hubName
        self.userName = userName
        self.auth = auth
        self.proxy = proxy
        self.maxConnectionsConfig = max(1, min(maxConnections, 32))
        self.useCompressConfig = useCompress
        self.useUdpAccelConfig = useUdpAccel
        self.makeStream = makeStream

        pool.onFrame = { [weak self] frame in self?.onFrame?(frame) }
        pool.onClose = { [weak self] error in self?.close(error) }
        pool.onByteCount = { [weak self] bIn, bOut in
            if bIn > 0 { self?.add(in: bIn) }
            if bOut > 0 { self?.add(out: bOut) }
        }
    }

    // MARK: - Handshake & Cluster Redirect

    func connect(log: (String) -> Void) async throws -> Welcome {
        var currentHost = host
        var currentPort = port
        var currentAuth = auth
        var redirectCount = 0

        while redirectCount < 5 {
            let (wel, redirect) = try await connectOnce(
                host: currentHost,
                port: currentPort,
                auth: currentAuth,
                log: log
            )

            if let redirect = redirect {
                redirectCount += 1
                log("Cluster redirect (\(redirectCount)/5) to \(redirect.host):\(redirect.port)")
                currentHost = redirect.host
                currentPort = redirect.port
                currentAuth = .ticket(redirect.ticket)
                self.host = currentHost
                self.port = currentPort
                self.auth = currentAuth
                continue
            }

            guard let finalWelcome = wel else {
                throw StreamError.protocolError("Connection closed without welcome or redirect")
            }

            self.welcome = finalWelcome
            log("Session \(finalWelcome.sessionName) established (TCP max=\(finalWelcome.maxConnection), compress=\(finalWelcome.useCompress), UDP=\(finalWelcome.useUdpAcceleration))")

            // Start KeepAlive & Additional connections
            startDataServices(welcome: finalWelcome)
            return finalWelcome
        }

        throw StreamError.protocolError("Too many cluster redirects (\(redirectCount))")
    }

    private struct RedirectInfo {
        let host: String
        let port: UInt16
        let ticket: Data
    }

    private func connectOnce(
        host: String,
        port: UInt16,
        auth: ClientAuth,
        log: (String) -> Void
    ) async throws -> (welcome: Welcome?, redirect: RedirectInfo?) {
        let s = makeStream(host, port, proxy)
        var activeStream: ByteStream = s
        try await activeStream.start()
        if isClosed { activeStream.cancel(); throw StreamError.closed }
        log("TLS established with \(host):\(port)")

        // 1. Signature upload
        var hello: Pack
        do {
            hello = try await uploadSignature(activeStream, body: softEtherWaterMark + randomBytes(Int.random(in: 0..<2000)), host: host)
        } catch {
            log("Signature rejected (\(error.localizedDescription)); retrying plain")
            activeStream.cancel()
            let s2 = makeStream(host, port, proxy)
            activeStream = s2
            try await activeStream.start()
            hello = try await uploadSignature(activeStream, body: Data("VPNCONNECT".utf8), host: host)
        }

        guard let random = hello.data("random"), random.count == 20 else {
            activeStream.cancel()
            throw StreamError.protocolError("Server hello missing random (not a SoftEther server?)")
        }
        log("Server: \(hello.str("hello") ?? "?") v\(hello.int("version") ?? 0) build \(hello.int("build") ?? 0)")

        // UDP acceleration setup
        let clientKeyV1 = randomBytes(20)
        let clientKeyV2 = randomBytes(128)
        var tempUdpAccel: UdpAccel?
        if useUdpAccelConfig {
            tempUdpAccel = UdpAccel(
                serverIP: host,
                serverPort: port,
                myCookie: UInt32.random(in: 1...UInt32.max),
                yourCookie: 0,
                myKeyV2: [UInt8](clientKeyV2),
                yourKeyV2: [UInt8](clientKeyV2)
            )
        }

        // 2. Login
        let login = try loginPack(
            random: random,
            auth: auth,
            host: host,
            port: port,
            clientUdpPort: tempUdpAccel?.localPort ?? 0,
            clientKeyV1: clientKeyV1,
            clientKeyV2: clientKeyV2
        )

        try await activeStream.send(httpPost(path: "/vpnsvc/vpn.cgi", type: "application/octet-stream",
                                             body: withDummy(login).serialize(), host: host))
        let w = try await readPack(activeStream)

        if let err = w.int("error"), err != 0 {
            activeStream.cancel()
            throw StreamError.protocolError("Server refused login: \(SoftEtherError.describe(Int(err)))")
        }

        // Handle Cluster Redirect
        if (w.int("Redirect") ?? 0) != 0 {
            guard let ticket = w.data("Ticket"), ticket.count == 20 else {
                activeStream.cancel()
                throw StreamError.protocolError("Cluster redirect missing 20-byte ticket")
            }
            let redirectIP: String
            if let ipStr = w.str("Ip"), !ipStr.isEmpty {
                redirectIP = ipStr
            } else if let ipInt = w.int("Ip") {
                redirectIP = ipString(ipInt)
            } else {
                redirectIP = host
            }
            let redirectPort = UInt16(w.int("Port") ?? UInt32(port))
            activeStream.cancel()
            return (nil, RedirectInfo(host: redirectIP, port: redirectPort, ticket: ticket))
        }

        // Parse Welcome packet
        let sessionKey = w.data("session_key")
        let maxConn = Int(w.int("max_connection") ?? 1)
        let useCompress = (w.int("use_compress") ?? 0) != 0
        let useEncrypt = (w.int("use_encrypt") ?? 0) != 0
        let halfConn = (w.int("half_connection") ?? 0) != 0
        let qos = (w.int("qos") ?? 0) != 0
        let timeoutMs = max(Int(w.int("timeout") ?? 20000), 500)
        let message = w.data("Msg").map { String(decoding: $0, as: UTF8.self) }

        // Parse UDP acceleration fields
        let useUdp = (w.int("use_udp_acceleration") ?? 0) != 0
        let udpVer = Int(w.int("udp_acceleration_version") ?? 1)
        let udpServerPort = w.int("udp_acceleration_server_port").map { UInt16($0) }
        let udpServerCookie = w.int("udp_acceleration_server_cookie")
        let udpClientCookie = w.int("udp_acceleration_client_cookie")
        let udpKey = w.data("udp_acceleration_server_key_v2") ?? w.data("udp_acceleration_server_key")
        let udpFastDisconnect = (w.int("udp_accel_fast_disconnect_detect") ?? 0) != 0

        var udpServerIP: String?
        if let sIp = w.str("udp_acceleration_server_ip"), !sIp.isEmpty {
            udpServerIP = sIp
        } else if let sIpInt = w.int("udp_acceleration_server_ip") {
            udpServerIP = ipString(sIpInt)
        } else {
            udpServerIP = host
        }

        // Initialize active UdpAccel if negotiated
        if useUdp, let sPort = udpServerPort, let sCookie = udpServerCookie,
           let cCookie = udpClientCookie, let sKey = udpKey, sKey.count >= 32 {
            let realUdp = UdpAccel(
                serverIP: udpServerIP ?? host,
                serverPort: sPort,
                myCookie: cCookie,
                yourCookie: sCookie,
                myKeyV2: [UInt8](clientKeyV2),
                yourKeyV2: [UInt8](sKey)
            )
            if let realUdp = realUdp {
                realUdp.onFrame = { [weak self] frame in self?.onFrame?(frame) }
                realUdp.onByteCount = { [weak self] bIn, bOut in
                    if bIn > 0 { self?.add(in: bIn) }
                    if bOut > 0 { self?.add(out: bOut) }
                }
                realUdp.start()
                self.udpAccel = realUdp
            }
        }

        let wel = Welcome(
            sessionName: w.str("session_name") ?? "",
            connectionName: w.str("connection_name") ?? "",
            timeoutMs: timeoutMs,
            message: message,
            sessionKey: sessionKey,
            maxConnection: maxConn,
            useCompress: useCompress,
            useEncrypt: useEncrypt,
            halfConnection: halfConn,
            qos: qos,
            useUdpAcceleration: useUdp,
            udpAccelVersion: udpVer,
            udpServerIp: udpServerIP,
            udpServerPort: udpServerPort,
            udpServerCookie: udpServerCookie,
            udpClientCookie: udpClientCookie,
            udpServerKey: udpKey,
            udpFastDisconnect: udpFastDisconnect
        )

        // Add main stream to ConnectionPool
        pool.add(stream: activeStream, useCompress: useCompress, timeoutMs: timeoutMs)
        return (wel, nil)
    }

    private func uploadSignature(_ s: ByteStream, body: Data, host: String) async throws -> Pack {
        try await s.send(httpPost(path: "/vpnsvc/connect.cgi", type: "image/jpeg", body: body, host: host))
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

    private func httpPost(path: String, type: String, body: Data, host: String) -> Data {
        var h = "POST \(path) HTTP/1.1\r\nHost: \(host)\r\n"
        h += "Content-Type: \(type)\r\nConnection: Keep-Alive\r\nContent-Length: \(body.count)\r\n\r\n"
        return Data(h.utf8) + body
    }

    private func withDummy(_ p: Pack) -> Pack {
        var p = p
        p.addData("pencore", randomBytes(Int.random(in: 0..<1000)))
        return p
    }

    // MARK: - Login Pack

    func loginPack() -> Pack {
        (try? loginPack(random: Data(repeating: 0, count: 20), auth: self.auth)) ?? Pack()
    }

    func loginPack(
        random: Data = Data(repeating: 0, count: 20),
        auth: ClientAuth? = nil,
        host: String? = nil,
        port: UInt16? = nil,
        clientUdpPort: UInt16 = 0,
        clientKeyV1: Data = Data(repeating: 0, count: 20),
        clientKeyV2: Data = Data(repeating: 0, count: 128)
    ) throws -> Pack {
        var p = Pack()
        let auth = auth ?? self.auth
        let host = host ?? self.host
        let port = port ?? self.port
        let clientVer: UInt32 = 444, build: UInt32 = 9807
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osVer = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let hostname = ProcessInfo.processInfo.hostName
        let uid = randomBytes(20)

        p.addStr("method", "login")
        p.addStr("hubname", hubName)
        p.addStr("username", userName)

        // Authentication fields
        switch auth {
        case .anonymous:
            p.addInt("authtype", 0)
        case .hashedPassword(let pw):
            p.addInt("authtype", 1)
            let userUpper = userName.uppercased()
            let pwData = Array(pw.utf8) + Array(userUpper.utf8)
            let hashed = SHA0.hash(pwData)
            let secure = SHA0.hash(hashed + Array(random))
            p.addData("secure_password", Data(secure))
        case .plainPassword(let pw):
            p.addInt("authtype", 2)
            p.addStr("plain_password", pw)
        case .certificate(let certDer, let signBlock):
            p.addInt("authtype", 3)
            p.addData("cert", certDer)
            let signature = try signBlock(random)
            p.addData("sign", signature)
        case .ticket(let ticket):
            p.addInt("authtype", 99)
            p.addData("ticket", ticket)
        }

        p.addStr("client_str", "SoftEther VPN Client")
        p.addInt("client_ver", clientVer)
        p.addInt("client_build", build)
        p.addInt("protocol", 0)                       // TCP
        p.addStr("hello", "SoftEther VPN Client")
        p.addInt("version", clientVer)
        p.addInt("build", build)
        p.addInt("client_id", 0)
        p.addInt("max_connection", UInt32(maxConnectionsConfig))
        p.addBool("use_encrypt", true)
        p.addBool("use_compress", useCompressConfig)
        p.addBool("half_connection", false)
        p.addBool("require_bridge_routing_mode", false)
        p.addBool("require_monitor_mode", false)
        p.addBool("qos", false)
        p.addBool("support_bulk_on_rudp", true)
        p.addBool("support_hmac_on_bulk_of_rudp", true)
        p.addBool("support_udp_recovery", true)
        p.addData("unique_id", uid)

        // UDP Acceleration negotiation
        if useUdpAccelConfig {
            p.addBool("use_udp_acceleration", true)
            p.addIPv4("udp_acceleration_client_ip", 0)
            p.addInt("udp_acceleration_client_port", UInt32(clientUdpPort))
            p.addData("udp_acceleration_client_key", clientKeyV1)
            p.addData("udp_acceleration_client_key_v2", clientKeyV2)
            p.addBool("support_hmac_on_udp_acceleration", true)
            p.addBool("support_udp_accel_fast_disconnect_detect", true)
            p.addInt("udp_acceleration_version", 2)
            p.addInt("udp_acceleration_max_version", 2)
        }

        // Node info
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

    // MARK: - Data Services & Multi-TCP

    private func startDataServices(welcome: Welcome) {
        let timeoutMs = welcome.timeoutMs
        let useCompress = welcome.useCompress

        // 1. KeepAlive task
        keepAliveTask = Task.detached { [weak self] in
            while !Task.isCancelled {
                let lo = max(timeoutMs / 5, 1000), hi = max(timeoutMs / 2, lo + 1)
                try? await Task.sleep(nanoseconds: UInt64(Int.random(in: lo...hi)) * 1_000_000)
                guard let self = self, !Task.isCancelled else { return }
                let junk = self.randomBytes(Int.random(in: 0..<512))
                let packet = Data(DataPhase.encodeKeepAlive(junk: [UInt8](junk)))
                await self.pool.broadcastKeepAlive(packet)
            }
        }

        // 2. Open additional TCP connections if negotiated
        if welcome.maxConnection > 1, let sessionKey = welcome.sessionKey {
            let targetCount = min(welcome.maxConnection, self.maxConnectionsConfig)
            for i in 1..<targetCount {
                let task = Task.detached { [weak self] in
                    guard let self = self, !Task.isCancelled else { return }
                    try? await self.openAdditionalConnection(index: i, sessionKey: sessionKey, useCompress: useCompress, timeoutMs: timeoutMs)
                }
                additionalTasks.append(task)
            }
        }
    }

    private func openAdditionalConnection(
        index: Int,
        sessionKey: Data,
        useCompress: Bool,
        timeoutMs: Int
    ) async throws {
        guard !closed else { return }
        let s = makeStream(host, port, proxy)
        try await s.start()
        guard !closed else { s.cancel(); return }

        // Signature
        _ = try await uploadSignature(s, body: Data("VPNCONNECT".utf8), host: host)

        // Additional Connect Pack
        var p = Pack()
        p.addStr("method", "additional_connect")
        p.addData("session_key", sessionKey)
        p.addStr("client_str", "SoftEther VPN Client")
        p.addInt("client_ver", 444)
        p.addInt("client_build", 9807)
        p.addInt("direction", 0) // both

        try await s.send(httpPost(path: "/vpnsvc/vpn.cgi", type: "application/octet-stream", body: p.serialize(), host: host))
        let resp = try await readPack(s)
        if let err = resp.int("error"), err != 0 {
            s.cancel()
            return
        }

        guard !closed else { s.cancel(); return }
        pool.add(stream: s, useCompress: useCompress, timeoutMs: timeoutMs)
    }

    // MARK: - Send Frame

    func sendFrame(_ frame: [UInt8]) {
        guard frame.count <= Self.maxBlock, !closed else { return }

        // Try UDP acceleration first if usable
        if let udp = udpAccel, udp.isUsable {
            if udp.sendFrame(frame) {
                return
            }
        }

        // Fall back to TCP pool
        sendLock.lock()
        pending.append(frame)
        if flushing || closed { sendLock.unlock(); return }
        flushing = true
        sendLock.unlock()

        Task.detached { [weak self] in await self?.flush() }
    }

    private func takeBatch() -> [[UInt8]]? {
        sendLock.lock(); defer { sendLock.unlock() }
        let frames = Array(pending.prefix(64)); pending.removeFirst(frames.count)
        if frames.isEmpty { flushing = false; return nil }
        return frames
    }

    private func flush() async {
        while true {
            guard let frames = takeBatch() else { return }
            let useCompress = welcome?.useCompress ?? false
            let encoded = DataPhase.encode(frames: frames, useCompress: useCompress)
            let totalBytes = frames.reduce(0) { $0 + $1.count }
            do {
                try await pool.send(data: Data(encoded), byteCount: totalBytes)
            } catch {
                close(error)
                return
            }
        }
    }

    func close(_ error: Error?) {
        sendLock.lock()
        if closed { sendLock.unlock(); return }
        closed = true
        sendLock.unlock()

        keepAliveTask?.cancel()
        additionalTasks.forEach { $0.cancel() }
        udpAccel?.stop()
        pool.close(error)
        onClose?(error)
    }

    private var isClosed: Bool { sendLock.lock(); defer { sendLock.unlock() }; return closed }

    func randomBytes(_ n: Int) -> Data {
        var d = Data(count: n)
        _ = d.withUnsafeMutableBytes { SecRandomCopyBytes(kSecRandomDefault, n, $0.baseAddress!) }
        return d
    }
}
