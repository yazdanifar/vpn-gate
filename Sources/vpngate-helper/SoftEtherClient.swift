import Foundation
import VPNGateCore

public enum ClientAuth {
    case anonymous
    case plainPassword(String)
    /// Standard password (authtype 1). Takes the PLAINTEXT password; the SHA-0 hashing happens in `loginPack`.
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
    /// Server `enable_udp_recovery`: when set the server's max_connection is not capped by the client's setting.
    public var enableUdpRecovery: Bool

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
        timeoutMs: Int = 30000,
        message: String? = nil,
        sessionKey: Data? = nil,
        maxConnection: Int = 1,
        useCompress: Bool = false,
        useEncrypt: Bool = true,
        halfConnection: Bool = false,
        qos: Bool = false,
        enableUdpRecovery: Bool = false,
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
        self.enableUdpRecovery = enableUdpRecovery
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
    private let disableQoS: Bool
    /// Whether we requested half connection in the login pack (Protocol.c: half_connection in the login Pack,
    /// read verbatim by the server, no negotiation). Only additional connections can be assigned a one-way
    /// direction; the primary connection is always client-to-server when this is on (Protocol.c:4172-4176).
    private let halfConnectionConfig: Bool
    private let loginUniqueId: Data                 // 20 bytes, stable per install
    private let nodeUniqueId: Data                  // 16 bytes
    /// Set when the server rejected the watermark upload and the plain one was used; additional connections then match.
    private var plainSignature = false
    /// IPv4 address the TCP/TLS connection of the established session really went to (nil behind a proxy or if unknown).
    private var connectedIPv4: String?
    private let makeStream: StreamFactory

    private let pool = ConnectionPool()
    private var udpAccel: UdpAccel?                  // guarded by sendLock together with closed and the task handles
    private var replenishTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?
    /// Poll/backoff base for topping up the additional-connection pool (tests shorten it).
    var replenishInterval: Double = 1.0

    /// Frames waiting for the TCP pool; beyond this they are dropped like a full interface queue (~13 MB of frames).
    static let maxPendingFrames = 4096
    private let sendLock = NSLock()
    private var pending: [[UInt8]] = []
    private var flushing = false
    private var closed = false
    private var _droppedFrames = 0
    var droppedFrames: Int { sendLock.lock(); defer { sendLock.unlock() }; return _droppedFrames }
    var pendingFrameCount: Int { sendLock.lock(); defer { sendLock.unlock() }; return pending.count }
    var activeConnectionCount: Int { pool.activeCount }
    var udpLocalPort: UInt16 { sendLock.lock(); let u = udpAccel; sendLock.unlock(); return u?.localPort ?? 0 }
    /// Whether frames are actually eligible to go over UDP right now (stable receive for ~10 s; see UdpAccel.isUsable).
    public var udpAccelUsable: Bool { sendLock.lock(); let u = udpAccel; sendLock.unlock(); return u?.isUsable ?? false }
    /// Whether the server negotiated UDP acceleration at all (welcome's use_udp_acceleration + a v2 key), regardless
    /// of whether it has become usable yet.
    public var udpAccelNegotiated: Bool { sendLock.lock(); let u = udpAccel; sendLock.unlock(); return u != nil }

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
        disableQoS: Bool = false,
        halfConnection: Bool = false,
        uniqueId: HostUniqueId? = nil,
        serverCertPolicy: ServerCertPolicy = .acceptAny,
        makeStream: StreamFactory? = nil
    ) {
        self.host = host
        self.port = port
        self.hubName = hubName
        self.userName = userName
        self.auth = auth
        self.proxy = proxy
        // Half connection needs separate send/receive sockets; request at least 4 (upstream's own minimum, Protocol.c:6022).
        self.maxConnectionsConfig = max(halfConnection ? 4 : 1, min(maxConnections, 32))
        self.useCompressConfig = useCompress
        self.useUdpAccelConfig = useUdpAccel
        self.disableQoS = disableQoS
        self.halfConnectionConfig = halfConnection
        let uid = uniqueId ?? HostUniqueId(key: HostUniqueId.secureRandom(32))
        self.loginUniqueId = uid.loginId
        self.nodeUniqueId = uid.nodeId
        self.makeStream = makeStream ?? { TLSStream(host: $0, port: $1, proxy: $2, policy: serverCertPolicy) }

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
        var activeStream: ByteStream = makeStream(host, port, proxy)
        var tempUdp: UdpAccel?
        var handedOff = false
        // Whatever this attempt opened is released on every exit path that did not hand it to the pool / client.
        defer {
            if !handedOff { activeStream.cancel() }
            tempUdp?.stop()
        }
        try await activeStream.start()
        if isClosed { throw StreamError.closed }
        log("TLS established with \(host):\(port)")

        // 1. Signature upload
        var hello: Pack
        do {
            hello = try await uploadSignature(activeStream, body: signatureBody(), host: host)
        } catch {
            log("Signature rejected (\(error.localizedDescription)); retrying plain")
            activeStream.cancel()
            activeStream = makeStream(host, port, proxy)
            try await activeStream.start()
            hello = try await uploadSignature(activeStream, body: Data("VPNCONNECT".utf8), host: host)
            plainSignature = true
        }

        guard let random = hello.data("random"), random.count == 20 else {
            throw StreamError.protocolError("Server hello missing random (not a SoftEther server?)")
        }
        log("Server: \(hello.str("hello") ?? "?") v\(hello.int("version") ?? 0) build \(hello.int("build") ?? 0)")
        let serverInfo = (name: hello.str("hello") ?? "", ver: hello.int("version") ?? 0, build: hello.int("build") ?? 0)

        // UDP acceleration: the socket is bound now so its port can be advertised; the server side is filled in from the welcome.
        let clientKeyV1 = randomBytes(20)
        let clientKeyV2 = randomBytes(128)
        if useUdpAccelConfig { tempUdp = UdpAccel(myKeyV2: [UInt8](clientKeyV2)) }

        // 2. Login
        let login = try loginPack(
            random: random,
            auth: auth,
            host: host,
            port: port,
            clientUdpPort: tempUdp?.localPort ?? 0,
            clientKeyV1: clientKeyV1,
            clientKeyV2: clientKeyV2,
            serverInfo: serverInfo
        )

        try await activeStream.send(httpPost(path: "/vpnsvc/vpn.cgi", type: "application/octet-stream",
                                             body: withDummy(login).serialize(), host: host))
        let w = try await readPack(activeStream)

        if let err = w.int("error"), err != 0 {
            throw StreamError.protocolError("Server refused login: \(SoftEtherError.describe(Int(err)))")
        }

        // Handle Cluster Redirect
        if (w.int("Redirect") ?? 0) != 0 {
            guard let ticket = w.data("Ticket"), ticket.count == 20 else {
                throw StreamError.protocolError("Cluster redirect missing 20-byte ticket")
            }
            let redirectIP = try Self.redirectHost(from: w, fallback: host)
            var redirectPort = port
            // "Port" is a list: the original client keeps the port it is already using if the server offers it,
            // otherwise takes the first one (client_exe.c:53335-53370).
            let offered = w.ints("Port")
            if !offered.isEmpty {
                let chosen = offered.contains(UInt32(port)) ? UInt32(port) : offered[0]
                guard let p = Self.validPort(chosen) else {
                    throw StreamError.protocolError("Cluster redirect to an invalid port (\(chosen))")
                }
                redirectPort = p
            }
            return (nil, RedirectInfo(host: redirectIP, port: redirectPort, ticket: ticket))
        }

        // Parse Welcome packet; without a session name and key nothing after this could work (upstream ParseWelcome fails the same way).
        // (upstream also asks for the policy:* elements, but PackGetPolicy never fails, so nothing is required of them.)
        guard let sessionName = w.str("session_name"), !sessionName.isEmpty,
              let connectionName = w.str("connection_name"),
              let sessionKey = w.data("session_key"), sessionKey.count == 20 else {
            throw StreamError.protocolError("Malformed welcome from server (missing session_name, connection_name or session_key)")
        }
        let useCompress = (w.int("use_compress") ?? 0) != 0
        let useEncrypt = (w.int("use_encrypt") ?? 0) != 0
        let halfConn = (w.int("half_connection") ?? 0) != 0
        let qos = (w.int("qos") ?? 0) != 0
        let enableUdpRecovery = (w.int("enable_udp_recovery") ?? 0) != 0
        let maxConn = Self.negotiatedMaxConnection(server: Int(w.int("max_connection") ?? 1), enableUdpRecovery: enableUdpRecovery,
                                                   client: maxConnectionsConfig, qos: qos, half: halfConn)
        let timeoutMs = max(Int(w.int("timeout") ?? 30000), 500)
        let message = w.data("Msg").map { String(decoding: $0, as: UTF8.self) }

        // Parse UDP acceleration fields. A bad value only disables UDP; the TCP session is unaffected.
        let useUdp = (w.int("use_udp_acceleration") ?? 0) != 0
        let udpVer = Int(w.int("udp_acceleration_version") ?? 1)
        let udpServerPort = w.int("udp_acceleration_server_port").flatMap(Self.validPort)
        let udpServerCookie = w.int("udp_acceleration_server_cookie")
        let udpClientCookie = w.int("udp_acceleration_client_cookie")
        let udpKey = w.data("udp_acceleration_server_key_v2")
        let udpFastDisconnect = (w.int("udp_accel_fast_disconnect_detect") ?? 0) != 0
        // Plaintext mode only when the server says so explicitly (upstream PlainTextMode = !udp_acceleration_use_encryption).
        let udpPlaintext = w.int("udp_acceleration_use_encryption").map { $0 == 0 } ?? false

        var advertisedIP: String?
        if let sIp = w.str("udp_acceleration_server_ip"), !sIp.isEmpty {
            advertisedIP = sIp
        } else if let sIpInt = w.int("udp_acceleration_server_ip"), !Self.isIPv6Flagged(w, "udp_acceleration_server_ip") {
            advertisedIP = packIPString(sIpInt)
        }
        let udpServerIP = Self.resolveUdpServerIP(advertised: advertisedIP, tcpHost: host)

        // Activate the UdpAccel that was advertised in the login pack (its bound port is what the server will send to).
        // Only the v2 key path is implemented; cookies must be nonzero (Protocol.c:6177-6270).
        if useUdp, let udp = tempUdp {
            let secondary = InputValidation.isIPv4Literal(host) && !InputValidation.isNonPublicIPv4(host) ? host : nil
            if udpVer == 2, let ip = udpServerIP, let sPort = udpServerPort, let sCookie = udpServerCookie, sCookie != 0,
               let cCookie = udpClientCookie, cCookie != 0, let sKey = udpKey ?? (udpPlaintext ? Data() : nil),
               udp.configure(serverIP: ip, serverPort: sPort, myCookie: UInt32(truncatingIfNeeded: cCookie),
                             yourCookie: UInt32(truncatingIfNeeded: sCookie), yourKeyV2: [UInt8](sKey),
                             fastDisconnect: udpFastDisconnect, useCompress: useCompress, plaintext: udpPlaintext,
                             secondaryIP: secondary) {
                udp.onFrame = { [weak self] frame in self?.onFrame?(frame) }
                udp.onByteCount = { [weak self] bIn, bOut in
                    if bIn > 0 { self?.add(in: bIn) }
                    if bOut > 0 { self?.add(out: bOut) }
                }
                tempUdp = nil          // ownership moves to self
                if installUdp(udp) { udp.start() }
            } else {
                log("UDP acceleration offered but unusable; using TCP only")
            }
        }

        let wel = Welcome(
            sessionName: sessionName,
            connectionName: connectionName,
            timeoutMs: timeoutMs,
            message: message,
            sessionKey: sessionKey,
            maxConnection: maxConn,
            useCompress: useCompress,
            useEncrypt: useEncrypt,
            halfConnection: halfConn,
            qos: qos,
            enableUdpRecovery: enableUdpRecovery,
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
        handedOff = true
        setConnectedIPv4(activeStream.remoteIPv4)
        // The primary connection is always client-to-server when half connection is on (Protocol.c:4172-4176);
        // the server-to-client direction is only ever assigned to an additional connection.
        pool.add(stream: activeStream, useCompress: useCompress, timeoutMs: timeoutMs,
                 direction: halfConnectionConfig ? .clientToServer : .both)
        return (wel, nil)
    }

    private func setConnectedIPv4(_ ip: String?) { sendLock.lock(); connectedIPv4 = ip; sendLock.unlock() }

    /// Stores the active UdpAccel; false (and the accel is stopped) if the client was closed meanwhile.
    private func installUdp(_ udp: UdpAccel) -> Bool {
        sendLock.lock(); defer { sendLock.unlock() }
        if closed { udp.stop(); return false }
        udpAccel = udp
        return true
    }

    // MARK: - Welcome field validation (hostile servers: TLS verification is off for VPN Gate relays)

    /// Session size per upstream (Protocol.c ClientConnectGetSessionKey): the server's value, capped by the client's own
    /// setting unless the server offers UDP recovery, clamped to 1...32, and at least 2 (4 with half connection) under QoS.
    static func negotiatedMaxConnection(server: Int, enableUdpRecovery: Bool, client: Int, qos: Bool, half: Bool) -> Int {
        var n = server
        if !enableUdpRecovery { n = min(n, client) }
        n = max(1, min(n, 32))
        if qos { n = max(n, half ? 4 : 2) }
        return n
    }

    static func validPort(_ raw: UInt32) -> UInt16? {
        UInt16(exactly: raw).flatMap { $0 == 0 ? nil : $0 }
    }

    private static func isIPv6Flagged(_ w: Pack, _ name: String) -> Bool { (w.int(name + "@ipv6_bool") ?? 0) != 0 }

    /// Redirect target from the pack's `Ip`: a hostname/IPv4 string, or SoftEther's pack integer. 0.0.0.0 / absent = same host.
    static func redirectHost(from w: Pack, fallback: String) throws -> String {
        if isIPv6Flagged(w, "Ip") { throw StreamError.protocolError("Cluster redirect to an IPv6 address is not supported") }
        let candidate: String
        if let ipStr = w.str("Ip"), !ipStr.isEmpty { candidate = ipStr }
        else if let ipInt = w.int("Ip") { candidate = packIPString(ipInt) }
        else { return fallback }
        guard InputValidation.isValidHost(candidate) else {
            throw StreamError.protocolError("Cluster redirect to an invalid host")
        }
        return candidate == "0.0.0.0" ? fallback : candidate
    }

    /// The UDP endpoint to use: the advertised IPv4 if it is a public literal, else the TCP peer
    /// (unspecified/private advertisements are the server's own view of itself behind NAT). nil if neither is an IPv4 literal.
    static func resolveUdpServerIP(advertised: String?, tcpHost: String) -> String? {
        if let a = advertised, InputValidation.isIPv4Literal(a), !InputValidation.isNonPublicIPv4(a) { return a }
        return InputValidation.isIPv4Literal(tcpHost) ? tcpHost : nil
    }

    /// The signature body of every connection: the watermark plus random padding (HTTP_PACK_RAND_SIZE_MAX*2), or the plain
    /// marker when the server refused the watermark on the first connection.
    private func signatureBody() -> Data {
        plainSignature ? Data("VPNCONNECT".utf8) : softEtherWaterMark + randomBytes(Int.random(in: 0..<2000))
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

    /// Upstream `Upper()` only maps a-z; Swift's `uppercased()` would also change non-ASCII letters and break the hash.
    static func asciiUppercased(_ s: String) -> String {
        String(decoding: s.utf8.map { $0 >= 97 && $0 <= 122 ? $0 - 32 : $0 }, as: UTF8.self)
    }

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
        clientKeyV2: Data = Data(repeating: 0, count: 128),
        serverInfo: (name: String, ver: UInt32, build: UInt32) = ("", 0, 0)
    ) throws -> Pack {
        var p = Pack()
        let auth = auth ?? self.auth
        let host = host ?? self.host
        let port = port ?? self.port
        let clientVer: UInt32 = 444, build: UInt32 = 9807
        let os = ProcessInfo.processInfo.operatingSystemVersion
        let osVer = "\(os.majorVersion).\(os.minorVersion).\(os.patchVersion)"
        let hostname = ProcessInfo.processInfo.hostName

        p.addStr("method", "login")
        p.addStr("hubname", hubName)
        p.addStr("username", userName)

        // Authentication fields
        switch auth {
        case .anonymous:
            p.addInt("authtype", 0)
        case .hashedPassword(let pw):
            p.addInt("authtype", 1)
            let pwData = Array(pw.utf8) + Array(Self.asciiUppercased(userName).utf8)
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
        p.addBool("half_connection", halfConnectionConfig)
        p.addBool("require_bridge_routing_mode", false)
        p.addBool("require_monitor_mode", false)
        p.addBool("qos", !disableQoS)                // upstream: !DisableQoS
        p.addBool("support_bulk_on_rudp", true)
        p.addBool("support_hmac_on_bulk_of_rudp", true)
        p.addBool("support_udp_recovery", true)
        p.addData("unique_id", loginUniqueId)

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
        p.addInt("rudp_bulk_max_version", 2)

        // Node info
        p.addStr("ClientProductName", "SoftEther VPN Client")
        p.addStr("ServerProductName", serverInfo.name)
        p.addStr("ClientOsName", "macOS")
        p.addStr("ClientOsVer", osVer)
        p.addStr("ClientOsProductId", "")
        p.addStr("ClientHostname", hostname)
        p.addStr("ServerHostname", host)
        p.addStr("ProxyHostname", proxy.kind == .none ? "" : proxy.host)
        p.addData("UniqueId", nodeUniqueId)
        p.addInt("ClientProductVer", clientVer)
        p.addInt("ClientProductBuild", build)
        p.addInt("ServerProductVer", serverInfo.ver)
        p.addInt("ServerProductBuild", serverInfo.build)
        p.addInt("ClientPort", 0)
        p.addInt("ServerPort2", UInt32(port))
        p.addInt("ProxyPort", UInt32(clamping: max(0, proxy.port)))
        p.addIPv4("ClientIpAddress", 0)
        p.addIPv4("ServerIpAddress", 0)
        p.addIPv4("ProxyIpAddress", 0)
        for name in ["ClientIpAddress6", "ServerIpAddress6", "ProxyIpAddress6"] { p.addData(name, Data(count: 16)) }
        return p
    }

    // MARK: - Data Services & Multi-TCP

    /// Hosts that must stay reachable outside a full tunnel: the host the session really ended up on (after cluster
    /// redirects; none when a proxy carries the TCP traffic) and the UDP acceleration endpoint.
    /// The IPv4 address the established session's TLS connection went to (nil behind a proxy or when unknown).
    var remoteIPv4: String? {
        sendLock.lock(); defer { sendLock.unlock() }
        return proxy.kind == .none ? connectedIPv4 : nil
    }

    var bypassHosts: [String] {
        sendLock.lock(); defer { sendLock.unlock() }
        var out = [String]()
        if proxy.kind == .none { out.append(connectedIPv4 ?? host) }
        if udpAccel != nil, let ip = welcome?.udpServerIp, !out.contains(ip) { out.append(ip) }
        return out
    }

    private func startDataServices(welcome: Welcome) {
        let timeoutMs = welcome.timeoutMs
        let useCompress = welcome.useCompress

        // 1. KeepAlive task
        let keepAlive = Task.detached { [weak self] in
            while !Task.isCancelled {
                let lo = max(timeoutMs / 5, 1000), hi = max(timeoutMs / 2, lo + 1)
                try? await Task.sleep(nanoseconds: UInt64(Int.random(in: lo...hi)) * 1_000_000)
                guard let self = self, !Task.isCancelled else { return }
                let junk = self.randomBytes(Int.random(in: 0..<512))
                let packet = Data(DataPhase.encodeKeepAlive(junk: [UInt8](junk)))
                await self.pool.broadcastKeepAlive(packet)
            }
        }

        // 2. Keep the pool at the negotiated size: open the additional TCP connections and replace any that die.
        var replenish: Task<Void, Never>?
        if welcome.maxConnection > 1, let sessionKey = welcome.sessionKey {
            let target = welcome.maxConnection          // already capped / raised by negotiatedMaxConnection
            replenish = Task.detached { [weak self] in
                await self?.replenishLoop(target: target, sessionKey: sessionKey, useCompress: useCompress, timeoutMs: timeoutMs)
            }
        }

        sendLock.lock()
        if closed { sendLock.unlock(); keepAlive.cancel(); replenish?.cancel(); return }
        keepAliveTask = keepAlive
        replenishTask = replenish
        sendLock.unlock()
    }

    private func replenishLoop(target: Int, sessionKey: Data, useCompress: Bool, timeoutMs: Int) async {
        var failures = 0
        while !Task.isCancelled && !isClosed {
            if pool.activeCount >= target {
                try? await Task.sleep(nanoseconds: UInt64(replenishInterval * 1_000_000_000))
                continue
            }
            do {
                try await openAdditionalConnection(sessionKey: sessionKey, useCompress: useCompress, timeoutMs: timeoutMs)
                failures = 0
            } catch {
                if isClosed { return }
                failures += 1
                let delay = min(replenishInterval * pow(2, Double(min(failures - 1, 5))), 30)
                try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
            }
        }
    }

    private func openAdditionalConnection(sessionKey: Data, useCompress: Bool, timeoutMs: Int) async throws {
        guard !isClosed else { return }
        let (host, port) = (self.host, self.port)
        let s = makeStream(host, port, proxy)
        var added = false
        defer { if !added { s.cancel() } }
        try await s.start()
        guard !isClosed else { return }

        // Signature: same upload as the first connection (ClientUploadSignature), then the server hello is discarded.
        _ = try await uploadSignature(s, body: signatureBody(), host: host)

        // Additional Connect Pack (PackAddClientVersion + the pencore HttpClientSend appends to every pack)
        var p = Pack()
        p.addStr("method", "additional_connect")
        p.addData("session_key", sessionKey)
        p.addStr("client_str", "SoftEther VPN Client")
        p.addInt("client_ver", 444)
        p.addInt("client_build", 9807)

        try await s.send(httpPost(path: "/vpnsvc/vpn.cgi", type: "application/octet-stream", body: withDummy(p).serialize(), host: host))
        let resp = try await readPack(s)
        if let err = resp.int("error"), err != 0 {
            throw StreamError.protocolError("Additional connection refused: \(SoftEtherError.describe(Int(err)))")
        }

        // The reply's `direction` (0 both, 1 server->client, 2 client->server) is chosen by the server, only when
        // half connection was requested; absent/0 means both ways, same as a normal connection (Protocol.c:5257).
        let direction = ConnectionPool.SocketDirection(wireValue: resp.int("direction"))
        guard !isClosed else { return }
        added = true
        pool.add(stream: s, useCompress: useCompress, timeoutMs: timeoutMs, direction: direction)
    }

    // MARK: - Send Frame

    func sendFrame(_ frame: [UInt8]) {
        guard frame.count <= Self.maxBlock else { return }

        sendLock.lock()
        if closed { sendLock.unlock(); return }
        let udp = udpAccel
        sendLock.unlock()

        // Try UDP acceleration first if usable
        if let udp = udp, udp.isUsable {
            if udp.sendFrame(frame) {
                return
            }
        }

        // Fall back to TCP pool
        sendLock.lock()
        if pending.count >= Self.maxPendingFrames { _droppedFrames += 1; sendLock.unlock(); return }
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
            let totalBytes = frames.reduce(0) { $0 + $1.count }
            do {
                let encoded = try DataPhase.encode(frames: frames, useCompress: useCompress)
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
        let (keepAlive, replenish, udp) = (keepAliveTask, replenishTask, udpAccel)
        keepAliveTask = nil; replenishTask = nil
        sendLock.unlock()

        keepAlive?.cancel()
        replenish?.cancel()
        udp?.stop()
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
