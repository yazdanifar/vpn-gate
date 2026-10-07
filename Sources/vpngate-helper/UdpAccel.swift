import Foundation
import Network
import VPNGateCore

/// SoftEther UDP Acceleration (Version 2.0 with ChaCha20-Poly1305 AEAD).
/// Reference: SoftEther src/Cedar/UdpAccel.c.
final class UdpAccel {
    public static let keepAliveIntervalMs: UInt64 = 1000 // 1 second
    public static let keepAliveTimeoutFastMs: UInt64 = 2100 // 2.1 seconds

    private let serverIP: String
    private let serverPort: UInt16
    private let myCookie: UInt32
    private let yourCookie: UInt32
    private let myKeyV2: [UInt8]   // 128 bytes, first 32 used for ChaCha20-Poly1305
    private let yourKeyV2: [UInt8] // 128 bytes, first 32 used for ChaCha20-Poly1305

    private var fd: Int32 = -1
    private var nextIv: [UInt8]
    private var lastRecvTick: UInt64 = 0
    private var lastRecvYourTick: UInt64 = 0
    private let lock = NSLock()
    private var isClosed = false
    private var receiveTask: Task<Void, Never>?
    private var keepAliveTask: Task<Void, Never>?

    var onFrame: (([UInt8]) -> Void)?
    var onByteCount: ((_ bytesIn: Int, _ bytesOut: Int) -> Void)?

    init?(
        serverIP: String,
        serverPort: UInt16,
        myCookie: UInt32,
        yourCookie: UInt32,
        myKeyV2: [UInt8],
        yourKeyV2: [UInt8]
    ) {
        self.serverIP = serverIP
        self.serverPort = serverPort
        self.myCookie = myCookie
        self.yourCookie = yourCookie
        self.myKeyV2 = myKeyV2
        self.yourKeyV2 = yourKeyV2

        // Initial 12-byte random IV
        var iv = [UInt8](repeating: 0, count: UdpAccelPacket.ivSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)
        self.nextIv = iv

        let s = socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else { return nil }
        self.fd = s

        // Set non-blocking socket
        var flags = fcntl(s, F_GETFL, 0)
        _ = fcntl(s, F_SETFL, flags | O_NONBLOCK)

        // Bind to port 0
        var sin = sockaddr_in()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = 0
        sin.sin_addr.s_addr = INADDR_ANY
        let rc = withUnsafePointer(to: &sin) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        guard rc == 0 else {
            closeSocket()
            return nil
        }
    }

    deinit {
        stop()
    }

    var localPort: UInt16 {
        guard fd >= 0 else { return 0 }
        var sin = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let rc = withUnsafeMutablePointer(to: &sin) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard rc == 0 else { return 0 }
        return UInt16(bigEndian: sin.sin_port)
    }

    var isUsable: Bool {
        lock.lock(); defer { lock.unlock() }
        guard !isClosed, lastRecvTick > 0 else { return false }
        let now = nowTickMs()
        return (now >= lastRecvTick) && (now - lastRecvTick < Self.keepAliveTimeoutFastMs)
    }

    func start() {
        startReceiving()
        startKeepAlives()
    }

    func stop() {
        lock.lock()
        if isClosed { lock.unlock(); return }
        isClosed = true
        lock.unlock()

        receiveTask?.cancel()
        keepAliveTask?.cancel()
        closeSocket()
    }

    private func closeSocket() {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }

    // MARK: - Send Frame

    func sendFrame(_ frame: [UInt8]) -> Bool {
        guard isUsable else { return false }
        return sendPacket(flag: .data, payload: frame)
    }

    private func sendPacket(flag: UdpAccelFlag, payload: [UInt8]) -> Bool {
        lock.lock()
        guard !isClosed, fd >= 0 else { lock.unlock(); return false }
        let iv = nextIv
        let yourTick = lastRecvYourTick
        let myTick = nowTickMs()
        let cookie = yourCookie
        let key = myKeyV2
        lock.unlock()

        guard let (packet, newIV) = try? UdpAccelPacket.encode(
            key32: key,
            iv: iv,
            cookie: cookie,
            myTick: myTick,
            yourTick: yourTick,
            flag: flag,
            payload: payload
        ) else {
            return false
        }

        lock.lock()
        nextIv = newIV
        let currentFd = fd
        lock.unlock()

        guard currentFd >= 0 else { return false }

        var sin = sockaddr_in()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = serverPort.bigEndian
        inet_pton(AF_INET, serverIP, &sin.sin_addr)

        let sent = withUnsafePointer(to: &sin) { sinPtr in
            sinPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                packet.withUnsafeBytes { dataPtr in
                    sendto(currentFd, dataPtr.baseAddress!, packet.count, 0, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size))
                }
            }
        }

        if sent > 0 {
            onByteCount?(0, payload.count)
            return true
        }
        return false
    }

    // MARK: - Receive Loop

    private func startReceiving() {
        receiveTask = Task.detached { [weak self] in
            var buf = [UInt8](repeating: 0, count: 2048)
            while !Task.isCancelled {
                guard let self = self else { return }
                self.lock.lock()
                let currentFd = self.fd
                let closed = self.isClosed
                let key = self.yourKeyV2
                let expectedCookie = self.myCookie
                self.lock.unlock()

                guard !closed, currentFd >= 0 else { return }

                var pfd = pollfd(fd: currentFd, events: Int16(POLLIN), revents: 0)
                let pollRc = poll(&pfd, 1, 500)
                if pollRc <= 0 { continue }

                var from = sockaddr_in()
                var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
                let n = withUnsafeMutablePointer(to: &from) {
                    $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                        recvfrom(currentFd, &buf, buf.count, 0, $0, &fromLen)
                    }
                }

                guard n >= UdpAccelPacket.minPacketSize else { continue }
                let raw = Array(buf.prefix(n))

                guard let decoded = try? UdpAccelPacket.decode(packet: raw, key32: key) else {
                    continue
                }

                // Verify cookie
                guard decoded.header.cookie == expectedCookie else { continue }

                let now = self.nowTickMs()
                self.lock.lock()
                self.lastRecvTick = now
                self.lastRecvYourTick = decoded.header.myTick
                self.lock.unlock()

                if decoded.header.flag == .data, !decoded.payload.isEmpty {
                    self.onByteCount?(decoded.payload.count, 0)
                    self.onFrame?(decoded.payload)
                }
            }
        }
    }

    // MARK: - Keep-Alive Loop

    private func startKeepAlives() {
        keepAliveTask = Task.detached { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { return }
                _ = self.sendPacket(flag: .keepAlive, payload: [])
                try? await Task.sleep(nanoseconds: Self.keepAliveIntervalMs * 1_000_000)
            }
        }
    }

    private func nowTickMs() -> UInt64 {
        UInt64(max(0, Date().timeIntervalSince1970 * 1000.0))
    }
}
