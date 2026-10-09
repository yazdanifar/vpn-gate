import Foundation
import VPNGateCore

/// SoftEther UDP Acceleration (Version 2.0 with ChaCha20-Poly1305 AEAD).
/// Reference: SoftEther src/Cedar/UdpAccel.c, UdpAccel.h.
///
/// Two-phase life cycle: `init` binds the local socket early (its port is advertised in the login pack), and
/// `configure` supplies the server's endpoint, cookies and key once the welcome arrives.
final class UdpAccel {
    // UdpAccel.h: KEEPALIVE_INTERVAL_MIN/MAX/TIMEOUT (legacy) and the *_FAST variants, WINDOW_SIZE_MSEC.
    // The interval is `rand() % (max - min) + min` (UdpAccel.c:285 area), so the maximum is exclusive.
    static let keepAliveIntervalMs: Range<UInt64> = 1000..<3000
    static let keepAliveIntervalFastMs: Range<UInt64> = 500..<1000
    static let keepAliveTimeoutMs: UInt64 = 9000
    static let keepAliveTimeoutFastMs: UInt64 = 2100
    static let windowMs: UInt64 = 30_000
    /// How long packets must arrive without a gap before UDP carries data: UDP_ACCELERATION_REQUIRE_CONTINUOUS
    /// (UdpAccel.h:123, confirmed in the Windows client as `FirstStableReceiveTick + 10000 <= Now`).
    static let stableReceiveMs: UInt64 = 10_000
    /// Upstream max_size passed to UdpAccelSend: 1000 for keep-alives (UdpAccel.c:285), MaxUdpPacketSize = 1454 - 20 - 8
    /// for data (UdpAccel.c:1170-1186). It only bounds the random zero padding.
    static let keepAliveMaxSize = 1000
    static let dataMaxSize = 1454 - 20 - 8

    static func monotonicMs() -> UInt64 { DispatchTime.now().uptimeNanoseconds / 1_000_000 }
    /// Time source in milliseconds; tests replace it.
    var clock: () -> UInt64 = UdpAccel.monotonicMs

    private let myKeyV2: [UInt8]   // 128 bytes, first 32 used for ChaCha20-Poly1305

    private let lock = NSLock()
    private var yourKeyV2: [UInt8] = []
    private var myCookie: UInt32 = 0
    private var yourCookie: UInt32 = 0
    private var dest = sockaddr_in()
    private var dest2: sockaddr_in?                 // the TCP peer IP (upstream YourIp2); keep-alives also go there while UDP is not usable
    private var useCompress = false                  // the session negotiated use_compress: data goes out zlib-compressed, flag 1
    private var plainMode = false                    // udp_acceleration_use_encryption == false: no IV/AEAD/MAC (PlainTextMode)
    private var configured = false
    private var fastDisconnect = false

    private var fd: Int32 = -1
    private var wakeRead: Int32 = -1, wakeWrite: Int32 = -1     // self-pipe: stop() wakes the receive thread
    private var started = false
    private var isClosed = false
    private var nextIv: [UInt8]
    private var lastRecvTick: UInt64 = 0         // when the last valid packet arrived (local clock)
    private var lastRecvMyTick: UInt64 = 0       // highest of our own ticks the peer echoed back
    private var lastRecvYourTick: UInt64 = 0     // highest peer tick seen; echoed in everything we send
    private var firstStableReceiveTick: UInt64 = 0
    private var keepAliveTask: Task<Void, Never>?

    var onFrame: (([UInt8]) -> Void)?
    var onByteCount: ((_ bytesIn: Int, _ bytesOut: Int) -> Void)?

    init?(myKeyV2: [UInt8]) {
        self.myKeyV2 = myKeyV2

        // Initial 12-byte random IV
        var iv = [UInt8](repeating: 0, count: UdpAccelPacket.ivSize)
        _ = SecRandomCopyBytes(kSecRandomDefault, iv.count, &iv)
        self.nextIv = iv

        let s = socket(AF_INET, SOCK_DGRAM, 0)
        guard s >= 0 else { return nil }
        _ = fcntl(s, F_SETFL, fcntl(s, F_GETFL, 0) | O_NONBLOCK)

        var sin = sockaddr_in()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = 0
        sin.sin_addr.s_addr = INADDR_ANY
        let rc = withUnsafePointer(to: &sin) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
        }
        var pipeFDs: [Int32] = [-1, -1]
        guard rc == 0, pipe(&pipeFDs) == 0 else { Darwin.close(s); return nil }
        self.fd = s
        wakeRead = pipeFDs[0]; wakeWrite = pipeFDs[1]
    }

    deinit { stop() }

    var localPort: UInt16 {
        lock.lock(); defer { lock.unlock() }
        guard fd >= 0 else { return 0 }
        var sin = sockaddr_in()
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        let rc = withUnsafeMutablePointer(to: &sin) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        return rc == 0 ? UInt16(bigEndian: sin.sin_port) : 0
    }

    /// Highest peer tick accepted so far, and the endpoint we currently send to (diagnostics and tests).
    var lastPeerTick: UInt64 { lock.lock(); defer { lock.unlock() }; return lastRecvYourTick }
    var peerPort: UInt16 { lock.lock(); defer { lock.unlock() }; return UInt16(bigEndian: dest.sin_port) }

    /// True once the socket has really been closed (by `stop()` or, after `start()`, by the receive thread on exit).
    var isSocketClosed: Bool { lock.lock(); defer { lock.unlock() }; return fd < 0 }

    /// Supplies the server side. Fails (UDP stays off, TCP carries on) for a non-IPv4-literal or unspecified address,
    /// port 0, or (unless `plaintext`) a key shorter than 32 bytes. `secondaryIP` is the TCP peer address; an unusable
    /// value is ignored (the caller decides whether it is public).
    @discardableResult
    func configure(serverIP: String, serverPort: UInt16, myCookie: UInt32, yourCookie: UInt32,
                   yourKeyV2: [UInt8], fastDisconnect: Bool, useCompress: Bool = false, plaintext: Bool = false,
                   secondaryIP: String? = nil) -> Bool {
        var sin = sockaddr_in()
        sin.sin_family = sa_family_t(AF_INET)
        sin.sin_port = serverPort.bigEndian
        guard serverPort != 0, plaintext || yourKeyV2.count >= 32, inet_pton(AF_INET, serverIP, &sin.sin_addr) == 1,
              sin.sin_addr.s_addr != 0 else { return false }
        var sin2: sockaddr_in?
        if let ip2 = secondaryIP {
            var a = sockaddr_in()
            a.sin_family = sa_family_t(AF_INET)
            a.sin_port = serverPort.bigEndian
            if inet_pton(AF_INET, ip2, &a.sin_addr) == 1, a.sin_addr.s_addr != 0 { sin2 = a }
        }
        lock.lock(); defer { lock.unlock() }
        guard !isClosed else { return false }
        dest = sin
        dest2 = sin2
        self.useCompress = useCompress; self.plainMode = plaintext
        self.myCookie = myCookie; self.yourCookie = yourCookie; self.yourKeyV2 = yourKeyV2
        self.fastDisconnect = fastDisconnect
        configured = true
        return true
    }

    /// True when the peer has been sending continuously for the stable period and recently enough to trust the path.
    var isUsable: Bool {
        lock.lock(); defer { lock.unlock() }
        return usableLocked()
    }

    /// UdpAccelIsSendReady(a, true): dead when `LastRecvTick + timeout < Now` (a gap resets the stable run).
    private func usableLocked() -> Bool {
        guard !isClosed, configured, lastRecvTick > 0, firstStableReceiveTick > 0 else { return false }
        let now = clock()
        if now < lastRecvTick || now - lastRecvTick > timeoutMsLocked { firstStableReceiveTick = 0; return false }
        return now >= firstStableReceiveTick && now - firstStableReceiveTick >= Self.stableReceiveMs
    }

    private var timeoutMsLocked: UInt64 { fastDisconnect ? Self.keepAliveTimeoutFastMs : Self.keepAliveTimeoutMs }

    func start() {
        lock.lock()
        guard configured, !isClosed, !started else { lock.unlock(); return }
        started = true
        lock.unlock()
        let t = Thread { [self] in receiveLoop() }
        t.name = "vpngate-udpaccel-rx"
        t.start()
        startKeepAlives()
    }

    func stop() {
        lock.lock()
        if isClosed { lock.unlock(); return }
        isClosed = true
        let task = keepAliveTask
        if started {
            // The receive thread owns the descriptors from here on: it closes them after it has left poll/recvfrom.
            var one: UInt8 = 1
            _ = write(wakeWrite, &one, 1)
        } else {
            closeDescriptorsLocked()
        }
        lock.unlock()
        task?.cancel()
    }

    private func closeDescriptorsLocked() {
        if fd >= 0 { Darwin.close(fd); fd = -1 }
        if wakeRead >= 0 { Darwin.close(wakeRead); wakeRead = -1 }
        if wakeWrite >= 0 { Darwin.close(wakeWrite); wakeWrite = -1 }
    }

    // MARK: - Send Frame

    func sendFrame(_ frame: [UInt8]) -> Bool {
        guard isUsable else { return false }
        lock.lock(); let compress = useCompress; lock.unlock()
        if compress {
            // Session UseCompress: every block is zlib-compressed and flagged (Session.c:517, UdpAccel.c:353).
            guard let z = try? DataPhase.compressFrame(frame) else { return false }
            return sendPacket(compressed: true, payload: z, maxSize: Self.dataMaxSize)
        }
        return sendPacket(compressed: false, payload: frame, maxSize: Self.dataMaxSize)
    }

    private func sendPacket(compressed: Bool, payload: [UInt8], maxSize: Int) -> Bool {
        // The whole encrypt+send runs under the lock: the IV chain must never hand the same nonce to two senders,
        // and the descriptor cannot be closed underneath sendto.
        lock.lock()
        guard !isClosed, configured, fd >= 0 else { lock.unlock(); return false }
        let pad = UdpAccelPacket.paddingSize(dataSize: payload.count, maxSize: maxSize)
        guard let (packet, newIV) = try? UdpAccelPacket.encode(
            key32: myKeyV2, iv: nextIv, cookie: yourCookie, myTick: clock(), yourTick: lastRecvYourTick,
            compressed: compressed, payload: payload, paddingSize: pad, plainMode: plainMode
        ) else { lock.unlock(); return false }
        nextIv = newIV
        let sent = sendDatagram(packet, to: dest)
        // Keep-alive while UDP is not usable: the peer may sit behind a NAT, so also try the TCP peer IP (UdpAccel.c:625-651).
        if payload.isEmpty, var other = dest2, other.sin_addr.s_addr != dest.sin_addr.s_addr, !usableLocked() {
            other.sin_port = dest.sin_port
            _ = sendDatagram(packet, to: other)
        }
        lock.unlock()

        if sent > 0 {
            onByteCount?(0, payload.count)
            return true
        }
        return false
    }

    /// Caller holds the lock (the descriptor must not close underneath sendto).
    private func sendDatagram(_ packet: [UInt8], to addr: sockaddr_in) -> Int {
        var sin = addr
        return withUnsafePointer(to: &sin) { sinPtr in
            sinPtr.withMemoryRebound(to: sockaddr.self, capacity: 1) { saPtr in
                packet.withUnsafeBytes { sendto(fd, $0.baseAddress!, packet.count, 0, saPtr, socklen_t(MemoryLayout<sockaddr_in>.size)) }
            }
        }
    }

    // MARK: - Receive

    /// Runs on a dedicated thread (blocking poll must not occupy the cooperative pool) and closes the descriptors on exit.
    private func receiveLoop() {
        var buf = [UInt8](repeating: 0, count: 2048)
        lock.lock(); let sock = fd, wake = wakeRead; lock.unlock()
        while true {
            var fds = [pollfd(fd: sock, events: Int16(POLLIN), revents: 0), pollfd(fd: wake, events: Int16(POLLIN), revents: 0)]
            let rc = poll(&fds, 2, 1000)
            lock.lock(); let closed = isClosed; lock.unlock()
            if closed { break }
            if rc < 0 { if errno == EINTR { continue }; break }
            if rc == 0 || fds[0].revents & Int16(POLLIN) == 0 { continue }

            var from = sockaddr_in()
            var fromLen = socklen_t(MemoryLayout<sockaddr_in>.size)
            let n = withUnsafeMutablePointer(to: &from) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { recvfrom(sock, &buf, buf.count, 0, $0, &fromLen) }
            }
            if n > 0 { handleDatagram(Array(buf.prefix(n)), from: from) }
        }
        lock.lock(); closeDescriptorsLocked(); lock.unlock()
    }

    /// Validates one received datagram (AEAD tag, cookie, tick window) and delivers its payload.
    func handleDatagram(_ raw: [UInt8], from: sockaddr_in) {
        lock.lock()
        guard !isClosed, configured else { lock.unlock(); return }
        let key = yourKeyV2, expectedCookie = myCookie, plain = plainMode
        lock.unlock()

        guard raw.count >= (plain ? UdpAccelPacket.minPlaintextSize : UdpAccelPacket.minPacketSize),
              let decoded = try? UdpAccelPacket.decode(packet: raw, key32: key, plainMode: plain),
              decoded.header.cookie == expectedCookie else { return }
        let h = decoded.header

        lock.lock()
        let now = clock()
        // Upstream drops a packet whose tick is a full window older than the newest peer tick seen (replay of stale traffic).
        if h.myTick < lastRecvYourTick, lastRecvYourTick - h.myTick >= Self.windowMs { lock.unlock(); return }
        if lastRecvTick != 0, now >= lastRecvTick, now - lastRecvTick > timeoutMsLocked { firstStableReceiveTick = 0 }   // gap: stability restarts
        let newest = h.myTick > lastRecvYourTick      // strictly: replaying the latest packet from elsewhere must not move the peer
        lastRecvMyTick = max(lastRecvMyTick, h.yourTick)
        lastRecvYourTick = max(lastRecvYourTick, h.myTick)
        if newest { dest = from }              // the peer (or its NAT mapping) moved: follow authenticated packets only
        if lastRecvMyTick != 0, now >= lastRecvMyTick, now - lastRecvMyTick < Self.windowMs {
            lastRecvTick = now
            if firstStableReceiveTick == 0 { firstStableReceiveTick = now }
        }
        lock.unlock()

        // Every non-empty payload is data; an empty one is a keep-alive. A nonzero flag means zlib (Connection.c:2845).
        guard !decoded.payload.isEmpty else { return }
        onByteCount?(decoded.payload.count, 0)
        if h.compressed {
            guard let frame = try? DataPhase.uncompressFrame(decoded.payload, maxLen: Self.maxInflatedSize), !frame.isEmpty else { return }
            onFrame?(frame)
        } else {
            onFrame?(decoded.payload)
        }
    }

    // MARK: - Keep-Alive Loop

    static let maxInflatedSize = 4096

    private func keepAliveRange() -> Range<UInt64> {
        lock.lock(); defer { lock.unlock() }
        return fastDisconnect ? Self.keepAliveIntervalFastMs : Self.keepAliveIntervalMs
    }

    private func startKeepAlives() {
        let task = Task.detached { [weak self] in
            while !Task.isCancelled {
                guard let self = self else { return }
                _ = self.sendPacket(compressed: false, payload: [], maxSize: Self.keepAliveMaxSize)
                try? await Task.sleep(nanoseconds: UInt64.random(in: self.keepAliveRange()) * 1_000_000)
            }
        }
        lock.lock()
        if isClosed { lock.unlock(); task.cancel(); return }
        keepAliveTask = task
        lock.unlock()
    }
}
