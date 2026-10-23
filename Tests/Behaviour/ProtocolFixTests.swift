import CryptoKit
import Foundation
import Security
import VPNGateCore

// Known-answer vectors below were produced OUTSIDE the code under test: a stdlib-only python3 -I script with its own
// SHA-0, ChaCha20-Poly1305 (checked against RFC 8439 §2.8.2) and zlib, and `openssl x509` for the certificate fingerprints.

private let testCertB64 =
    "MIIDETCCAfmgAwIBAgIUK/mTODp0SH8taMB6BxNBynYEnbgwDQYJKoZIhvcNAQELBQAwFzEVMBMGA1UEAwwMdnBuZ2F0ZS10ZXN0"
    + "MCAXDTI2MTAwODA2MTMzM1oYDzIxMjYwOTE0MDYxMzMzWjAXMRUwEwYDVQQDDAx2cG5nYXRlLXRlc3QwggEiMA0GCSqGSIb3DQEB"
    + "AQUAA4IBDwAwggEKAoIBAQCy9aQrsR6pusJ4DgdrfLxImIIUbj5k96nVJjLavH2xXrj/YKlu5KjzP2Yo3CEzPkEpZ6yi3h2YsAY8"
    + "vQh3RMpDG7WJdnwIR/OnYRN8ucWA4RhZ9oeL63m6WkqZBC2fBjwOe3WwoAKnhLZiweQHH37Z9qll8VtW79/jyGJkv1k+pbACQUY4"
    + "goHeANIEBnIkE9UdwcNloudi3+Ts6ND93/nKB0TMQavfHCzEc8eWTzB/LKhFxk/XqFlaHLg1HRz5ITgIvbfDU8k9ThLadZVp8Eaz"
    + "QXadMro7JmqAd+tzZb2hf8etY+QM4FmnTFkGzMX+WpV/OuNLDti4BA+vOT2YX7HNAgMBAAGjUzBRMB0GA1UdDgQWBBTHw+EJrRw1"
    + "LR8OY56/DtjcaIqiDjAfBgNVHSMEGDAWgBTHw+EJrRw1LR8OY56/DtjcaIqiDjAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEB"
    + "CwUAA4IBAQABtMTpeP/RrQZ3xzvFAUhFFlNaM9QlUSgzfKUKTuLn5jZWDFtVT54Ro8QoDzSQv/6MWpyVmNq573cIRE7XJZBzjRdd"
    + "I/DHeVUwEX6fvIERajsd9yOwW1rrdb9p/wDbM6+AhNzPC7rXTfxq8Go793ZV9eN6ZJBsjybw4c6ocle4mbtY98AVwesHYGF9RtIc"
    + "xurJzdUxFb6ykWE3AD8GGiVbnzd9Q1BMWUWKPuujVgR6ZFQTsmzde2Xbi2AMACF3fbVIpsy+UOwBHcXiIJ5GepgByoUKarnTyDmq"
    + "3CvInUp4ca0SvCljzRuEh9XSFuJdGwclaDzVa1QhibQqNZbKwLyU"
private let testCertSHA1 = "DC:42:DC:6E:79:80:85:BD:FC:EE:38:8C:34:91:5C:68:3A:CC:5F:E2"
private let testCertSHA256 = "8B:2E:3D:CD:DF:27:56:0A:45:AA:75:65:71:E8:FA:74:D4:EE:76:68:99:06:CA:64:AB:9F:84:1A:3A:75:F5:C2"

private func hexBytes(_ s: String) -> [UInt8] {
    var out = [UInt8](); var i = s.startIndex
    while i < s.endIndex { let j = s.index(i, offsetBy: 2); out.append(UInt8(s[i..<j], radix: 16)!); i = j }
    return out
}

private struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }

private func connectError(_ s: FakeSoftEtherServer, host: String = "1.2.3.4") async -> String? {
    let c = SoftEtherClient(host: host, port: 443, proxy: ProxySettings(), makeStream: s.factory)
    defer { c.close(nil) }
    do { _ = try await c.connect { _ in }; return nil } catch { return error.localizedDescription }
}

private func udpWelcome(
    ip: String? = nil, ipInt: UInt32? = nil, port: UInt32 = 40001, key: Data = Data(repeating: 0x99, count: 128),
    version: UInt32 = 2, serverCookie: UInt32 = 0x12345678, clientCookie: UInt32 = 0x87654321,
    encryption: Bool? = nil, compress: Bool = false
) -> Pack {
    var p = Pack()
    p.addStr("session_name", "SID-UDP"); p.addStr("connection_name", "CID-1")
    p.addInt("timeout", 20000); p.addData("session_key", Data(repeating: 0x11, count: 20))
    p.addInt("max_connection", 1); p.addBool("use_udp_acceleration", true); p.addInt("udp_acceleration_version", version)
    p.addBool("use_compress", compress)
    if let e = encryption { p.addBool("udp_acceleration_use_encryption", e) }
    if let ip = ip { p.addStr("udp_acceleration_server_ip", ip) }
    if let n = ipInt { p.addInt("udp_acceleration_server_ip", n) }
    p.addInt("udp_acceleration_server_port", port)
    p.addInt("udp_acceleration_server_cookie", serverCookie); p.addInt("udp_acceleration_client_cookie", clientCookie)
    p.addData("udp_acceleration_server_key_v2", key)
    return p
}

/// ByteStream wrapper whose sends can be held back (to fill the client's pending queue).
private final class HoldableStream: ByteStream {
    let inner: FakeStream
    let hold = Locked(false)
    let gate = Gate()
    init(_ inner: FakeStream) { self.inner = inner }
    var buffer: ByteBuffer {
        get { inner.buffer }
        set { inner.buffer = newValue }
    }
    func start() async throws { try await inner.start() }
    func send(_ data: Data) async throws { if hold.value { await gate.wait() }; try await inner.send(data) }
    func readChunk() async throws -> Data { try await inner.readChunk() }
    func cancel() { inner.cancel(); gate.release() }
}

/// Fails the second send (the login POST) after a successful signature exchange.
private final class ThrowingStream: ByteStream {
    let inner: FakeStream
    let sends = Locked(0)
    init(_ inner: FakeStream) { self.inner = inner }
    var buffer: ByteBuffer {
        get { inner.buffer }
        set { inner.buffer = newValue }
    }
    func start() async throws { try await inner.start() }
    func send(_ data: Data) async throws {
        var n = 0;
        sends.update {
            $0 += 1; n = $0
        }
        if n >= 2 { throw Boom() }
        try await inner.send(data)
    }
    func readChunk() async throws -> Data { try await inner.readChunk() }
    func cancel() { inner.cancel() }
}

// MARK: loopback UDP helpers (127.0.0.1 only)

private func loopbackAddr(_ port: UInt16) -> sockaddr_in {
    var a = sockaddr_in()
    a.sin_family = sa_family_t(AF_INET); a.sin_port = port.bigEndian
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr)
    return a
}

private final class LoopbackUDP {
    let fd: Int32
    let port: UInt16
    init() {
        let sock = socket(AF_INET, SOCK_DGRAM, 0)
        var a = loopbackAddr(0)
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(sock, $0, &len) } }
        fd = sock
        port = UInt16(bigEndian: a.sin_port)
    }
    deinit { Darwin.close(fd) }
    func recv(timeout: Double = 3) -> [UInt8]? {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&p, 1, Int32(timeout * 1000)) > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: 2048)
        let n = recvfrom(fd, &buf, buf.count, 0, nil, nil)
        return n > 0 ? Array(buf.prefix(n)) : nil
    }
}

private let udpKeyMine = (0..<32).map { UInt8($0) }
private let udpKeyPeer = (0..<32).map { UInt8(100 + $0) }

private func makeUdp(
    fast: Bool = false, serverPort: UInt16 = 9, clock: Locked<UInt64>, serverIP: String = "127.0.0.1",
    compress: Bool = false, plaintext: Bool = false, secondaryIP: String? = nil
) -> UdpAccel {
    let u = UdpAccel(myKeyV2: udpKeyMine + [UInt8](repeating: 0, count: 96))!
    precondition(
        u.configure(
            serverIP: serverIP, serverPort: serverPort, myCookie: 7, yourCookie: 9,
            yourKeyV2: udpKeyPeer, fastDisconnect: fast, useCompress: compress, plaintext: plaintext,
            secondaryIP: secondaryIP))
    u.clock = { clock.value }
    return u
}

private let ivCounter = Locked(UInt8(0))
private func peerPacket(
    myTick: UInt64, yourTick: UInt64, cookie: UInt32 = 7, compressed: Bool = false,
    payload: [UInt8] = [1, 2, 3], plaintext: Bool = false
) -> [UInt8] {
    var n: UInt8 = 0
    ivCounter.update {
        $0 &+= 1; n = $0
    }
    let iv = [UInt8](repeating: n, count: 12)
    return try! UdpAccelPacket.encode(
        key32: udpKeyPeer, iv: iv, cookie: cookie, myTick: myTick, yourTick: yourTick,
        compressed: compressed, payload: payload, plainMode: plaintext
    ).packet
}

/// Drives a UdpAccel to "usable" with the fake clock (packets 2 s apart for 10 s, all echoing our ticks).
private func makeUsable(_ u: UdpAccel, _ clk: Locked<UInt64>, from: sockaddr_in) {
    for step in 0...5 {
        clk.update { $0 = 100_000 + UInt64(step) * 2000 }
        u.handleDatagram(peerPacket(myTick: 1000 + UInt64(step) * 2000, yourTick: clk.value - 100, payload: []), from: from)
    }
}

// MARK: DER helper for PKCS#8 wrapping

private func der(_ tag: UInt8, _ body: [UInt8]) -> [UInt8] {
    var len: [UInt8]
    if body.count < 128 {
        len = [UInt8(body.count)]
    } else if body.count < 256 {
        len = [0x81, UInt8(body.count)]
    } else {
        len = [0x82, UInt8(body.count >> 8), UInt8(body.count & 0xff)]
    }
    return [tag] + len + body
}

private func makeRSAKey() -> (pkcs1: Data, publicKey: SecKey) {
    var err: Unmanaged<CFError>?
    let attrs: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]
    let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err)!  // not permanent: never touches a keychain
    let ext = SecKeyCopyExternalRepresentation(priv, &err)! as Data  // PKCS#1 RSAPrivateKey
    return (ext, SecKeyCopyPublicKey(priv)!)
}

private func verifySHA1(_ pub: SecKey, signature: Data, over message: Data) -> Bool {
    // Verified through the *digest* algorithm with a CryptoKit SHA-1, independent of the message-variant used to sign.
    let digest = Data(Insecure.SHA1.hash(data: message))
    return SecKeyVerifySignature(pub, .rsaSignatureDigestPKCS1v15SHA1, digest as CFData, signature as CFData, nil)
}

func registerProtocolFixTests() {
    // MARK: 1 hostile welcome / redirect values

    test("protocol/redirect-port-above-65535-is-a-protocol-error-not-a-trap") {
        let s = FakeSoftEtherServer(); s.redirect = true; s.redirectPort = 70000
        let e = await connectError(s)
        expect(e?.contains("invalid port") == true, "got \(e ?? "success")")
        expect(s.lastStream?.isCancelled == true, "stream must be released")
    }
    test("protocol/redirect-port-zero-and-huge-are-rejected") {
        for port: UInt32 in [0, 65536, UInt32.max] {
            let s = FakeSoftEtherServer(); s.redirect = true; s.redirectPort = port
            let e = await connectError(s)
            expect(e?.contains("invalid port") == true, "port \(port): \(e ?? "success")")
        }
    }
    test("protocol/redirect-host-is-validated") {
        for bad in ["1.2.3.4\r\nX-Evil: 1", String(repeating: "a", count: 300), "-oProxyCommand", "a b"] {
            let s = FakeSoftEtherServer(); s.redirect = true; s.redirectHost = bad
            let e = await connectError(s)
            expect(e?.contains("invalid host") == true, "\(bad.prefix(20)): \(e ?? "success")")
        }
    }
    test("protocol/hostile-udp-fields-disable-udp-but-keep-tcp") {
        let s = FakeSoftEtherServer()
        s.welcomeOverride = udpWelcome(ipInt: 0xFFFF_FFFF, port: 70000)
        let c = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), makeStream: s.factory)
        let w = try await c.connect { _ in }
        expectEqual(w.sessionName, "SID-UDP")
        expectEqual(w.udpServerPort, nil, "port 70000 must not become a UInt16")
        expectEqual(c.udpLocalPort, 0, "no UDP accel may run")
        expectEqual(c.bypassHosts, ["1.2.3.4"])
        c.close(nil)
        for port: UInt32 in [0, 65536, UInt32.max] {
            let s2 = FakeSoftEtherServer(); s2.welcomeOverride = udpWelcome(ip: "1.2.3.4", port: port)
            let c2 = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), makeStream: s2.factory)
            let w2 = try await c2.connect { _ in }
            expectEqual(w2.udpServerPort, nil, "port \(port)")
            c2.close(nil)
        }
    }

    // MARK: 4 pack IP integer byte order (SoftEther IPToUINT / PackAddIp)

    test("protocol/pack-ip-integer-is-little-endian-reading-of-the-address-bytes") {
        expectEqual(packIPString(0x0807_0605), "5.6.7.8")
        expectEqual(packIPString(0x0100_007F), "127.0.0.1")
        expectEqual(packIPValue([5, 6, 7, 8]), 0x0807_0605)
        expectEqual(packIPString(packIPValue([203, 0, 113, 9])), "203.0.113.9")
        expectEqual(ipString(0x0807_0605), "8.7.6.5", "the network-order helper is NOT the pack decoder")
    }
    test("protocol/redirect-port-list-prefers-the-current-port-else-the-first") {
        for (offered, current, expected) in [([8443, 443, 992], 443, 443), ([8443, 992], 443, 8443)] as [([UInt32], UInt16, UInt16)] {
            let s = FakeSoftEtherServer(); s.redirect = true; s.redirectPorts = offered
            let ports = Locked([UInt16]())
            let c = SoftEtherClient(
                host: "1.2.3.4", port: current, proxy: ProxySettings(),
                makeStream: { h, p, pr in
                    ports.update { $0.append(p) }
                    if s.streamsCreated >= 1 { s.redirect = false }
                    return s.factory(h, p, pr)
                })
            _ = try await c.connect { _ in }
            expectEqual(ports.value.last, expected, "offered \(offered) while on \(current)")
            c.close(nil)
        }
    }
    test("protocol/redirect-ip-integer-goes-to-the-right-host") {
        let s = FakeSoftEtherServer(); s.redirect = true; s.redirectIpInt = 0x0807_0605
        let hosts = Locked([String]())
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, proxy: ProxySettings(),
            makeStream: { h, p, pr in
                hosts.update { $0.append(h) }
                if s.streamsCreated >= 1 { s.redirect = false }
                return s.factory(h, p, pr)
            })
        _ = try await c.connect { _ in }
        expectEqual(hosts.value, ["1.2.3.4", "5.6.7.8"])
        expectEqual(c.bypassHosts, ["5.6.7.8"], "routes must follow the redirect target")
        c.close(nil)
    }

    // MARK: 5/6 UDP endpoint selection and socket reuse

    test("protocol/udp-server-ip-selection") {
        let r = SoftEtherClient.resolveUdpServerIP
        expectEqual(r("8.8.4.4", "9.9.9.9"), "8.8.4.4")
        expectEqual(r("0.0.0.0", "9.9.9.9"), "9.9.9.9")
        expectEqual(r("192.168.1.5", "9.9.9.9"), "9.9.9.9")
        expectEqual(r("10.1.2.3", "9.9.9.9"), "9.9.9.9")
        expectEqual(r("172.20.0.1", "9.9.9.9"), "9.9.9.9")
        expectEqual(r("127.0.0.1", "9.9.9.9"), "9.9.9.9")
        expectEqual(r(nil, "9.9.9.9"), "9.9.9.9")
        expectEqual(r("udp.example.com", "9.9.9.9"), "9.9.9.9")
        expectEqual(r("0.0.0.0", "vpn.example.com"), nil, "hostname peer: no IP literal to send UDP to")
        expectEqual(r("172.32.0.1", "9.9.9.9"), "172.32.0.1", "172.32/16 is public")
    }
    test("protocol/udp-integer-ip-uses-pack-byte-order") {
        let s = FakeSoftEtherServer(); s.welcomeOverride = udpWelcome(ipInt: 0x0403_0201)  // 1.2.3.4 as SoftEther sends it
        let c = SoftEtherClient(host: "9.9.9.9", port: 443, proxy: ProxySettings(), useUdpAccel: false, makeStream: s.factory)
        let w = try await c.connect { _ in }
        expectEqual(w.udpServerIp, "1.2.3.4")
        c.close(nil)
    }
    test("protocol/advertised-udp-port-is-the-port-that-stays-bound") {
        let s = FakeSoftEtherServer(); s.welcomeOverride = udpWelcome(ip: "10.0.0.1")  // private -> falls back to the TCP peer
        let c = SoftEtherClient(host: "127.0.0.1", port: 443, proxy: ProxySettings(), makeStream: s.factory)
        let w = try await c.connect { _ in }
        expectEqual(w.udpServerIp, "127.0.0.1")
        let advertised = s.logins[0].int("udp_acceleration_client_port") ?? 0
        expect(advertised > 0, "login must advertise a bound port")
        expectEqual(UInt32(c.udpLocalPort), advertised, "the advertised socket is the one in use")
        expectEqual(c.bypassHosts, ["127.0.0.1"])
        c.close(nil)
        await expectA(await eventually(3) { c.udpLocalPort == 0 }, "socket must be closed on close()")
    }

    // MARK: 7/8/9/10 UdpAccel

    test("udp/stale-ticks-dropped-and-last-peer-tick-is-monotonic") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        let got = Locked(0); u.onFrame = { _ in got.update { $0 += 1 } }
        let from = loopbackAddr(5000)
        u.handleDatagram(peerPacket(myTick: 50_000, yourTick: 99_000), from: from)
        expectEqual(got.value, 1); expectEqual(u.lastPeerTick, 50_000)
        u.handleDatagram(peerPacket(myTick: 90_000, yourTick: 99_500), from: from)
        expectEqual(got.value, 2); expectEqual(u.lastPeerTick, 90_000)
        u.handleDatagram(peerPacket(myTick: 50_000, yourTick: 99_500), from: from)  // 40 s behind: replay of old traffic
        expectEqual(got.value, 2, "stale packet must be dropped"); expectEqual(u.lastPeerTick, 90_000)
        u.handleDatagram(peerPacket(myTick: 70_000, yourTick: 99_500), from: from)  // 20 s behind: inside the window
        expectEqual(got.value, 3); expectEqual(u.lastPeerTick, 90_000, "tick must never move backwards")
        u.stop()
    }
    test("udp/wrong-cookie-and-tampered-packets-are-ignored") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        let got = Locked(0); u.onFrame = { _ in got.update { $0 += 1 } }
        u.handleDatagram(peerPacket(myTick: 10, yourTick: 99_000, cookie: 8), from: loopbackAddr(5000))
        var bad = peerPacket(myTick: 10, yourTick: 99_000); bad[bad.count - 1] ^= 1
        u.handleDatagram(bad, from: loopbackAddr(5000))
        u.handleDatagram([1, 2, 3], from: loopbackAddr(5000))
        expectEqual(got.value, 0); expectEqual(u.lastPeerTick, 0)
        u.stop()
    }
    test("udp/needs-a-stable-receive-period-and-times-out") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        expect(!u.isUsable, "nothing received yet")
        u.handleDatagram(peerPacket(myTick: 1000, yourTick: 99_900, payload: []), from: loopbackAddr(5000))
        expect(!u.isUsable, "first packet alone is not a stable period")
        // keep the run alive with a packet every 2 s (inside the 9 s timeout) for just under 10 s
        for step in 1...4 {
            clk.update { $0 = 100_000 + UInt64(step) * 2000 }
            u.handleDatagram(peerPacket(myTick: 1000 + UInt64(step) * 2000, yourTick: clk.value - 100, payload: []), from: loopbackAddr(5000))
        }
        clk.update { $0 = 109_999 }
        expect(!u.isUsable, "9.999 s since the first packet is not 10 s")
        clk.update { $0 = 110_000 }
        u.handleDatagram(peerPacket(myTick: 11_000, yourTick: 109_900, payload: []), from: loopbackAddr(5000))
        expect(u.isUsable, "10 s of continuous traffic (UDP_ACCELERATION_REQUIRE_CONTINUOUS)")
        clk.update { $0 = 110_000 + 9_000 }
        expect(u.isUsable, "legacy timeout is 9 s: still alive at exactly 9 s (LastRecvTick + timeout < Now)")
        clk.update { $0 = 110_000 + 9_001 }
        expect(!u.isUsable, "silent for more than 9 s")
        u.stop()
    }
    test("udp/gap-longer-than-the-timeout-restarts-the-stable-run") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        u.handleDatagram(peerPacket(myTick: 1000, yourTick: 99_900, payload: []), from: loopbackAddr(5000))
        clk.update { $0 = 105_000 }
        u.handleDatagram(peerPacket(myTick: 6000, yourTick: 104_900, payload: []), from: loopbackAddr(5000))
        clk.update { $0 = 114_001 }  // 9.001 s of silence
        u.handleDatagram(peerPacket(myTick: 15_000, yourTick: 113_900, payload: []), from: loopbackAddr(5000))
        expect(!u.isUsable, "114 s is 14 s after the first packet but the run restarted at 114.001")
        clk.update { $0 = 119_000 }
        u.handleDatagram(peerPacket(myTick: 20_000, yourTick: 118_900, payload: []), from: loopbackAddr(5000))
        expect(!u.isUsable, "5 s after the restart")
        clk.update { $0 = 124_001 }
        u.handleDatagram(peerPacket(myTick: 25_000, yourTick: 123_900, payload: []), from: loopbackAddr(5000))
        expect(u.isUsable, "10 s after the restart")
        u.stop()
    }
    test("udp/packet-that-does-not-echo-our-tick-is-not-live") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        u.handleDatagram(peerPacket(myTick: 1000, yourTick: 0, payload: []), from: loopbackAddr(5000))  // never heard us
        clk.update { $0 = 111_000 }
        u.handleDatagram(peerPacket(myTick: 12_000, yourTick: 60_000, payload: []), from: loopbackAddr(5000))  // echo is 51 s old
        expect(!u.isUsable, "no round trip inside the 30 s window")
        u.stop()
    }
    test("udp/fast-disconnect-mode-uses-the-short-timeout") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(fast: true, clock: clk)
        u.handleDatagram(peerPacket(myTick: 1000, yourTick: 99_900, payload: []), from: loopbackAddr(5000))
        for step in 1...5 {
            clk.update { $0 = 100_000 + UInt64(step) * 2000 }
            u.handleDatagram(peerPacket(myTick: 1000 + UInt64(step) * 2000, yourTick: clk.value - 100, payload: []), from: loopbackAddr(5000))
        }
        expect(u.isUsable)
        clk.update { $0 = 110_000 + 2_100 }; expect(u.isUsable)
        clk.update { $0 = 110_000 + 2_101 }; expect(!u.isUsable, "fast mode drops after 2.1 s")
        u.stop()
    }
    test("udp/peer-address-follows-newest-authenticated-packet-only") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(serverPort: 4000, clock: clk)
        expectEqual(u.peerPort, 4000)
        u.handleDatagram(peerPacket(myTick: 100, yourTick: 99_000), from: loopbackAddr(5000))
        expectEqual(u.peerPort, 5000)
        let replay = peerPacket(myTick: 100, yourTick: 99_000)
        u.handleDatagram(replay, from: loopbackAddr(6666))  // same tick from elsewhere
        expectEqual(u.peerPort, 5000, "a replayed/equal tick must not redirect traffic")
        u.handleDatagram(peerPacket(myTick: 200, yourTick: 99_000), from: loopbackAddr(5001))
        expectEqual(u.peerPort, 5001)
        u.stop()
    }
    test("udp/configure-rejects-bad-endpoints") {
        let u = UdpAccel(myKeyV2: udpKeyMine)!
        let key = udpKeyPeer
        expect(!u.configure(serverIP: "vpn.example.com", serverPort: 4000, myCookie: 1, yourCookie: 2, yourKeyV2: key, fastDisconnect: false), "hostname")
        expect(!u.configure(serverIP: "0.0.0.0", serverPort: 4000, myCookie: 1, yourCookie: 2, yourKeyV2: key, fastDisconnect: false), "unspecified")
        expect(!u.configure(serverIP: "1.2.3.4", serverPort: 0, myCookie: 1, yourCookie: 2, yourKeyV2: key, fastDisconnect: false), "port 0")
        expect(!u.configure(serverIP: "1.2.3.4", serverPort: 4000, myCookie: 1, yourCookie: 2, yourKeyV2: [1, 2, 3], fastDisconnect: false), "short key")
        expect(u.configure(serverIP: "1.2.3.4", serverPort: 4000, myCookie: 1, yourCookie: 2, yourKeyV2: key, fastDisconnect: false))
        u.stop()
    }
    test("udp/stop-closes-descriptors-after-the-receive-thread-exits") {
        let lb = LoopbackUDP(); let clk = Locked(UInt64(1)); let u = makeUdp(serverPort: lb.port, clock: clk)
        let port = u.localPort
        expect(port > 0)
        u.start()
        _ = lb.recv()  // first keep-alive proves the loops are running
        u.stop()
        await expectA(await eventually(3) { u.isSocketClosed }, "receive thread must close the socket after leaving poll")
        expectEqual(u.localPort, 0)
        expect(!u.sendFrame([1]), "no send after stop")
        let idle = makeUdp(clock: clk)  // never started: stop() closes immediately
        idle.stop(); expect(idle.isSocketClosed)
    }
    test("udp/keepalives-use-negotiated-peer-cookie-and-key") {
        let lb = LoopbackUDP(); let clk = Locked(UInt64(5000)); let u = makeUdp(serverPort: lb.port, clock: clk)
        u.start()
        guard let raw = lb.recv() else { fail("no keep-alive datagram"); u.stop(); return }
        let d = try UdpAccelPacket.decode(packet: raw, key32: udpKeyMine)
        expectEqual(d.header.cookie, 9); expectEqual(d.header.compressed, false); expectEqual(d.payload.count, 0); expectEqual(d.header.myTick, 5000)
        u.stop()
    }
    test("udp/concurrent-senders-never-reuse-a-nonce") {
        let lb = LoopbackUDP(); let clk = Locked(UInt64(100_000)); let u = makeUdp(serverPort: lb.port, clock: clk)
        makeUsable(u, clk, from: loopbackAddr(lb.port))
        expect(u.isUsable)
        let threads = 4, each = 40
        let done = DispatchGroup()
        for _ in 0..<threads {
            done.enter();
            Thread.detachNewThread {
                for i in 0..<each { _ = u.sendFrame([UInt8(i)]) }; done.leave()
            }
        }
        await withCheckedContinuation { (c: CheckedContinuation<Void, Never>) in done.notify(queue: .global()) { c.resume() } }
        var ivs = Set<[UInt8]>(); var n = 0
        while let p = lb.recv(timeout: 0.3) { ivs.insert(Array(p.prefix(12))); n += 1 }
        expect(n >= threads * each / 2, "received \(n)")
        expectEqual(ivs.count, n, "every datagram needs a unique nonce")
        u.stop()
    }

    // MARK: UDP parity with upstream (flag semantics, compression, welcome gating, second IP, padding, interval)

    let zPlain = hexBytes(
        "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f68656c6c6f2068656c6c6f2068656c6c6f2068656c6c6f"
    )
    let zBlock = hexBytes("789c6360646266616563e7e0e4e2e6e1e5e367a0333f233527275f01830400a6120c71")  // python zlib.compress(zPlain)

    test("udp/compressed-flag-payload-is-inflated-and-delivered") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        let got = Locked([[UInt8]]()); u.onFrame = { f in got.update { $0.append(f) } }
        let from = loopbackAddr(5000)
        u.handleDatagram(peerPacket(myTick: 1000, yourTick: 99_900, compressed: true, payload: zBlock), from: from)
        expectEqual(got.value, [zPlain], "flag 1 = zlib payload, must not be dropped as a keep-alive")
        u.handleDatagram(peerPacket(myTick: 1100, yourTick: 99_900, compressed: false, payload: [9, 8, 7]), from: from)
        expectEqual(got.value.count, 2); expectEqual(got.value[1], [9, 8, 7])
        u.handleDatagram(peerPacket(myTick: 1200, yourTick: 99_900, compressed: true, payload: [1, 2, 3, 4]), from: from)  // not zlib
        u.handleDatagram(peerPacket(myTick: 1300, yourTick: 99_900, compressed: true, payload: Array(zBlock.prefix(10))), from: from)  // truncated
        expectEqual(got.value.count, 2, "undecodable compressed payloads are dropped")
        // inflation is bounded: a 1 MB zero run compresses to ~1 KB and must not be delivered
        let bomb = try DataPhase.compressFrame([UInt8](repeating: 0, count: 1 << 20))
        u.handleDatagram(peerPacket(myTick: 1400, yourTick: 99_900, compressed: true, payload: bomb), from: from)
        expectEqual(got.value.count, 2, "zip bomb dropped")
        u.stop()
    }
    test("udp/keepalive-is-empty-payload-flag-zero-and-delivers-nothing") {
        let clk = Locked(UInt64(100_000)); let u = makeUdp(clock: clk)
        let got = Locked(0); u.onFrame = { _ in got.update { $0 += 1 } }
        u.handleDatagram(peerPacket(myTick: 1000, yourTick: 99_900, compressed: true, payload: []), from: loopbackAddr(5000))
        u.handleDatagram(peerPacket(myTick: 1100, yourTick: 99_900, compressed: false, payload: []), from: loopbackAddr(5000))
        expectEqual(got.value, 0)
        u.stop()
    }
    test("udp/negotiated-compression-sends-zlib-with-flag-1-and-padding-below-32") {
        let lb = LoopbackUDP(); let clk = Locked(UInt64(100_000)); let u = makeUdp(serverPort: lb.port, clock: clk, compress: true)
        makeUsable(u, clk, from: loopbackAddr(lb.port))
        expect(u.isUsable)
        expect(u.sendFrame(zPlain))
        guard let raw = lb.recv() else { fail("no data datagram"); u.stop(); return }
        let d = try UdpAccelPacket.decode(packet: raw, key32: udpKeyMine)
        expectEqual(d.header.compressed, true); expectEqual(d.payload, zBlock, "same bytes as python zlib.compress")
        let pad = raw.count - (UdpAccelPacket.minPacketSize + zBlock.count)
        expect(pad >= 0 && pad <= 31, "padding \(pad)")
        u.stop()
    }
    test("udp/uncompressed-session-sends-raw-frames-with-flag-0") {
        let lb = LoopbackUDP(); let clk = Locked(UInt64(100_000)); let u = makeUdp(serverPort: lb.port, clock: clk)
        makeUsable(u, clk, from: loopbackAddr(lb.port))
        expect(u.sendFrame([5, 6, 7, 8]))
        guard let raw = lb.recv() else { fail("no data datagram"); u.stop(); return }
        let d = try UdpAccelPacket.decode(packet: raw, key32: udpKeyMine)
        expectEqual(d.header.compressed, false); expectEqual(d.payload, [5, 6, 7, 8])
        u.stop()
    }
    test("udp/plaintext-mode-has-no-iv-no-mac-and-no-padding") {
        let lb = LoopbackUDP(); let clk = Locked(UInt64(100_000)); let u = makeUdp(serverPort: lb.port, clock: clk, plaintext: true)
        let got = Locked([[UInt8]]()); u.onFrame = { f in got.update { $0.append(f) } }
        // peer -> us: bare cookie(4) tick(8) tick(8) size(2) flag(1) data
        let wire = peerPacket(myTick: 1000, yourTick: 99_900, payload: [1, 2, 3], plaintext: true)
        expectEqual(wire, hexBytes("00000007") + hexBytes("00000000000003e8") + hexBytes("000000000001863c") + hexBytes("0003") + [0, 1, 2, 3])
        u.handleDatagram(wire, from: loopbackAddr(lb.port))
        expectEqual(got.value, [[1, 2, 3]])
        u.handleDatagram(peerPacket(myTick: 1100, yourTick: 99_900, payload: [4]), from: loopbackAddr(5000))  // encrypted packet is garbage here
        expectEqual(got.value.count, 1)
        // us -> peer
        u.start()
        guard let raw = lb.recv() else { fail("no keep-alive"); u.stop(); return }
        expectEqual(raw.count, 23, "plaintext keep-alive: 23 header bytes, nothing else")
        expectEqual(Array(raw.prefix(4)), hexBytes("00000009"))
        u.stop()
    }
    test("udp/keepalive-also-goes-to-tcp-peer-ip-until-udp-is-usable") {
        // primary 127.0.0.2 (nobody listens), secondary 127.0.0.1 (the test socket)
        let lb = LoopbackUDP(); let clk = Locked(UInt64(100_000))
        let u = makeUdp(serverPort: lb.port, clock: clk, serverIP: "127.0.0.2", secondaryIP: "127.0.0.1")
        u.start()
        guard let raw = lb.recv() else { fail("keep-alive must reach the second IP"); u.stop(); return }
        let d = try UdpAccelPacket.decode(packet: raw, key32: udpKeyMine)
        expectEqual(d.payload.count, 0); expectEqual(d.header.cookie, 9)
        u.stop()
        // once usable the second IP is left alone
        let lb2 = LoopbackUDP(); let clk2 = Locked(UInt64(100_000))
        let u2 = makeUdp(serverPort: lb2.port, clock: clk2, serverIP: "127.0.0.2", secondaryIP: "127.0.0.1")
        var from2 = loopbackAddr(lb2.port); inet_pton(AF_INET, "127.0.0.2", &from2.sin_addr)
        makeUsable(u2, clk2, from: from2)
        expect(u2.isUsable)
        u2.start()
        expect(lb2.recv(timeout: 0.6) == nil, "no second-IP keep-alive while UDP is usable")
        u2.stop()
    }
    test("udp/padding-follows-upstream-rand-modulo-min-room-32") {
        var bounds: [Int] = []
        expectEqual(
            UdpAccelPacket.paddingSize(
                dataSize: 0, maxSize: 1000,
                random: {
                    bounds.append($0); return $0 - 1
                }), 31)
        expectEqual(bounds, [32])
        expectEqual(
            UdpAccelPacket.paddingSize(
                dataSize: 1370, maxSize: 1426,
                random: {
                    bounds.append($0); return $0 - 1
                }), 4)
        expectEqual(bounds, [32, 5], "room = max - (51 + data) = 5")
        expectEqual(UdpAccelPacket.paddingSize(dataSize: 1375, maxSize: 1426, random: { _ in 99 }), 0, "packet already at max: no padding")
        for _ in 0..<200 { expect(UdpAccelPacket.paddingSize(dataSize: 100, maxSize: 1426) <= 31) }
        let padded = try UdpAccelPacket.encode(
            key32: udpKeyMine, iv: [UInt8](repeating: 1, count: 12), cookie: 1, myTick: 1, yourTick: 0,
            compressed: false, payload: [1], paddingSize: 20)
        expectEqual(padded.packet.count, UdpAccelPacket.minPacketSize + 1 + 20)
        let back = try UdpAccelPacket.decode(packet: padded.packet, key32: udpKeyMine)
        expectEqual(back.payload, [1])
    }
    test("udp/keepalive-interval-maximum-is-exclusive") {
        expect(UdpAccel.keepAliveIntervalMs.contains(1000)); expect(!UdpAccel.keepAliveIntervalMs.contains(3000))
        expect(UdpAccel.keepAliveIntervalFastMs.contains(500)); expect(!UdpAccel.keepAliveIntervalFastMs.contains(1000))
        expectEqual(UdpAccel.stableReceiveMs, 10_000)
    }
    test("udp/welcome-gating-version-cookies-encryption") {
        func udpRuns(_ w: Pack, _ want: Bool, _ why: String) async throws {
            let s = FakeSoftEtherServer(); s.welcomeOverride = w
            let c = SoftEtherClient(host: "127.0.0.1", port: 443, proxy: ProxySettings(), makeStream: s.factory)
            _ = try await c.connect { _ in }
            let on = c.udpLocalPort != 0
            c.close(nil)
            expectEqual(on, want, why)
        }
        let lb = LoopbackUDP(); let port = UInt32(lb.port)
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port), true, "baseline: v2 with cookies uses UDP")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, encryption: true), true, "explicit encryption")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, version: 1), false, "v1 key path is not implemented")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, version: 0), false, "version 0 means v1")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, serverCookie: 0), false, "zero server cookie")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, clientCookie: 0), false, "zero client cookie")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, key: Data(), encryption: false), true, "plaintext mode needs no key")
        try await udpRuns(udpWelcome(ip: "127.0.0.1", port: port, key: Data(), encryption: true), false, "encrypted mode needs the key")
    }

    // MARK: 11 + 19 independent vectors

    test("udp/rfc8439-aead-vector-pins-nonce-and-tag-handling") {
        let key = SymmetricKey(data: Data(0x80..<0xa0))
        let nonce = try ChaChaPoly.Nonce(data: Data(hexBytes("070000004041424344454647")))
        let aad = Data(hexBytes("50515253c0c1c2c3c4c5c6c7"))
        let pt = Data("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".utf8)
        let box = try ChaChaPoly.seal(pt, using: key, nonce: nonce, authenticating: aad)
        expectEqual(Array(box.ciphertext.prefix(16)), hexBytes("d31a8d34648e60db7b86afbc53ef7ec2"))
        expectEqual(Array(box.tag), hexBytes("1ae10b594f09e26a7e902ecbd0600691"))
    }
    test("udp/v2-packet-matches-independent-python-chacha20poly1305") {
        let expected = hexBytes(
            "0102030405060708090a0b0c75aa772e0952a4b348e946afd4a18c0ebefc944e46a9bf1e3f8d8ca8258c8a597dc9e8dcf15d4fda31846aa807c3f95fa623c39e1e4248ebd79621fd1556865c39aca0b909fb59"
        )
        let key = (0..<32).map { UInt8($0) }, iv = (1...12).map { UInt8($0) }
        let payload = Array("UDP acceleration v2 payload test".utf8)
        let enc = try UdpAccelPacket.encode(key32: key, iv: iv, cookie: 0x11223344, myTick: 1000, yourTick: 2000, compressed: false, payload: payload)
        expectEqual(enc.packet, expected, "wire layout must be IV || ciphertext || tag with no AAD")
        let dec = try UdpAccelPacket.decode(packet: expected, key32: key)
        expectEqual(dec.header.cookie, 0x11223344); expectEqual(dec.header.myTick, 1000); expectEqual(dec.header.yourTick, 2000)
        expectEqual(dec.payload, payload)
    }
    test("udp/any-nonzero-flag-byte-decodes-as-compressed") {
        let key = (0..<32).map { UInt8($0) }
        // flag byte 7 in an otherwise valid, authentic packet: upstream treats any nonzero flag as "compressed"
        for (flag, want) in [(UInt8(0), false), (1, true), (7, true)] {
            var plain = [UInt8](repeating: 0, count: 23); plain[22] = flag
            let box = try ChaChaPoly.seal(plain, using: SymmetricKey(data: key), nonce: ChaChaPoly.Nonce(data: Data(repeating: 3, count: 12)))
            let packet = [UInt8](repeating: 3, count: 12) + [UInt8](box.ciphertext) + [UInt8](box.tag)
            let dec = try UdpAccelPacket.decode(packet: packet, key32: key)
            expectEqual(dec.header.compressed, want)
        }
    }
    test("dataphase/zlib-block-from-python-decodes-and-encoder-matches") {
        let plain = hexBytes(
            "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f68656c6c6f2068656c6c6f2068656c6c6f2068656c6c6f"
        )
        let z = hexBytes("789c6360646266616563e7e0e4e2e6e1e5e367a0333f233527275f01830400a6120c71")
        let unz = try DataPhase.uncompressFrame(z), re = try DataPhase.compressFrame(plain)
        expectEqual(unz, plain)
        expectEqual(re, z, "same zlib default level as python's zlib.compress")
        var d = DataPhaseDecoder(useCompress: true)
        let items = try d.feed(be32(1) + be32(UInt32(z.count)) + z)
        expectEqual(items, [.frame(plain)])
    }
    test("dataphase/compression-failure-is-an-error-not-a-raw-frame") {
        expectThrows(try DataPhase.compressFrame([UInt8](repeating: 7, count: 500), capacity: 4))
        let enc = try DataPhase.encode(frames: [[1, 2, 3]], useCompress: true)
        expect(enc != DataPhase.encode(frames: [[1, 2, 3]]), "compressed encoding differs from raw")
        let raw = try DataPhase.encode(frames: [[1, 2, 3]], useCompress: false)
        expectEqual(raw, DataPhase.encode(frames: [[1, 2, 3]]))
    }

    test("handshake/secure-password-matches-independent-python-sha0") {
        let random = Array(0..<20).map { UInt8($0) }
        for (pw, user, want) in [
            ("pass456", "bob", "1e0db3ad0b464ace496b2f397ded6d37914df92d"),
            ("s3cret", "jürgen", "f393a418a80101c9d947349c864a334c13cb044d"),  // non-ASCII letter must stay as is
            ("pw", "straße", "814b4441653d7c5ed931fd7b00ebdac32c2fa370"),
        ] {
            let s = FakeSoftEtherServer()
            let c = SoftEtherClient(host: "1.2.3.4", port: 443, userName: user, auth: .hashedPassword(pw), proxy: ProxySettings(), makeStream: s.factory)
            _ = try await c.connect { _ in }
            expectEqual(s.helloPack().data("random").map { [UInt8]($0) }, random)
            expectEqual(s.logins[0].data("secure_password").map { [UInt8]($0) }, hexBytes(want), "\(user)")
            c.close(nil)
        }
        expectEqual(SoftEtherClient.asciiUppercased("jürgen-ß"), "JüRGEN-ß")
    }
    test("handshake/login-requests-qos-like-upstream") {
        let s = FakeSoftEtherServer()
        let c = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), makeStream: s.factory)
        _ = try await c.connect { _ in }
        expectEqual(s.logins[0].int("qos"), 1)
        c.close(nil)
    }

    // MARK: 14 welcome validation, 13 leaks

    test("handshake/welcome-without-session-key-or-name-is-rejected") {
        let s = FakeSoftEtherServer(); s.welcomeOverride = Pack()
        let e = await connectError(s)
        expect(e?.contains("Malformed welcome") == true, "empty pack: \(e ?? "success")")
        expect(s.lastStream?.isCancelled == true)
        var noKey = Pack(); noKey.addStr("session_name", "SID-X")
        let s2 = FakeSoftEtherServer(); s2.welcomeOverride = noKey
        let e2 = await connectError(s2)
        expect(e2?.contains("Malformed welcome") == true, "no key: \(e2 ?? "success")")
        var shortKey = noKey; shortKey.addData("session_key", Data(repeating: 1, count: 5))
        let s3 = FakeSoftEtherServer(); s3.welcomeOverride = shortKey
        let e3 = await connectError(s3)
        expect(e3 != nil, "5-byte session key")
    }
    test("handshake/stream-is-cancelled-when-login-pack-building-fails") {
        let s = FakeSoftEtherServer()
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, auth: .certificate(certDer: Data([1]), sign: { _ in throw Boom() }),
            proxy: ProxySettings(), makeStream: s.factory)
        do { _ = try await c.connect { _ in }; fail("should throw") } catch { expectEqual(error.localizedDescription, "boom") }
        expect(s.lastStream?.isCancelled == true, "leaked TLS stream")
    }
    test("handshake/stream-is-cancelled-when-sending-the-login-fails") {
        let s = FakeSoftEtherServer()
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, proxy: ProxySettings(),
            makeStream: { h, p, pr in
                ThrowingStream(s.factory(h, p, pr) as! FakeStream)
            })
        do { _ = try await c.connect { _ in }; fail("should throw") } catch { expectEqual(error.localizedDescription, "boom") }
        expect(s.lastStream?.isCancelled == true, "leaked TLS stream")
    }
    test("handshake/plain-retry-failure-releases-the-new-stream") {
        let s = FakeSoftEtherServer(); s.rejectWatermark = true
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, proxy: ProxySettings(),
            makeStream: { h, p, pr in
                if s.streamsCreated >= 1 { s.failStart = Boom() }
                return s.factory(h, p, pr)
            })
        do { _ = try await c.connect { _ in }; fail("should throw") } catch { expectEqual(error.localizedDescription, "boom") }
        expectEqual(s.streamsCreated, 2)
        expect(s.lastStream?.isCancelled == true, "second stream leaked")
    }

    // MARK: half connection

    test("halfconnect/login-requests-it-and-asks-for-at-least-4-connections") {
        let off = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), maxConnections: 1, halfConnection: false)
        expectEqual(off.loginPack().int("half_connection"), 0)

        let on = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), maxConnections: 1, halfConnection: true)
        expectEqual(on.loginPack().int("half_connection"), 1)
        // maxConnections: 1 must be raised to the half-connection minimum, not kept at 1.
        expectEqual(on.loginPack().int("max_connection"), 4)
    }

    test("halfconnect/directions-are-applied-end-to-end") {
        // Primary = client-to-server (our own rule); 3 additional connections get server assigned directions:
        // client-to-server, server-to-client, and "both" (an empty/omitted reply, same as a normal connection).
        let s = FakeSoftEtherServer(); s.maxConnections = 4
        s.additionalConnectDirections = [2, 1, 0]
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, proxy: ProxySettings(), maxConnections: 4,
            useUdpAccel: false, halfConnection: true, makeStream: s.factory)
        c.replenishInterval = 0.05
        let frames = Locked([[UInt8]]())
        c.onFrame = { frame in frames.update { $0.append(frame) } }
        _ = try await c.connect { _ in }
        await expectA(await eventually(5) { c.activeConnectionCount == 4 }, "pool did not fill: \(c.activeConnectionCount)")
        let streams = s.streams
        expectEqual(streams.count, 4)
        // Identify each stream by what it was actually told, not by array position (additional connections are
        // opened one at a time, but nothing here should depend on assuming that stays true).
        guard let stcAdditional = streams.first(where: { $0.assignedDirection == 1 }) else {
            expect(false, "no stream was ever assigned direction=1 (server-to-client)"); return
        }
        let sendCapable = streams.filter { $0.assignedDirection != 1 }  // primary (nil) + direction 2 and 0
        expectEqual(sendCapable.count, 3)

        // 1. Send-side: sending many frames must never land on the server-to-client-only socket.
        for i in 0..<40 { c.sendFrame([UInt8](repeating: UInt8(i % 256), count: 64)) }
        await expectA(await eventually(3) { sendCapable.reduce(0) { $0 + $1.bytesReceivedFromClient } > 0 })
        try? await Task.sleep(nanoseconds: 100_000_000)  // let any stray send settle before asserting zero
        expectEqual(stcAdditional.bytesReceivedFromClient, 0, "nothing must be sent on the server-to-client-only socket")

        // 2. Receive-side: data delivered on the server-to-client socket must still reach onFrame normally.
        let probe = try DataPhase.encode(frames: [[UInt8](repeating: 0xAB, count: 10)], useCompress: false)
        stcAdditional.deliver([UInt8](probe))
        await expectA(
            await eventually(3) { frames.value.contains { $0 == [UInt8](repeating: 0xAB, count: 10) } },
            "frame delivered on the server-to-client socket never reached onFrame")

        c.close(nil)
    }

    test("halfconnect/client-to-server-only-socket-is-not-torn-down-for-never-receiving") {
        // A send-only socket is NEVER expected to receive application data; the per-socket idle-read watchdog
        // must not fire for it just because nothing ever arrives.
        let s = FakeSoftEtherServer(); s.maxConnections = 2; s.welcomeTimeoutMs = 500  // clamped to the 500ms floor anyway
        s.additionalConnectDirections = [2]  // the one additional connection is client-to-server-only
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, proxy: ProxySettings(), maxConnections: 2,
            useUdpAccel: false, halfConnection: true, makeStream: s.factory)
        c.replenishInterval = 0.05
        _ = try await c.connect { _ in }
        await expectA(await eventually(5) { c.activeConnectionCount == 2 })
        try? await Task.sleep(nanoseconds: 900_000_000)  // well past the 500ms idle-read timeout
        expectEqual(c.activeConnectionCount, 2, "the send-only socket must survive despite never receiving anything")
        c.close(nil)
    }

    // MARK: 12 additional connections

    test("pool/additional-connection-is-replaced-after-a-socket-dies") {
        let s = FakeSoftEtherServer(); s.maxConnections = 3
        let c = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), maxConnections: 3, useUdpAccel: false, makeStream: s.factory)
        c.replenishInterval = 0.05
        _ = try await c.connect { _ in }
        await expectA(await eventually(5) { c.activeConnectionCount == 3 }, "pool never filled: \(c.activeConnectionCount)")
        expectEqual(s.additionalConnects.count, 2)
        s.lastStream?.failFromServer(StreamError.closed)  // one additional socket dies
        await expectA(
            await eventually(5) { s.additionalConnects.count == 3 && c.activeConnectionCount == 3 },
            "pool did not replenish: attempts \(s.additionalConnects.count), active \(c.activeConnectionCount)")
        c.close(nil)
    }
    test("pool/failed-additional-connects-are-retried-with-backoff") {
        let s = FakeSoftEtherServer(); s.maxConnections = 2; s.failAdditionalConnects = 2
        let c = SoftEtherClient(host: "1.2.3.4", port: 443, proxy: ProxySettings(), maxConnections: 2, useUdpAccel: false, makeStream: s.factory)
        c.replenishInterval = 0.05
        _ = try await c.connect { _ in }
        await expectA(await eventually(5) { c.activeConnectionCount == 2 }, "never recovered: \(s.additionalConnects.count) attempts")
        expectEqual(s.additionalConnects.count, 3, "two refusals then success")
        c.close(nil)
        await expectA(await eventually(3) { c.activeConnectionCount == 0 })
        let seen = s.additionalConnects.count
        try? await Task.sleep(nanoseconds: 300_000_000)
        expectEqual(s.additionalConnects.count, seen, "no connection attempts after close()")
    }

    // MARK: 17 pending queue

    test("client/pending-send-queue-is-capped") {
        let s = FakeSoftEtherServer()
        let held = Locked<HoldableStream?>(nil)
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, proxy: ProxySettings(), useUdpAccel: false,
            makeStream: { h, p, pr in
                let st = HoldableStream(s.factory(h, p, pr) as! FakeStream); held.update { $0 = st }; return st
            })
        _ = try await c.connect { _ in }
        held.value!.hold.update { $0 = true }
        for i in 0..<6000 { c.sendFrame([UInt8(i & 0xff), 1, 2, 3]) }
        expect(c.pendingFrameCount <= SoftEtherClient.maxPendingFrames, "pending \(c.pendingFrameCount)")
        expect(c.droppedFrames >= 6000 - SoftEtherClient.maxPendingFrames - 64, "dropped \(c.droppedFrames)")
        c.close(nil)
    }

    // MARK: 3 session routes

    test("session/extra-bypass-hosts-from-the-transport-get-routes") {
        let h = SessionHarness(); h.bypassHostsFor = ["5.6.7.8", "1.2.3.4", "9.9.9.9"]
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        let up = Locked(false); s.emit = { e in if e.state == .connected { up.update { $0 = true } } }
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await eventually(5) { up.value })
        expectEqual(h.nets.value[0].applied.first?.host, "1.2.3.4")
        expectEqual(h.nets.value[0].bypassed, ["5.6.7.8", "9.9.9.9"], "primary host is not added twice")
        s.disconnect()
    }

    // MARK: 2 certificate authentication

    test("cert/signature-verifies-over-the-server-random") {
        let key = makeRSAKey()
        let random = Data((0..<20).map { UInt8($0) })
        let sig = try CertAuth.sign(random, privateKeyDer: key.pkcs1)
        expectEqual(sig.count, 256)
        expect(verifySHA1(key.publicKey, signature: sig, over: random), "RSA PKCS#1 v1.5 SHA-1 signature over the 20 random bytes")
        expect(!verifySHA1(key.publicKey, signature: sig, over: Data(repeating: 0, count: 20)), "must not verify over other data")
    }
    test("cert/pkcs8-wrapped-keys-are-accepted") {
        let key = makeRSAKey()
        let algId = der(0x30, der(0x06, [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]) + [0x05, 0x00])
        let pkcs8 = Data(der(0x30, der(0x02, [0]) + algId + der(0x04, [UInt8](key.pkcs1))))
        expectEqual(CertAuth.unwrapPKCS8(pkcs8), key.pkcs1)
        expectEqual(CertAuth.unwrapPKCS8(key.pkcs1), nil, "a PKCS#1 key is not PKCS#8")
        let random = Data(repeating: 0x5a, count: 20)
        let sig8 = try CertAuth.sign(random, privateKeyDer: pkcs8)
        expect(verifySHA1(key.publicKey, signature: sig8, over: random))
    }
    test("cert/bad-or-missing-key-fails_without_leaking_key_bytes") {
        expectThrows(try CertAuth.signer(privateKeyDer: nil)(Data(count: 20)))
        expectThrows(try CertAuth.signer(privateKeyDer: Data())(Data(count: 20)))
        let junk = Data("not a key SECRETSECRET".utf8)
        do { _ = try CertAuth.sign(Data(count: 20), privateKeyDer: junk); fail("should throw") } catch {
            expect(!error.localizedDescription.contains("SECRET"), error.localizedDescription)
        }
        expectThrows(try CertAuth.sign(Data(count: 20), privateKeyDer: Data(count: CertAuth.maxKeyBytes + 1)))
    }
    test("cert/login-carries-a-real-signature-over-the-servers-random") {
        let key = makeRSAKey(); let s = FakeSoftEtherServer()
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, userName: "carol",
            auth: .certificate(certDer: Data(base64Encoded: testCertB64)!, sign: CertAuth.signer(privateKeyDer: key.pkcs1)),
            proxy: ProxySettings(), makeStream: s.factory)
        _ = try await c.connect { _ in }
        expectEqual(s.logins[0].int("authtype"), 3)
        expectEqual(s.logins[0].data("cert"), Data(base64Encoded: testCertB64)!)
        let random = s.helloPack().data("random")!
        expect(verifySHA1(key.publicKey, signature: s.logins[0].data("sign") ?? Data(), over: random), "sign field must verify over the hello random")
        c.close(nil)
    }
    test("cert/session-builds-the-signer-from-connect-config") {
        let key = makeRSAKey()
        var cfg = ConnectConfig(host: "1.2.3.4", authType: "User Certificate")
        cfg.certDer = Data([1, 2]); cfg.privateKeyDer = key.pkcs1
        let t = SessionDependencies().transport(config: cfg, port: 443)
        expect(t is SoftEtherClient)
        // missing key: the handshake must fail with a clear message instead of sending empty bytes
        let s = FakeSoftEtherServer()
        let c = SoftEtherClient(
            host: "1.2.3.4", port: 443, auth: .certificate(certDer: Data([1]), sign: CertAuth.signer(privateKeyDer: nil)),
            proxy: ProxySettings(), makeStream: s.factory)
        do { _ = try await c.connect { _ in }; fail("should throw") } catch {
            expect(error.localizedDescription.contains("private key"), error.localizedDescription)
        }
    }
    test("cert/connect-config-carries-the-key-and-ipc-clamps-sizes") {
        var cfg = ConnectConfig(host: "1.2.3.4", authType: "User Certificate")
        cfg.certDer = Data([1, 2, 3]); cfg.privateKeyDer = Data(repeating: 9, count: 1200)
        let back = try JSONDecoder().decode(ConnectConfig.self, from: JSONEncoder().encode(cfg))
        expectEqual(back, cfg)
        var r = HelperRequest(cmd: "connect"); r.config = cfg
        expectEqual(IPCServer.validate(r), nil)
        cfg.privateKeyDer = Data(count: CertAuth.maxKeyBytes + 1); r.config = cfg
        expectEqual(IPCServer.validate(r), "private key too large")
        cfg.privateKeyDer = nil; cfg.certDer = Data(count: CertAuth.maxCertBytes + 1); r.config = cfg
        expectEqual(IPCServer.validate(r), "certificate too large")
        let acc = ClientAccount(name: "n", host: "1.2.3.4", authType: .certificate)
        let c2 = acc.toConnectConfig(certDer: Data([1]), privateKeyDer: Data([2]))
        expectEqual(c2.privateKeyDer, Data([2])); expectEqual(c2.certDer, Data([1]))
    }

    // MARK: 18 server certificate pinning

    test("tls/pin-parses-sha1-and-sha256-fingerprints-in_any_format") {
        let der = Data(base64Encoded: testCertB64)!
        for fp in [
            testCertSHA1, testCertSHA1.lowercased(), testCertSHA1.replacingOccurrences(of: ":", with: ""),
            testCertSHA256, testCertSHA256.replacingOccurrences(of: ":", with: " "),
        ] {
            guard let pin = CertPin(fp) else { fail("unparsed: \(fp)"); continue }
            expect(pin.matches(certDER: der), fp)
        }
        expectEqual(CertPin("abcd"), nil); expectEqual(CertPin(String(repeating: "g", count: 40)), nil); expectEqual(CertPin(""), nil)
        var other = der; other[other.count - 1] ^= 1
        expect(!CertPin(testCertSHA256)!.matches(certDER: other))
        expect(!CertPin(testCertSHA1)!.matches(certDER: other))
    }
    test("tls/policy-enforces-the-pin-and-fails-closed") {
        let der = Data(base64Encoded: testCertB64)!
        let pinned = ServerCertPolicy(checkServerCert: true, fingerprint: testCertSHA256)
        expectEqual(pinned.rejection(leafDER: der), nil)
        expect(pinned.rejection(leafDER: Data([1, 2, 3]))?.contains("does not match") == true)
        expect(pinned.rejection(leafDER: nil) != nil)
        // a configured fingerprint is enforced even if the checkbox says otherwise
        expect(ServerCertPolicy(checkServerCert: false, fingerprint: testCertSHA1).rejection(leafDER: Data([1])) != nil)
        // garbage fingerprint: never silently accept
        let bad = ServerCertPolicy(checkServerCert: true, fingerprint: "not-hex")
        expectEqual(bad, .invalidPin); expect(bad.rejection(leafDER: der) != nil)
        // unchanged default for VPN Gate relays
        expectEqual(ServerCertPolicy(checkServerCert: false, fingerprint: nil), .acceptAny)
        expectEqual(ServerCertPolicy(checkServerCert: false, fingerprint: "  "), .acceptAny)
        expectEqual(ServerCertPolicy(checkServerCert: true, fingerprint: nil), .systemTrust)
        expectEqual(ServerCertPolicy.acceptAny.rejection(leafDER: nil), nil)
    }
    test("tls/session-passes-the-account-pin-to-the-transport") {
        var cfg = ConnectConfig(host: "1.2.3.4"); cfg.checkServerCert = true; cfg.serverCertFingerprint = testCertSHA1
        expect(SessionDependencies().transport(config: cfg, port: 443) is SoftEtherClient)
    }
}
