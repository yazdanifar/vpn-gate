import Darwin
import Foundation
import VPNGateCore

/// Connects straight to loopback (no interface binding) and records what was asked for.
final class LoopbackConnector: SocksConnector {
    let requests = Locked([(host: String, port: UInt16)]())
    var remap: [String: String] = [:]
    func connect(host: String, port: UInt16) -> Result<Int32, SocksServer.Failure> {
        requests.update { $0.append((host, port)) }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in(); addr.sin_family = sa_family_t(AF_INET); addr.sin_port = port.bigEndian
        inet_pton(AF_INET, remap[host] ?? host, &addr.sin_addr)
        return SocksServer.connect(fd, to: &addr, timeoutMs: 2000)
    }
}

/// Accepts one connection and echoes everything back until it closes.
private final class EchoServer {
    let port: UInt16
    private let fd: Int32
    init() {
        let lfd = socket(AF_INET, SOCK_STREAM, 0)
        var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = UInt32(INADDR_LOOPBACK).bigEndian
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(lfd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(lfd, 4)
        var b = sockaddr_in(); var l = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &b) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(lfd, $0, &l) } }
        port = UInt16(bigEndian: b.sin_port)
        fd = lfd
        Thread.detachNewThread {
            let c = accept(lfd, nil, nil)
            guard c >= 0 else { return }
            var buf = [UInt8](repeating: 0, count: 1024)
            while true {
                let n = recv(c, &buf, buf.count, 0)
                if n <= 0 { break }
                _ = SocksServer.writeAll(c, Array(buf[0..<n]))
            }
            close(c)
        }
    }
    deinit { close(fd) }
}

/// A loopback port nothing listens on (bound, read back, closed).
private func unusedPort() -> UInt16 {
    let fd = socket(AF_INET, SOCK_STREAM, 0); defer { close(fd) }
    var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = UInt32(INADDR_LOOPBACK).bigEndian
    _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    var l = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &l) } }
    return UInt16(bigEndian: a.sin_port)
}

private func dial(_ port: UInt16) -> Int32 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_port = port.bigEndian
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr)
    _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    var tv = timeval(tv_sec: 3, tv_usec: 0)
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
    return fd
}

/// Greeting (no auth) + a CONNECT request; returns the reply's status byte (nil if the server hung up).
private func socksConnect(_ fd: Int32, atyp: UInt8, dest: [UInt8], port: UInt16, cmd: UInt8 = 1) -> UInt8? {
    _ = SocksServer.writeAll(fd, [5, 1, 0])
    guard SocksServer.readExactly(fd, 2) == [5, 0] else { return nil }
    _ = SocksServer.writeAll(fd, [5, cmd, 0, atyp] + dest + [UInt8(port >> 8), UInt8(port & 0xFF)])
    return SocksServer.readExactly(fd, 10).map { $0[1] }
}

private func dnsAnswer(for query: [UInt8], ip: [UInt8]) -> [UInt8] {
    var r = query
    r[2] |= 0x80; r[7] = 1
    r += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4] + ip
    return r
}

private struct StubDNS: DNSUpstream {
    var ip: [UInt8]?
    func query(_ message: [UInt8], server: String, timeoutMs: Int32) -> [UInt8]? { ip.map { dnsAnswer(for: message, ip: $0) } }
}

private let socksLease = Lease(
    ip: 0x0AE991B6, mask: 0xFFFF0000, router: 0x0AE9FEFE,
    dns: [0x0AE9FEFE], seconds: 3600, serverID: 0x0AE9FEFE)

func registerSocksTests() {
    test("socks/relays-both-directions-for-an-ipv4-destination") {
        let echo = EchoServer()
        let server = SocksServer(port: 0, connector: LoopbackConnector())
        try server.start(); defer { server.stop() }
        let fd = dial(server.boundPort); defer { close(fd) }
        expectEqual(socksConnect(fd, atyp: 1, dest: [127, 0, 0, 1], port: echo.port), 0)
        _ = SocksServer.writeAll(fd, Array("hello".utf8))
        expectEqual(SocksServer.readExactly(fd, 5).map { String(decoding: $0, as: UTF8.self) }, "hello")
    }
    test("socks/passes-a-domain-name-to-the-connector-unresolved") {
        let echo = EchoServer()
        let conn = LoopbackConnector(); conn.remap = ["example.test": "127.0.0.1"]
        let server = SocksServer(port: 0, connector: conn)
        try server.start(); defer { server.stop() }
        let fd = dial(server.boundPort); defer { close(fd) }
        let name = Array("example.test".utf8)
        expectEqual(socksConnect(fd, atyp: 3, dest: [UInt8(name.count)] + name, port: echo.port), 0)
        expectEqual(conn.requests.value.first?.host, "example.test")
    }
    test("socks/rejects-unsupported-commands-address-types-and-methods") {
        let server = SocksServer(port: 0, connector: LoopbackConnector())
        try server.start(); defer { server.stop() }
        do {
            let fd = dial(server.boundPort); defer { close(fd) }
            expectEqual(socksConnect(fd, atyp: 1, dest: [1, 2, 3, 4], port: 80, cmd: 2), SocksServer.Failure.commandUnsupported.rawValue)
        }
        do {
            let fd = dial(server.boundPort); defer { close(fd) }
            expectEqual(socksConnect(fd, atyp: 4, dest: [UInt8](repeating: 1, count: 16), port: 80), SocksServer.Failure.addressTypeUnsupported.rawValue)
        }
        do {
            let fd = dial(server.boundPort); defer { close(fd) }
            _ = SocksServer.writeAll(fd, [5, 1, 2])  // only username/password offered
            expectEqual(SocksServer.readExactly(fd, 2), [5, 0xFF])
        }
        do {
            let fd = dial(server.boundPort); defer { close(fd) }
            let bad = Array("a b;rm".utf8)
            expectEqual(socksConnect(fd, atyp: 3, dest: [UInt8(bad.count)] + bad, port: 80), SocksServer.Failure.hostUnreachable.rawValue)
        }
    }
    test("socks/reports-a-refused-connection") {
        let server = SocksServer(port: 0, connector: LoopbackConnector())
        try server.start(); defer { server.stop() }
        let fd = dial(server.boundPort); defer { close(fd) }
        let port = unusedPort()
        let code = socksConnect(fd, atyp: 1, dest: [127, 0, 0, 1], port: port)
        expect(code != nil && code != 0, "expected a failure code, got \(String(describing: code))")
    }
    test("socks/stop-closes-the-listener-and-live-sessions") {
        let echo = EchoServer()
        let server = SocksServer(port: 0, connector: LoopbackConnector())
        try server.start()
        let fd = dial(server.boundPort); defer { close(fd) }
        expectEqual(socksConnect(fd, atyp: 1, dest: [127, 0, 0, 1], port: echo.port), 0)
        server.stop()
        expect(!server.isListening)
        var b: UInt8 = 0
        expect(recv(fd, &b, 1, 0) <= 0, "an established session must end when the proxy stops")
    }
    test("socks/port-can-be-rebound-right-after-stop") {
        let first = SocksServer(port: 0, connector: LoopbackConnector())
        try first.start()
        let port = first.boundPort
        first.stop()
        let second = SocksServer(port: port, connector: LoopbackConnector())
        try second.start()
        expectEqual(second.boundPort, port)
        second.stop()
    }
    test("socks/large-simultaneous-transfers-do-not-deadlock") {
        let echo = EchoServer()
        let server = SocksServer(port: 0, connector: LoopbackConnector())
        try server.start(); defer { server.stop() }
        let fd = dial(server.boundPort); defer { close(fd) }
        expectEqual(socksConnect(fd, atyp: 1, dest: [127, 0, 0, 1], port: echo.port), 0)
        let total = 4 * 1024 * 1024
        let writer = Thread {
            _ = SocksServer.writeAll(fd, [UInt8](repeating: 7, count: total)); shutdown(fd, SHUT_WR)
        }
        writer.start()
        var got = 0
        var buf = [UInt8](repeating: 0, count: 65536)
        while got < total { let n = recv(fd, &buf, buf.count, 0); if n <= 0 { break }; got += n }
        expectEqual(got, total)
    }
    test("socks/tunnel-connector-resolves-through-the-vpn-dns-and-binds-the-interface") {
        let echo = EchoServer()
        // lo0 stands in for the utun: the socket is really bound to it with IP_BOUND_IF.
        let c = TunnelConnector(
            interfaceIndex: if_nametoindex("lo0"), dnsServers: ["10.233.254.254"],
            upstream: StubDNS(ip: [127, 0, 0, 1]))
        switch c.connect(host: "example.test", port: echo.port) {
        case .success(let fd): close(fd)
        case .failure(let f): fail("connect failed: \(f)")
        }
        let none = TunnelConnector(interfaceIndex: if_nametoindex("lo0"), dnsServers: ["10.233.254.254"], upstream: StubDNS(ip: nil))
        if case .success(let fd) = none.connect(host: "example.test", port: echo.port) { close(fd); fail("unresolvable name must not connect") }
    }
    test("socks/a-query-is-a-well-formed-recursive-a-question") {
        let q = DNSMessage.aQuery(name: "www.example.com", id: 0x1234)
        expectEqual(Array(q[0..<4]), [0x12, 0x34, 0x01, 0x00])
        expectEqual(DNSMessage.queryName(q), "www.example.com")
        expectEqual(Array(q.suffix(4)), [0, 1, 0, 1])
        expectEqual(DNSMessage.resolvedIPv4Addresses(dnsAnswer(for: q, ip: [9, 8, 7, 6])), ["9.8.7.6"])
    }
    test("socks/netconfig-adds-only-an-interface-scoped-default-route") {
        let r = RecordingRunner(); let d = FakeDNS()
        let path = tempPath(UUID().uuidString + ".state")
        let n = NetConfig(runner: r, dns: d, stateFile: path)
        try n.applySocks(iface: "utun7", lease: socksLease, mtuOverride: nil)
        expect(r.log.contains("/sbin/route -n add -ifscope utun7 default 10.233.254.254"), "log: \(r.log)")
        expect(r.log.contains("/sbin/route -n add -ifscope utun7 -host 10.233.254.254 -interface utun7"), "log: \(r.log)")
        expect(r.log.filter { $0.contains("route -n add") }.allSatisfy { $0.contains("-ifscope") }, "every route must be scoped: \(r.log)")
        expect(
            !r.log.contains { $0.contains("0.0.0.0/1") || $0.contains("128.0.0.0/1") || $0.contains("::/1") || $0.contains("get default") },
            "no global route may be touched: \(r.log)")
        expectEqual(d.setCalls.count, 0)
        n.teardown()
        expect(r.log.contains("/sbin/route -n delete -ifscope utun7 default 10.233.254.254"), "log: \(r.log)")
        expectEqual(d.removeCalls, 0)
        expect(!FileManager.default.fileExists(atPath: path))
    }
    test("socks/session-serves-a-proxy-and-leaves-routes-and-dns-alone") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        let events = Locked([HelperEvent]()); s.emit = { e in events.update { $0.append(e) } }
        var cfg = ConnectConfig(host: "1.2.3.4")
        cfg.tunnelMode = .socksProxy; cfg.socksPort = 0
        cfg.routing = RoutingConfig(rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .direct)])
        s.connect(config: cfg)
        await expectA(await eventually(5) { events.value.last?.state == .connected }, "never connected")
        expectEqual(h.nets.value[0].socksIfaces, ["utunF0"])
        expectEqual(h.nets.value[0].applied.count, 0, "the full-tunnel apply() must not run")
        expectEqual(h.dnsProxies.value.count, 0, "no system resolver proxy in SOCKS mode")
        let server = h.socksServers.value[0]
        expect(server.isListening)
        expect(events.value.last?.log?.hasPrefix("SOCKS5 proxy on 127.0.0.1:") == true, "log: \(String(describing: events.value.last?.log))")
        expect(h.tuns.value[0].reading)
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3), "run task did not finish")
        expect(!server.isListening, "proxy must stop on disconnect")
        expectEqual(h.nets.value[0].tornDown, 1)
    }
    test("socks/ipc-rejects-ports-outside-1024-65535") {
        var r = HelperRequest(cmd: "connect"); r.host = "1.2.3.4"
        r.socksPort = 80
        expectEqual(IPCServer.validate(r), nil)  // full tunnel ignores the port
        r.tunnelMode = .socksProxy
        expect(IPCServer.validate(r) != nil)
        r.socksPort = 1080
        expectEqual(IPCServer.validate(r), nil)
        var cfg = ConnectConfig(host: "1.2.3.4"); cfg.socksPort = 70000; cfg.tunnelMode = .socksProxy
        var r2 = HelperRequest(cmd: "connect"); r2.config = cfg
        expect(IPCServer.validate(r2) != nil)
    }
    test("socks/config-defaults-to-full-tunnel-when-fields-are-absent") {
        let json = #"{"host":"1.2.3.4"}"#.data(using: .utf8)!
        let cfg = try JSONDecoder().decode(ConnectConfig.self, from: json)
        expectEqual(cfg.tunnelMode, .fullTunnel); expectEqual(cfg.socksPort, 1080)
        var c2 = ConnectConfig(host: "1.2.3.4"); c2.tunnelMode = .socksProxy; c2.socksPort = 9050
        let back = try JSONDecoder().decode(ConnectConfig.self, from: JSONEncoder().encode(c2))
        expectEqual(back.tunnelMode, .socksProxy); expectEqual(back.socksPort, 9050)
    }
}
