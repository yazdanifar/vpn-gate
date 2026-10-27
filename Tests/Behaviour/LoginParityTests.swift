import Foundation
import VPNGateCore

// Login / welcome / additional_connect parity with the stock SoftEther client (v4.44-9807), the new defaults,
// and the address the bypass route is built from.

private func welcome(
    connectionName: String? = "CID-1", maxConnection: UInt32? = nil, enableUdpRecovery: Bool? = nil,
    qos: Bool? = nil, timeout: UInt32? = nil
) -> Pack {
    var p = Pack()
    p.addStr("session_name", "SID-1")
    if let c = connectionName { p.addStr("connection_name", c) }
    p.addData("session_key", Data(repeating: 0x11, count: 20))
    if let m = maxConnection { p.addInt("max_connection", m) }
    if let e = enableUdpRecovery { p.addBool("enable_udp_recovery", e) }
    if let q = qos { p.addBool("qos", q) }
    if let t = timeout { p.addInt("timeout", t) }
    return p
}

private func connect(
    _ s: FakeSoftEtherServer, maxConnections: Int = 1, disableQoS: Bool = false,
    uniqueId: HostUniqueId? = nil, host: String = "1.2.3.4", proxy: ProxySettings = ProxySettings()
) -> SoftEtherClient {
    SoftEtherClient(
        host: host, port: 443, proxy: proxy, maxConnections: maxConnections, useUdpAccel: false,
        disableQoS: disableQoS, uniqueId: uniqueId, makeStream: s.factory)
}

func registerLoginParityTests() {
    // MARK: login pack
    test("loginparity/qos-is-sent-unless-disabled") {
        let on = SoftEtherClient(host: "h", port: 443, proxy: ProxySettings()).loginPack()
        expectEqual(on.int("qos"), 1, "stock Client Manager default: QoS on")
        let off = SoftEtherClient(host: "h", port: 443, proxy: ProxySettings(), disableQoS: true).loginPack()
        expectEqual(off.int("qos"), 0, "VPN Gate client sets DisableQoS")
    }
    test("loginparity/rudp-bulk-max-version-and-pencore-on-the-wire") {
        let s = FakeSoftEtherServer(); let c = connect(s)
        _ = try await c.connect { _ in }
        expectEqual(s.logins[0].int("rudp_bulk_max_version"), 2)
        expect((s.logins[0].data("pencore")?.count ?? 1000) < 1000, "login carries pencore, rand % 1000 bytes")
        c.close(nil)
    }
    test("loginparity/unique-id-is-stable-per-install-and-not-per-attempt") {
        let id = HostUniqueId(key: Data(repeating: 7, count: 32))
        let a = SoftEtherClient(host: "h", port: 443, proxy: ProxySettings(), uniqueId: id)
        let b = SoftEtherClient(host: "other", port: 443, proxy: ProxySettings(), uniqueId: id)
        let p1 = a.loginPack(), p2 = a.loginPack(), p3 = b.loginPack()
        expectEqual(p1.data("unique_id")?.count, 20); expectEqual(p1.data("UniqueId")?.count, 16, "NodeInfo UniqueId is 16 bytes")
        expectEqual(p1.data("unique_id"), p2.data("unique_id"), "same across attempts")
        expectEqual(p1.data("unique_id"), p3.data("unique_id"), "same across clients of one install")
        expectEqual(p1.data("UniqueId"), p3.data("UniqueId"))
        let other = SoftEtherClient(
            host: "h", port: 443, proxy: ProxySettings(),
            uniqueId: HostUniqueId(key: Data(repeating: 8, count: 32))
        ).loginPack()
        expect(other.data("unique_id") != p1.data("unique_id"), "another install, another id")
        expect(p1.data("unique_id") != p1.data("UniqueId").map { $0 + Data(count: 4) }, "node id is not the login id")
    }
    test("loginparity/host-unique-id-file-persists-and-is-private") {
        let path = tempPath("uid-\(UUID().uuidString.prefix(6))")
        let first = HostUniqueId.load(path: path)
        let second = HostUniqueId.load(path: path)
        expectEqual(first.key, second.key); expectEqual(first.key.count, 32)
        let mode = (try? FileManager.default.attributesOfItem(atPath: path)[.posixPermissions] as? Int) ?? 0
        expectEqual(mode & 0o077, 0, "readable by root only")
        try Data("short".utf8).write(to: URL(fileURLWithPath: path))
        let healed = HostUniqueId.load(path: path)
        expectEqual(healed.key.count, 32, "a malformed file is replaced")
        expectEqual(HostUniqueId.load(path: path).key, healed.key)
        // unwritable location: still yields a usable (per-process) value, never throws
        expectEqual(HostUniqueId.load(path: "/nonexistent-dir-vpngate/uid").key.count, 32)
        try? FileManager.default.removeItem(atPath: path)
    }
    test("loginparity/node-info-carries-the-server-hello") {
        let s = FakeSoftEtherServer(); let c = connect(s)
        _ = try await c.connect { _ in }
        let l = s.logins[0]
        expectEqual(l.str("ServerProductName"), "SoftEther VPN Server")
        expectEqual(l.int("ServerProductVer"), 432); expectEqual(l.int("ServerProductBuild"), 9729)
        for n in ["ClientIpAddress6", "ServerIpAddress6", "ProxyIpAddress6"] { expectEqual(l.data(n)?.count, 16, n) }
        c.close(nil)
    }

    // MARK: additional_connect
    test("loginparity/additional-connect-matches-the-stock-client") {
        let s = FakeSoftEtherServer(); s.maxConnections = 2
        let c = connect(s, maxConnections: 2); c.replenishInterval = 0.05
        _ = try await c.connect { _ in }
        await expectA(await eventually(5) { s.additionalConnects.count == 1 })
        let signatures = s.requests.filter { $0.path == "/vpnsvc/connect.cgi" }
        expectEqual(signatures.count, 2)
        for r in signatures { expectEqual(Array(r.body.prefix(6)), Array("GIF89a".utf8), "watermark upload, not VPNCONNECT") }
        let p = s.additionalConnects[0]
        expectEqual(p.str("method"), "additional_connect"); expectEqual(p.data("session_key")?.count, 20)
        expectEqual(p.int("client_ver"), 444); expectEqual(p.int("client_build"), 9807)
        expect(p.data("pencore") != nil, "pencore on every pack")
        expect(p.element(named: "direction") == nil, "the client never sends a direction")
        c.close(nil)
    }
    test("loginparity/additional-connect-uses-the-plain-signature-only-if-the-first-connection-had-to") {
        let s = FakeSoftEtherServer(); s.maxConnections = 2; s.rejectWatermark = true
        let c = connect(s, maxConnections: 2); c.replenishInterval = 0.05
        _ = try await c.connect { _ in }
        await expectA(await eventually(5) { s.additionalConnects.count == 1 }, "additional connect failed against a plain-only server")
        let bodies = s.requests.filter { $0.path == "/vpnsvc/connect.cgi" }.map(\.body)
        expect(bodies.count >= 3 && bodies.last == Array("VPNCONNECT".utf8), "same signature as the first connection")
        c.close(nil)
    }

    // MARK: welcome
    test("loginparity/welcome-requires-session-and-connection-name") {
        let s = FakeSoftEtherServer(); s.welcomeOverride = welcome(connectionName: nil)
        do { _ = try await connect(s).connect { _ in }; fail("welcome without connection_name accepted") } catch {
            expect(error.localizedDescription.contains("connection_name"), "\(error)")
        }
        let ok = FakeSoftEtherServer(); ok.welcomeOverride = welcome(connectionName: "")
        let c = connect(ok); _ = try await c.connect { _ in }; c.close(nil)
    }
    test("loginparity/welcome-timeout-defaults-to-30s") {
        let s = FakeSoftEtherServer(); s.welcomeOverride = welcome()
        let c = connect(s); let w = try await c.connect { _ in }
        expectEqual(w.timeoutMs, 30000); c.close(nil)
    }
    test("loginparity/max-connection-rule") {
        let n = SoftEtherClient.negotiatedMaxConnection
        expectEqual(n(8, false, 1, false, false), 1, "capped by the client without UDP recovery")
        expectEqual(n(8, true, 1, false, false), 8, "server value kept with UDP recovery")
        expectEqual(n(100, true, 1, false, false), 32); expectEqual(n(0, false, 4, false, false), 1)
        expectEqual(n(1, false, 1, true, false), 2, "QoS raises to 2"); expectEqual(n(1, false, 1, true, true), 4)
        expectEqual(n(3, false, 8, true, false), 3)
    }
    test("loginparity/welcome-max-connection-applied") {
        let s = FakeSoftEtherServer(); s.welcomeOverride = welcome(maxConnection: 6, enableUdpRecovery: true)
        let c = connect(s); let w6 = try await c.connect { _ in }; expectEqual(w6.maxConnection, 6); c.close(nil)
        let t = FakeSoftEtherServer(); t.welcomeOverride = welcome(maxConnection: 6)
        let d = connect(t, maxConnections: 3); let w = try await d.connect { _ in }
        expectEqual(w.maxConnection, 3); expect(!w.enableUdpRecovery); d.close(nil)
        let q = FakeSoftEtherServer(); q.welcomeOverride = welcome(maxConnection: 1, qos: true)
        q.maxConnections = 2
        let e = connect(q); e.replenishInterval = 0.05
        let wq = try await e.connect { _ in }; expectEqual(wq.maxConnection, 2, "QoS session opens a second connection")
        await expectA(await eventually(5) { q.additionalConnects.count == 1 }, "the QoS bump must be honoured by the pool")
        e.close(nil)
    }

    // MARK: defaults and IPC compatibility
    test("loginparity/defaults-are-the-stock-ones") {
        expectEqual(ConnectConfig(host: "h").maxConnection, 1); expectEqual(ConnectConfig(host: "h").disableQoS, false)
        let acc = ClientAccount(name: "a", host: "h")
        expectEqual(acc.maxConnection, 1); expectEqual(acc.disableQoS, false)
        let old = #"{"id":"\#(UUID().uuidString)","name":"n","host":"h"}"#
        let decoded = try JSONDecoder().decode(ClientAccount.self, from: Data(old.utf8))
        expectEqual(decoded.maxConnection, 1, "a stored account lacking the field gets the stock value")
        expectEqual(decoded.disableQoS, false)
        var kept = ClientAccount(name: "a", host: "h", maxConnection: 8, disableQoS: true)
        kept = try JSONDecoder().decode(ClientAccount.self, from: JSONEncoder().encode(kept))
        expectEqual(kept.maxConnection, 8, "an explicit 8 is not migrated"); expectEqual(kept.disableQoS, true)
        expectEqual(kept.toConnectConfig().disableQoS, true)
    }
    test("loginparity/connect-config-from-an-older-app-still-decodes") {
        // what the previous app version sent: no disableQoS key
        var cfg = ConnectConfig(host: "h", maxConnection: 5)
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(cfg)) as! [String: Any]
        json.removeValue(forKey: "disableQoS")
        cfg = try JSONDecoder().decode(ConnectConfig.self, from: JSONSerialization.data(withJSONObject: json))
        expectEqual(cfg.disableQoS, false); expectEqual(cfg.maxConnection, 5)
        let min = try JSONDecoder().decode(ConnectConfig.self, from: Data(#"{"host":"x"}"#.utf8))
        expectEqual(min.maxConnection, 1); expectEqual(min.hubName, "VPNGATE")
        let round = try JSONDecoder().decode(ConnectConfig.self, from: JSONEncoder().encode(ConnectConfig(host: "h", disableQoS: true)))
        expectEqual(round.disableQoS, true)
    }
    test("loginparity/vpngate-server-connect-uses-the-vpngate-client-settings") {
        let h = SessionHarness(); let seen = Locked([ConnectConfig]())
        var d = h.deps()
        d.makeTransportConfig = { cfg, port in
            seen.update { $0.append(cfg) }
            return FakeTransport(host: cfg.host, port: port, network: h.network)
        }
        let s = VPNSession(deps: d, timing: h.fastTiming)
        s.connect(host: "1.2.3.4", port: 443, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await eventually(5) { !seen.value.isEmpty })
        expectEqual(seen.value.first?.maxConnection, 1); expectEqual(seen.value.first?.disableQoS, true)
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3))
    }

    // MARK: bypass address
    test("loginparity/client-reports-the-connected-address") {
        let s = FakeSoftEtherServer(); s.remoteIPv4 = "198.51.100.7"
        let c = connect(s, host: "vpn.example.org"); _ = try await c.connect { _ in }
        expectEqual(c.remoteIPv4, "198.51.100.7"); expectEqual(c.bypassHosts, ["198.51.100.7"])
        c.close(nil)
        let u = FakeSoftEtherServer()
        let d = connect(u, host: "vpn.example.org"); _ = try await d.connect { _ in }
        expectEqual(d.remoteIPv4, nil); expectEqual(d.bypassHosts, ["vpn.example.org"], "unknown address: fall back to the name")
        d.close(nil)
        var proxy = ProxySettings(); proxy.kind = .http; proxy.host = "10.9.9.9"; proxy.port = 3128
        let p = FakeSoftEtherServer(); p.remoteIPv4 = "10.9.9.9"
        let e = connect(p, proxy: proxy); _ = try await e.connect { _ in }
        expectEqual(e.remoteIPv4, nil, "behind a proxy the peer is the proxy"); expectEqual(e.bypassHosts, [])
        e.close(nil)
    }
    test("loginparity/session-bypasses-the-resolved-address-not-the-hostname") {
        let h = SessionHarness(); h.remoteIPv4For = { _ in "203.0.113.9" }
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        s.connect(config: ConnectConfig(host: "vpn.example.org", ports: [443], autoReconnect: false))
        await expectA(await eventually(5) { !h.nets.value.isEmpty && !h.nets.value[0].applied.isEmpty })
        expectEqual(h.nets.value[0].applied.first?.host, "203.0.113.9")
        s.disconnect(); await expectA(await s.waitUntilIdle(timeout: 3))

        let h2 = SessionHarness(); h2.remoteIPv4For = { _ in "203.0.113.9" }
        let s2 = VPNSession(deps: h2.deps(), timing: h2.fastTiming)
        s2.connect(config: ConnectConfig(host: "1.2.3.4", ports: [443], autoReconnect: false))
        await expectA(await eventually(5) { !h2.nets.value.isEmpty && !h2.nets.value[0].applied.isEmpty })
        expectEqual(h2.nets.value[0].applied.first?.host, "1.2.3.4", "an IPv4 literal is used as given")
        s2.disconnect(); await expectA(await s2.waitUntilIdle(timeout: 3))

        let h3 = SessionHarness()  // address unknown: the name, as before
        let s3 = VPNSession(deps: h3.deps(), timing: h3.fastTiming)
        s3.connect(config: ConnectConfig(host: "vpn.example.org", ports: [443], autoReconnect: false))
        await expectA(await eventually(5) { !h3.nets.value.isEmpty && !h3.nets.value[0].applied.isEmpty })
        expectEqual(h3.nets.value[0].applied.first?.host, "vpn.example.org")
        s3.disconnect(); await expectA(await s3.waitUntilIdle(timeout: 3))
    }
    test("loginparity/session-keeps-the-proxy-as-bypass") {
        let h = SessionHarness(); h.remoteIPv4For = { _ in "203.0.113.9" }
        var p = ProxySettings(); p.kind = .http; p.host = "10.9.9.9"; p.port = 3128
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        s.connect(config: ConnectConfig(host: "vpn.example.org", ports: [443], proxy: p, autoReconnect: false))
        await expectA(await eventually(5) { !h.nets.value.isEmpty && !h.nets.value[0].applied.isEmpty })
        expectEqual(h.nets.value[0].applied.first?.host, "10.9.9.9")
        s.disconnect(); await expectA(await s.waitUntilIdle(timeout: 3))
    }

    // MARK: .p12 legacy keychain path
}
