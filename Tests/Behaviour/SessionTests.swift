import Foundation
import VPNGateCore

struct TestError: Error, LocalizedError { var errorDescription: String? { "test error" } }

private final class Recorder {
    let events = Locked([HelperEvent]())
    func attach(_ s: VPNSession) { s.emit = { e in self.events.update { $0.append(e) } } }
    var states: [ConnectionState] { events.value.map(\.state) }
    var last: HelperEvent? { events.value.last }
    func waitFor(_ st: ConnectionState, server: String? = nil, timeout: Double = 5) async -> Bool {
        await eventually(timeout) { self.events.value.contains { $0.state == st && (server == nil || $0.server == server) } && self.last?.state == st }
    }
}

func registerSessionTests() {
    test("session/connects-through-all-states-and-configures-network") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: 995, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected), "never connected; states \(r.states)")
        let order = r.states.reduce(into: [ConnectionState]()) { if $1 != $0.last { $0.append($1) } }
        expectEqual(order, [.connecting, .authenticating, .dhcp, .connected])
        expectEqual(r.last?.virtualIP, "10.233.145.182"); expectEqual(r.last?.server, "1.2.3.4")
        expectEqual(h.tuns.value.count, 1); expectEqual(h.nets.value.count, 1)
        expectEqual(h.nets.value[0].applied.first?.host, "1.2.3.4")
        expectEqual(h.nets.value[0].applied.first?.iface, "utunF0")
        expect(h.tuns.value[0].reading, "tun must be reading once configured")
        expectEqual(h.transports.value[0].port, 995)
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3), "run task did not finish")
        expectEqual(s.snapshot.state, .disconnected); expectEqual(s.snapshot.server, nil)
        expectEqual(h.nets.value[0].tornDown, 1); expect(h.tuns.value[0].closed)
        expect(h.transports.value[0].closeCalls >= 1)
    }
    test("session/uses-proxy-host-for-the-bypass-route") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        var p = ProxySettings(); p.kind = .http; p.host = "10.9.9.9"; p.port = 3128
        s.connect(host: "1.2.3.4", port: nil, proxy: p, autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        expectEqual(h.nets.value[0].applied.first?.host, "10.9.9.9")
        s.disconnect()
    }
    test("session/disconnect-is-idempotent-and-safe-when-idle") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        s.disconnect(); s.disconnect()
        expectEqual(s.snapshot.state, .disconnected)
        await expectA(await s.waitUntilIdle(timeout: 1))
    }
    test("session/port-order-listed-port-first-then-defaults") {
        let h = SessionHarness(); h.connectErrorFor = { _, _ in TestError() }
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        s.connect(host: "1.2.3.4", port: 1889, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await s.waitUntilIdle(timeout: 5))
        expectEqual(h.transports.value.map { Int($0.port) }, [1889, 443, 992, 5555, 1194])
        let h2 = SessionHarness(); h2.connectErrorFor = { _, _ in TestError() }
        let s2 = VPNSession(deps: h2.deps(), timing: h2.fastTiming)
        s2.connect(host: "1.2.3.4", port: 443, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await s2.waitUntilIdle(timeout: 5))
        expectEqual(h2.transports.value.map { Int($0.port) }, [443, 992, 5555, 1194], "no duplicate of the listed port")
    }
    test("session/out-of-range-ports-do-not-trap") {                      // B4
        for bad in [70000, -5, 0, 65536] {
            let h = SessionHarness(); h.connectErrorFor = { _, _ in TestError() }
            let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
            s.connect(host: "1.2.3.4", port: bad, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
            await expectA(await s.waitUntilIdle(timeout: 5), "port \(bad)")
            expectEqual(h.transports.value.map { Int($0.port) }, [443, 992, 5555, 1194], "port \(bad)")
        }
    }
    test("session/falls-back-to-next-port-when-first-fails") {
        let h = SessionHarness(); h.connectErrorFor = { _, p in p == 1889 ? TestError() : nil }
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: 1889, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        expectEqual(h.transports.value.map { Int($0.port) }, [1889, 443])
        expectEqual(h.transports.value[0].closeCalls, 1, "failed transport is closed")
        s.disconnect()
    }
    test("session/failure-reports-error-and-releases-resources") {
        let h = SessionHarness(); h.tunError = TestError()
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await s.waitUntilIdle(timeout: 5))
        expectEqual(r.last?.state, .disconnected); expectEqual(r.last?.error, "test error")
        expect(h.transports.value[0].closeCalls >= 1, "transport must be closed when the tun cannot be created")
    }
    test("session/dhcp-failure-tears-everything-down") {
        let h = SessionHarness(); h.network.silent = true
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await s.waitUntilIdle(timeout: 5))
        expect(r.last?.error?.contains("DHCP") == true, "error \(r.last?.error ?? "nil")")
        expect(h.tuns.value.allSatisfy { $0.closed }); expectEqual(h.nets.value.count, 0, "no routes before a lease")
    }
    test("session/link-drop-reconnects-with-a-fresh-tunnel") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: true, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        h.transports.value[0].drop()
        await expectA(await eventually(5) { h.transports.value.count == 2 && r.last?.state == .connected }, "states \(r.states)")
        expect(r.states.contains(.reconnecting))
        expectEqual(h.tuns.value.count, 2); expect(h.tuns.value[0].closed)
        expectEqual(h.nets.value[0].tornDown, 1, "old routes removed")
        expectEqual(h.nets.value[1].tornDown, 0)
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3))
    }
    test("session/link-drop-without-auto-reconnect-stays-down") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        h.transports.value[0].drop()
        await expectA(await eventually(3) { r.last?.state == .disconnected })
        expectEqual(r.last?.error, "Connection lost")
        await expectA(await s.waitUntilIdle(timeout: 3))
        expectEqual(h.transports.value.count, 1); expectEqual(h.nets.value[0].tornDown, 1)
    }
    test("session/gives-up-after-max-attempts") {
        let h = SessionHarness(); h.connectErrorFor = { _, _ in TestError() }
        var t = h.fastTiming; t.maxAttempts = 2
        let s = VPNSession(deps: h.deps(), timing: t); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: true, blockIPv6: true)
        await expectA(await s.waitUntilIdle(timeout: 5), "states \(r.states)")
        expectEqual(r.last?.error, "Gave up reconnecting")
        expectEqual(h.transports.value.count, 4 * 3, "3 attempts × 4 default ports")
    }
    test("session/user-disconnect-stops-reconnect-loop") {
        let h = SessionHarness(); h.connectErrorFor = { _, _ in TestError() }
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: true, blockIPv6: true)
        try await Task.sleep(nanoseconds: 100_000_000)
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3))
        let n = h.transports.value.count
        try await Task.sleep(nanoseconds: 300_000_000)
        expectEqual(h.transports.value.count, n, "no attempts after disconnect")
    }
    test("session/connect-disconnect-cycles-do-not-leak-threads-or-tasks", timeout: 60) {   // B1
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        let before = threadCount()
        for i in 0..<40 {
            s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
            await expectA(await eventually(5) { r.last?.state == .connected }, "cycle \(i)")
            s.disconnect()
        }
        await expectA(await s.waitUntilIdle(timeout: 5), "run tasks never finished")
        let after = threadCount()
        expect(after - before <= 8, "threads grew from \(before) to \(after)")
        expectEqual(h.nets.value.count, h.nets.value.filter { $0.tornDown == 1 }.count, "every applied config torn down once")
        expect(h.tuns.value.allSatisfy { $0.closed })
    }
    test("session/reconnect-to-another-server-replaces-the-stale-attempt") {      // B2
        let h = SessionHarness()
        let gate = Gate(); h.gateFor = { $0 == "1.1.1.1" ? gate : nil }
        let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.1.1.1", port: nil, proxy: ProxySettings(), autoReconnect: true, blockIPv6: true)
        await expectA(await eventually(3) { h.transports.value.count == 1 })
        s.connect(host: "2.2.2.2", port: nil, proxy: ProxySettings(), autoReconnect: true, blockIPv6: true)
        await expectA(await r.waitFor(.connected, server: "2.2.2.2"), "states \(r.states)")
        gate.release()                                               // the stale handshake now completes
        try await Task.sleep(nanoseconds: 400_000_000)
        expectEqual(h.tuns.value.count, 1, "stale attempt must not create a tun")
        expectEqual(h.nets.value.count, 1, "stale attempt must not touch routes")
        expectEqual(h.nets.value[0].applied.first?.host, "2.2.2.2")
        expect(h.transports.value[0].closeCalls >= 1, "stale transport closed")
        expectEqual(s.snapshot.server, "2.2.2.2"); expectEqual(s.snapshot.state, .connected)
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3))
    }
    test("session/block-ipv6-flag-reaches-the-network-config") {
        for flag in [true, false] {
            let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
            s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: flag)
            await expectA(await r.waitFor(.connected))
            expectEqual(h.nets.value[0].ipv6Flags, [flag])
            s.disconnect()
        }
    }
    test("session/idle-snapshot-already-carries-the-helper-version") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming)
        expectEqual(s.snapshot.helperVersion, helperVersion)
    }
    test("session/events-carry-the-helper-version") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        expectEqual(r.last?.helperVersion, helperVersion)
        s.disconnect()
    }
    test("session/lost-dhcp-lease-triggers-a-reconnect", timeout: 10) {
        let h = SessionHarness(); h.network.leaseSeconds = 1
        var t = h.fastTiming; t.minRenewSeconds = 0.05; t.bridge.dhcpTimeout = 0.2
        let s = VPNSession(deps: h.deps(), timing: t); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: true, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        h.network.silent = true                                   // the server stops answering renewals
        await expectA(await eventually(6) { h.transports.value.count >= 2 }, "no reconnect after the lease was lost; states \(r.states)")
        expectEqual(h.nets.value[0].tornDown, 1, "routes of the dead lease removed")
        s.disconnect()
        await expectA(await s.waitUntilIdle(timeout: 3))
    }
    test("session/counters-are-published-while-connected", timeout: 8) {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        await expectA(await eventually(4) { (r.last?.bytesOut ?? 0) > 0 }, "bytesOut should include the DHCP/ARP traffic")
        s.disconnect()
    }
    test("session/traffic-flows-both-ways-through-the-bridge") {
        let h = SessionHarness(); let s = VPNSession(deps: h.deps(), timing: h.fastTiming); let r = Recorder(); r.attach(s)
        s.connect(host: "1.2.3.4", port: nil, proxy: ProxySettings(), autoReconnect: false, blockIPv6: true)
        await expectA(await r.waitFor(.connected))
        let tun = h.tuns.value[0], t = h.transports.value[0]
        tun.inject(hostPacket(to: 0x08080808))                         // host → internet (gateway resolved via fake ARP)
        await expectA(await eventually { h.network.ipv4Packets.count == 1 }, "packet not forwarded to the hub")
        // hub → host: find our MAC from what we sent
        let ours = Array(t.sent.last![6..<12])
        t.onFrame?(ipv4Frame(dstMAC: ours, src: 0x08080808, dst: 0x0AE991B6))
        await expectA(await eventually { tun.written.count == 1 }, "packet not delivered to the tun")
        s.disconnect()
    }
}
