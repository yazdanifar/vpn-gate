import Foundation
import VPNGateCore

private func client(_ s: FakeSoftEtherServer, proxy: ProxySettings = ProxySettings()) -> SoftEtherClient {
    SoftEtherClient(host: "1.2.3.4", port: 443, proxy: proxy, makeStream: s.factory)
}

private func connectFails(_ s: FakeSoftEtherServer) async -> String? {
    do { _ = try await client(s).connect { _ in }; return nil } catch { return error.localizedDescription }
}

func registerHandshakeTests() {
    test("handshake/happy-path") {
        let s = FakeSoftEtherServer(); let c = client(s)
        let logs = Locked([String]())
        let w = try await c.connect { m in logs.update { $0.append(m) } }
        expectEqual(w.sessionName, "SID-VPN-TEST-1"); expectEqual(w.timeoutMs, 20000)
        let r = s.requests
        expectEqual(r.count, 2)
        expectEqual(r[0].path, "/vpnsvc/connect.cgi"); expectEqual(r[0].contentType, "image/jpeg")
        expectEqual(Array(r[0].body.prefix(6)), Array("GIF89a".utf8), "signature image prefix")
        expectEqual(r[1].path, "/vpnsvc/vpn.cgi"); expectEqual(r[1].contentType, "application/octet-stream")
        expectEqual(s.logins.count, 1)
        expectEqual(s.logins[0].str("hubname"), "VPNGATE"); expectEqual(s.logins[0].int("authtype"), 0)
        expect(logs.value.contains { $0.contains("SID-VPN-TEST-1") }, "logs: \(logs.value)")
        c.close(nil)
    }
    test("handshake/falls-back-to-plain-signature") {
        let s = FakeSoftEtherServer(); s.rejectWatermark = true
        let c = client(s)
        _ = try await c.connect { _ in }
        expectEqual(s.streamsCreated, 2, "a fresh connection is used for the retry")
        expectEqual(s.requests[1].body, Array("VPNCONNECT".utf8))
        expect(s.lastStream != nil && !s.lastStream!.isCancelled)
        c.close(nil)
    }
    test("handshake/login-error-is-reported") {
        let s = FakeSoftEtherServer(); s.loginError = 3
        let e = await connectFails(s)
        expect(e?.contains("error 3") == true, "got \(e ?? "success")")
    }
    test("handshake/missing-random-is-not-softether") {
        let s = FakeSoftEtherServer(); s.omitRandom = true
        let e = await connectFails(s)
        expect(e?.contains("not a SoftEther") == true, "got \(e ?? "success")")
    }
    test("handshake/cluster-redirect-is-unsupported") {
        let s = FakeSoftEtherServer(); s.redirect = true
        let e = await connectFails(s)
        expect(e?.lowercased().contains("redirect") == true, "got \(e ?? "success")")
    }
    test("handshake/http-error-fails") {
        let s = FakeSoftEtherServer(); s.helloStatus = 500
        let e = await connectFails(s)
        expect(e != nil, "should fail")
    }
    test("handshake/transport-failure-propagates") {
        struct Boom: Error, LocalizedError { var errorDescription: String? { "boom" } }
        let s = FakeSoftEtherServer(); s.failStart = Boom()
        let e = await connectFails(s)
        expectEqual(e, "boom")
    }
    test("handshake/frames-sent-with-the-welcome-are-not-lost") {
        let s = FakeSoftEtherServer(); s.trailingAfterWelcome = DataPhase.encode(frames: [[1, 2, 3]])
        let c = client(s); let got = Locked([[UInt8]]())
        c.onFrame = { f in got.update { $0.append(f) } }
        _ = try await c.connect { _ in }
        await eventually { got.value.count == 1 }
        expectEqual(got.value, [[1, 2, 3]])
        c.close(nil)
    }
    test("dataphase/client-reassembles-byte-by-byte-delivery") {
        let s = FakeSoftEtherServer(); s.chunkSize = 1
        let c = client(s); let got = Locked([[UInt8]]())
        c.onFrame = { f in got.update { $0.append(f) } }
        _ = try await c.connect { _ in }
        let frames = (0..<5).map { i in [UInt8](repeating: UInt8(i), count: 100 + i) }
        s.lastStream!.deliver(DataPhase.encode(frames: frames))
        await eventually(5) { got.value.count == 5 }
        expectEqual(got.value, frames)
        c.close(nil)
    }
    test("dataphase/server-keepalives-are-swallowed") {
        let s = FakeSoftEtherServer(); let c = client(s); let got = Locked([[UInt8]]())
        c.onFrame = { f in got.update { $0.append(f) } }
        _ = try await c.connect { _ in }
        s.lastStream!.deliver(DataPhase.encodeKeepAlive(junk: [1, 2, 3]) + DataPhase.encode(frames: [[7]]))
        await eventually { got.value.count == 1 }
        expectEqual(got.value, [[7]])
        c.close(nil)
    }
    test("dataphase/oversized-block-closes-with-error") {
        let s = FakeSoftEtherServer(); let c = client(s); let err = Locked<Error?>(nil); let n = Locked(0)
        c.onClose = { e in err.update { $0 = e }; n.update { $0 += 1 } }
        _ = try await c.connect { _ in }
        s.lastStream!.deliver([0,0,0,1, 0,0,0x20,0])
        await eventually { n.value == 1 }
        expectEqual(n.value, 1)
        expect(err.value is DataPhaseError, "got \(String(describing: err.value))")
    }
    test("dataphase/server-eof-closes-exactly-once") {
        let s = FakeSoftEtherServer(); let c = client(s); let n = Locked(0)
        c.onClose = { _ in n.update { $0 += 1 } }
        _ = try await c.connect { _ in }
        s.lastStream!.closeFromServer()
        await eventually { n.value >= 1 }
        c.close(nil); c.close(nil)
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(n.value, 1, "onClose count")
    }
    test("dataphase/outgoing-frames-arrive-in-order-and-counters-update") {
        let s = FakeSoftEtherServer(); let c = client(s)
        _ = try await c.connect { _ in }
        let frames = (0..<300).map { i in [UInt8(i & 0xff), UInt8(i >> 8), 0, 0] + [UInt8](repeating: 9, count: 50) }
        frames.forEach { c.sendFrame($0) }
        await eventually(5) { s.framesReceived.count == 300 }
        expectEqual(s.framesReceived, frames)
        expectEqual(c.bytesOut, UInt64(300 * 54))
        s.lastStream!.deliver(DataPhase.encode(frames: [[1, 2, 3, 4, 5]]))
        await eventually { c.bytesIn == 5 }
        expectEqual(c.bytesIn, 5)
        c.close(nil)
    }
    test("dataphase/oversized-outgoing-frame-is-dropped") {
        let s = FakeSoftEtherServer(); let c = client(s)
        _ = try await c.connect { _ in }
        c.sendFrame([UInt8](repeating: 1, count: 3201)); c.sendFrame([2])
        await eventually { s.framesReceived.count == 1 }
        expectEqual(s.framesReceived, [[2]])
        c.close(nil)
    }
    test("dataphase/client-sends-keepalives", timeout: 10) {
        let s = FakeSoftEtherServer(); s.welcomeTimeoutMs = 5000      // keep-alive every 1-2.5 s
        let c = client(s)
        _ = try await c.connect { _ in }
        let ok = await eventually(4) { s.keepAlivesReceived >= 1 }
        expect(ok, "no keep-alive within 4s")
        c.close(nil)
    }
    test("dataphase/close-cancels-stream-and-send-after-close-is-safe") {
        let s = FakeSoftEtherServer(); let c = client(s)
        _ = try await c.connect { _ in }
        c.close(nil)
        expect(s.lastStream!.isCancelled)
        c.sendFrame([1, 2, 3])
        try await Task.sleep(nanoseconds: 50_000_000)
    }
    test("handshake/proxy-settings-are-passed-to-the-stream-factory") {
        let seen = Locked<ProxySettings?>(nil)
        let s = FakeSoftEtherServer()
        var p = ProxySettings(); p.kind = .socks5; p.host = "px"; p.port = 1080
        let c = SoftEtherClient(host: "h", port: 443, proxy: p, makeStream: { h, po, pr in
            seen.update { $0 = pr }; return s.factory(h, po, pr) })
        _ = try await c.connect { _ in }
        expectEqual(seen.value, p)
        expectEqual(s.logins[0].str("ProxyHostname"), "px")
        c.close(nil)
    }
}
