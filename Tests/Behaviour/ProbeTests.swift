import Foundation
import VPNGateCore

private struct Refused: Error {}

/// A stream that cannot connect, to stand in for a closed or filtered port.
private final class DeadStream: ByteStream {
    var buffer = ByteBuffer()
    func start() async throws { throw Refused() }
    func send(_ data: Data) async throws { throw Refused() }
    func readChunk() async throws -> Data { throw Refused() }
    func cancel() {}
}

func registerProbeTests() {
    test("probe/real-softether-hello-counts-as-reachable") {
        let server = FakeSoftEtherServer()
        let r = await ServerProbe.run(host: "10.0.0.1", ports: [443], factory: server.factory)
        guard case .ok(let port, let connectMs, let helloMs, let build) = r else { return expect(false, "\(r)") }
        expectEqual(port, 443); expectEqual(build, 9729)
        expect(connectMs >= 1 && helloMs >= connectMs, "times \(connectMs) \(helloMs)")
        expectEqual(server.requests.first?.path, "/vpnsvc/connect.cgi")
        expect(server.logins.isEmpty, "the probe must never log in")
    }

    test("probe/plain-tcp-or-https-server-is-not-reachable-as-vpn") {
        let notVPN = FakeSoftEtherServer(); notVPN.helloStatus = 404
        let a = await ServerProbe.run(host: "h", ports: [443], factory: notVPN.factory)
        expectEqual(a, .failed("Not a VPN server (HTTP 404)"))
        let noRandom = FakeSoftEtherServer(); noRandom.omitRandom = true
        let b = await ServerProbe.run(host: "h", ports: [443], factory: noRandom.factory)
        expectEqual(b, .failed("Not a SoftEther server"))
    }

    test("probe/connection-failure-is-reported") {
        let r = await ServerProbe.run(host: "h", ports: [443]) { _, _, _ in DeadStream() }
        expect(!r.isOK, "\(r)")
    }

    test("probe/falls-back-to-the-next-port") {
        let server = FakeSoftEtherServer()
        let tried = Locked([UInt16]())
        let r = await ServerProbe.run(host: "h", ports: [443, 992]) { h, p, px in
            tried.update { $0.append(p) }
            return p == 443 ? DeadStream() : server.factory(h, p, px)
        }
        guard case .ok(let port, _, _, _) = r else { return expect(false, "\(r)") }
        expectEqual(port, 992); expectEqual(tried.value, [443, 992])
    }

    test("probe/all-ports-failing-names-the-last-port") {
        let r = await ServerProbe.run(host: "h", ports: [443, 992]) { _, _, _ in DeadStream() }
        guard case .failed(let why) = r else { return expect(false, "\(r)") }
        expect(why.contains("992"), why)
    }

    test("probe/times-out-on-a-silent-server") {
        // Accepts the connection but never answers (no reader on the other side).
        final class Silent: ByteStream {
            var buffer = ByteBuffer()
            private let q = AsyncQueue()
            func start() async throws {}
            func send(_ data: Data) async throws {}
            func readChunk() async throws -> Data { try await q.next() }
            func cancel() { q.finish() }
        }
        let t0 = Date()
        let r = await ServerProbe.run(host: "h", ports: [443], timeout: 0.3) { _, _, _ in Silent() }
        expect(!r.isOK && Date().timeIntervalSince(t0) < 3, "\(r)")
    }

    test("probe/sort-rank-puts-fast-first-then-untested-then-failed") {
        let fast = ProbeOutcome.ok(port: 443, connectMs: 90, helloMs: 200, build: nil)
        let slow = ProbeOutcome.ok(port: 443, connectMs: 900, helloMs: 1500, build: nil)
        let order = [ProbeOutcome.failed("x"), nil, slow, .testing, .queued, fast].sorted { ProbeOutcome.sortRank($0) < ProbeOutcome.sortRank($1) }
        expectEqual(order.first, fast); expectEqual(order[1], slow); expectEqual(order.last, .failed("x"))
        expectEqual(VPNServer(hostName: "a", ip: "1.2.3.4").testRank, 0)
    }

    test("probe/port-choice-follows-the-windows-order-and-is-capped") {
        var s = VPNServer(hostName: "a", ip: "1.2.3.4", sslPorts: [5555, 22, 443, 992, 995])
        expectEqual(ServerProbe.ports(for: s), [443, 992, 995])
        s.sslPorts = []; s.listedPort = 1194
        expectEqual(ServerProbe.ports(for: s), [1194])
        s.listedPort = 0
        expectEqual(ServerProbe.ports(for: s), [443])
    }
}
