import Foundation
import Network
import Darwin
import VPNGateCore

/// Listens on 127.0.0.1:<ephemeral>; accepts connections and never answers.
private final class SilentListener {
    let fd: Int32; let port: UInt16
    init() {
        let s = socket(AF_INET, SOCK_STREAM, 0)
        var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1")
        _ = withUnsafePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        listen(s, 8)
        var len = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
        fd = s
        port = UInt16(bigEndian: a.sin_port)
    }
    func close() { Darwin.close(fd) }
}

private func isCancelled(_ s: NWConnection.State) -> Bool { if case .cancelled = s { return true }; return false }

func registerSystemTests() {
    // MARK: packet reader (utun stand-in)
    test("fdreader/delivers-ipv4-and-skips-other-families") {
        var fds: [Int32] = [0, 0]; socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        let r = FDPacketReader(fd: fds[0]); let got = Locked([[UInt8]]())
        r.onPacket = { p in got.update { $0.append(p) } }; r.startReading()
        func put(_ af: UInt8, _ body: [UInt8]) { let d = [0, 0, 0, af] + body; _ = d.withUnsafeBytes { write(fds[1], $0.baseAddress, d.count) } }
        put(30, [1, 2, 3, 4])                       // AF_INET6 → ignored
        put(2, [9, 8, 7, 6])
        await expectA(await eventually { got.value.count == 1 })
        expectEqual(got.value, [[9, 8, 7, 6]])
        r.write(ipv4: [5, 5, 5, 5])
        var buf = [UInt8](repeating: 0, count: 64); let n = read(fds[1], &buf, 64)
        expectEqual(Array(buf[0..<n]), [0, 0, 0, 2, 5, 5, 5, 5])
        r.close(); Darwin.close(fds[1])
    }
    test("fdreader/ipv6-is-forwarded-only-when-enabled-and-written-as-af-inet6") {        // review 15
        var fds: [Int32] = [0, 0]; socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        let r = FDPacketReader(fd: fds[0], forwardIPv6: true); let got = Locked([[UInt8]]())
        r.onPacket = { p in got.update { $0.append(p) } }; r.startReading()
        func put(_ af: UInt8, _ body: [UInt8]) { let d = [0, 0, 0, af] + body; _ = d.withUnsafeBytes { write(fds[1], $0.baseAddress, d.count) } }
        put(30, [0x60, 1, 2, 3]); put(18, [7, 7, 7, 7])
        await expectA(await eventually { got.value.count == 1 })
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(got.value, [[0x60, 1, 2, 3]], "AF_INET6 forwarded, other families still skipped")
        r.write(ipv6: [0x60, 9, 9, 9])
        var buf = [UInt8](repeating: 0, count: 64); let n = read(fds[1], &buf, 64)
        expectEqual(Array(buf[0..<n]), [0, 0, 0, 30, 0x60, 9, 9, 9], "utun header for IPv6 is AF_INET6 = 30 on macOS")
        r.close(); Darwin.close(fds[1])
    }
    test("fdreader/closed-reader-never-reads-from-a-recycled-descriptor") {          // B8
        var fds: [Int32] = [0, 0]; socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds)
        let old = fds[0]
        let r = FDPacketReader(fd: old); let got = Locked(0)
        r.onPacket = { _ in got.update { $0 += 1 } }; r.startReading()
        try await Task.sleep(nanoseconds: 100_000_000)           // reader thread is parked in poll()
        r.close()
        // The kernel hands the same descriptor number to the next tunnel.
        var next: [Int32] = [0, 0]; socketpair(AF_UNIX, SOCK_DGRAM, 0, &next)
        dup2(next[0], old)
        let d: [UInt8] = [0, 0, 0, 2, 1, 2, 3, 4]
        _ = d.withUnsafeBytes { write(next[1], $0.baseAddress, d.count) }
        try await Task.sleep(nanoseconds: 500_000_000)
        expectEqual(got.value, 0, "stale reader consumed a packet that belongs to the next tunnel")
        Darwin.close(old); Darwin.close(next[0]); Darwin.close(next[1]); Darwin.close(fds[1])
    }

    // MARK: TLS stream
    test("tlsstream/refused-connection-is-cancelled") {                                  // B9
        let l = SilentListener(); let port = l.port; l.close()           // nothing listens on this port any more
        let s = TLSStream(host: "127.0.0.1", port: port, proxy: ProxySettings())
        do { try await s.start(timeout: 3); fail("connected to a closed port") } catch {}
        await expectA(await eventually(2) { isCancelled(s.connState) }, "connection left alive after failure: \(s.connState)")
    }
    test("tlsstream/timeout-cancels-the-connection") {                                   // B9
        let l = SilentListener(); defer { l.close() }
        let s = TLSStream(host: "127.0.0.1", port: l.port, proxy: ProxySettings())
        let start = Date()
        do { try await s.start(timeout: 0.6); fail("handshake with a silent peer succeeded") }
        catch { expect(error is StreamError, "error \(error)") }
        expect(Date().timeIntervalSince(start) < 3)
        await expectA(await eventually(2) { isCancelled(s.connState) }, "connection still retrying in the background: \(s.connState)")
    }

    // MARK: CLI parsing
    test("probe-args/parse") {                                                                // B19
        expect(parseProbeArgs(["x"]) == nil)
        expect(parseProbeArgs(["x", "--probe"]) == nil)
        expectEqual(parseProbeArgs(["x", "--probe", "1.2.3.4"])?.0, "1.2.3.4")
        expectEqual(parseProbeArgs(["x", "--probe", "1.2.3.4"])?.1, 443)
        expectEqual(parseProbeArgs(["x", "--probe", "h", "--port", "992"])?.1, 992)
    }
    test("probe-args/dangling-or-invalid-port") {                                             // B19
        expectEqual(parseProbeArgs(["x", "--probe", "h", "--port"])?.1, 443, "missing value must not crash")
        expect(parseProbeArgs(["x", "--probe", "h", "--port", "abc"]) == nil || parseProbeArgs(["x", "--probe", "h", "--port", "abc"])?.1 == 443)
        expect(parseProbeArgs(["x", "--probe", "h", "--port", "70000"]) == nil, "out-of-range port must be rejected")
    }

    // MARK: shutdown
    test("shutdown/signal-runs-cleanup-once-off-the-signal-path") {                        // B5
        let calls = Locked((cleanup: 0, finish: 0, onMain: false))
        let c = ShutdownCoordinator(signals: [SIGUSR2], cleanup: {
            calls.update { $0.cleanup += 1; $0.onMain = Thread.isMainThread }
            _ = SystemRunner().run("/bin/echo", ["cleanup may spawn processes and take locks"])
        }, finish: { calls.update { $0.finish += 1 } })
        raise(SIGUSR2); raise(SIGUSR2)
        await expectA(await eventually { calls.value.finish >= 1 })
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(calls.value.cleanup, 1, "cleanup count"); expectEqual(calls.value.finish, 1, "finish count")
        _ = c
    }

    // MARK: command runner
    test("runner/system-runner-captures-output-and-status") {
        let r = SystemRunner().run("/bin/echo", ["hi", "there"])
        expectEqual(r.status, 0); expectEqual(r.out, "hi there\n")
        expectEqual(SystemRunner().run("/bin/sh", ["-c", "exit 3"]).status, 3)
        expectEqual(SystemRunner().run("/nonexistent/binary", []).status, -1)
    }
}
