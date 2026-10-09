import Foundation
import Darwin
import VPNGateCore

/// Raw client socket for protocol-level tests.
final class RawClient {
    let fd: Int32
    init?(path: String) {
        fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { $0.copyBytes(from: Array(path.utf8) + [0]) }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if rc != 0 { Darwin.close(fd); return nil }
        var one: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, 4)   // the test client must survive a closed peer
    }
    func write(_ s: String) { let d = Array(s.utf8); _ = d.withUnsafeBytes { Darwin.write(fd, $0.baseAddress, d.count) } }
    /// Returns bytes read, "" on EOF, nil on timeout.
    func read(timeout: Double = 1) -> String? {
        var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
        guard poll(&p, 1, Int32(timeout * 1000)) > 0 else { return nil }
        var buf = [UInt8](repeating: 0, count: 65536)
        let n = Darwin.read(fd, &buf, buf.count)
        return n <= 0 ? "" : String(decoding: buf[0..<n], as: UTF8.self)
    }
    func close() { Darwin.close(fd) }
}

private func startServer(uid: uid_t? = getuid(), console: @escaping () -> uid_t? = { nil }, name: String = "s")
    -> (IPCServer, FakeSession, String) {
    let path = tempPath("\(name)-\(UUID().uuidString.prefix(6)).sock")
    let fake = FakeSession()
    let srv = IPCServer(path: path, allowedUID: uid, consoleUID: console, session: fake)
    try! srv.start()
    return (srv, fake, path)
}

func registerIPCTests() {
    test("ipc/sends-snapshot-on-connect") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        var e = HelperEvent(state: .connected); e.server = "1.2.3.4"; e.virtualIP = "10.0.0.2"; fake.snapshot = e
        let got = Locked([HelperEvent]())
        let c = HelperClient(path: path); c.onEvent = { ev in got.update { $0.append(ev) } }
        expect(c.connect())
        await expectA(await eventually { got.value.count >= 1 })
        expectEqual(got.value.first?.state, .connected); expectEqual(got.value.first?.virtualIP, "10.0.0.2")
    }
    test("ipc/connect-and-disconnect-requests-reach-the-session") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let c = HelperClient(path: path)
        var r = HelperRequest(cmd: "connect"); r.host = "1.2.3.4"; r.port = 443
        c.send(r)
        await expectA(await eventually { fake.connects.count == 1 })
        expectEqual(fake.connects[0].host, "1.2.3.4"); expectEqual(fake.connects[0].port, 443)
        c.send(HelperRequest(cmd: "disconnect"))
        await expectA(await eventually { fake.disconnects == 1 })
    }
    test("ipc/events-are-broadcast-to-every-client") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let a = Locked([HelperEvent]()), b = Locked([HelperEvent]())
        let ca = HelperClient(path: path); ca.onEvent = { e in a.update { $0.append(e) } }
        let cb = HelperClient(path: path); cb.onEvent = { e in b.update { $0.append(e) } }
        expect(ca.connect() && cb.connect())
        await expectA(await eventually { a.value.count >= 1 && b.value.count >= 1 })
        var ev = HelperEvent(state: .dhcp); ev.log = "hello"
        fake.emit?(ev)
        await expectA(await eventually { a.value.last?.log == "hello" && b.value.last?.log == "hello" })
    }
    test("ipc/tolerates-garbage-and-split-lines") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let c = RawClient(path: path)!
        _ = c.read()
        c.write("garbage\n\n{not json}\n")
        c.write(#"{"cmd":"disc"#); try await Task.sleep(nanoseconds: 50_000_000); c.write("onnect\"}\n")
        await expectA(await eventually { fake.disconnects == 1 }, "split JSON line was not reassembled")
        c.write(#"{"cmd":"status"}"# + "\n")
        expect((c.read() ?? "").contains("state"), "status request answered")
        c.close()
    }
    test("ipc/rejects-other-users") {
        let (srv, fake, path) = startServer(uid: getuid() + 1); defer { srv.stop() }
        let c = RawClient(path: path)!
        let r = c.read(timeout: 1.5)
        expectEqual(r, "", "connection from a non-allowed uid must be closed without data")
        c.write(#"{"cmd":"disconnect"}"# + "\n")
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(fake.disconnects, 0)
    }
    test("ipc/ipv6-and-reconnect-flags-are-forwarded-with-safe-defaults") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let c = RawClient(path: path)!; _ = c.read()
        c.write(#"{"cmd":"connect","host":"1.2.3.4"}"# + "\n")
        c.write(#"{"cmd":"connect","host":"1.2.3.4","blockIPv6":false}"# + "\n")
        await expectA(await eventually { fake.connects.count == 2 })
        expectEqual(fake.blockIPv6Flags, [true, false], "IPv6 must be blocked unless the app explicitly says otherwise")
        c.close()
    }
    test("ipc/console-user-is-accepted-without-a-configured-uid") {
        // the installer package cannot know the user's uid, so the helper trusts whoever is at the console
        let (srv, fake, path) = startServer(uid: nil, console: { getuid() }); defer { srv.stop() }
        let c = RawClient(path: path)!
        expect((c.read(timeout: 2) ?? "").contains("state"), "console user must get the snapshot")
        c.write(#"{"cmd":"disconnect"}"# + "\n")
        await expectA(await eventually { fake.disconnects == 1 })
        c.close()
    }
    test("ipc/non-console-users-are-rejected-in-console-mode") {
        let (srv, fake, path) = startServer(uid: nil, console: { getuid() + 1 }); defer { srv.stop() }
        let c = RawClient(path: path)!
        expectEqual(c.read(timeout: 1.5), "")
        c.write(#"{"cmd":"disconnect"}"# + "\n")
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(fake.disconnects, 0)
        // nobody logged in (loginwindow): console owner unknown → only root may talk to the helper
        let (srv2, _, path2) = startServer(uid: nil, console: { nil }); defer { srv2.stop() }
        expectEqual(RawClient(path: path2)!.read(timeout: 1.5), "")
    }
    test("console-uid/lookup-matches-the-console-device") {
        var st = stat(); stat("/dev/console", &st)
        expectEqual(currentConsoleUID(), st.st_uid == 0 ? nil : st.st_uid)
    }
    test("ipc/console-uid-is-resolved-per-connection") {
        let who = Locked<uid_t?>(getuid() + 1)
        let (srv, _, path) = startServer(uid: nil, console: { who.value }); defer { srv.stop() }
        expectEqual(RawClient(path: path)!.read(timeout: 1.5), "", "before the user logs in")
        who.update { $0 = getuid() }                                   // fast user switching / login
        expect((RawClient(path: path)!.read(timeout: 2) ?? "").contains("state"))
    }
    test("ipc/socket-is-private-to-the-user") {
        let (srv, _, path) = startServer(); defer { srv.stop() }
        var st = stat(); stat(path, &st)
        expectEqual(st.st_mode & 0o777, 0o600)
    }
    test("ipc/invalid-connect-requests-are-rejected-before-reaching-the-session") {   // B14
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let c = RawClient(path: path)!; _ = c.read()
        for host in ["-interface", "1.2.3.4; reboot", "", "a b"] {
            let h = String(data: try JSONEncoder().encode(host), encoding: .utf8)!
            c.write(#"{"cmd":"connect","host":\#(h),"port":443}"# + "\n")
        }
        for port in [0, 70000, -1] { c.write(#"{"cmd":"connect","host":"1.2.3.4","port":\#(port)}"# + "\n") }
        c.write(#"{"cmd":"connect","host":"1.2.3.4","proxy":{"kind":"http","host":"-x","port":80}}"# + "\n")
        c.write(#"{"cmd":"connect","host":"1.2.3.4","proxy":{"kind":"http","host":"p","port":99999}}"# + "\n")
        try await Task.sleep(nanoseconds: 300_000_000)
        expectEqual(fake.connects.count, 0, "session received: \(fake.connects)")
        // and a valid one still works
        c.write(#"{"cmd":"connect","host":"vpn1.example.net","port":443}"# + "\n")
        await expectA(await eventually { fake.connects.count == 1 })
        c.close()
    }
    test("ipc/rejected-request-reports-an-error-event") {                             // B14
        let (srv, _, path) = startServer(); defer { srv.stop() }
        let c = RawClient(path: path)!; _ = c.read()
        c.write(#"{"cmd":"connect","host":"-interface"}"# + "\n")
        let r = c.read(timeout: 1) ?? ""
        expect(r.contains("error"), "client not told why: \(r)")
        c.close()
    }
    test("ipc/slow-client-cannot-stall-the-session", timeout: 15) {                    // B13
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let slow = RawClient(path: path)!                                   // connects, never reads
        var rb: Int32 = 1024; setsockopt(slow.fd, SOL_SOCKET, SO_RCVBUF, &rb, 4)
        let fast = Locked(0)
        let good = HelperClient(path: path); good.onEvent = { _ in fast.update { $0 += 1 } }
        expect(good.connect())
        await eventually { fast.value >= 1 }
        let done = Locked(false)
        DispatchQueue.global().async {
            var ev = HelperEvent(state: .connected); ev.log = String(repeating: "x", count: 60_000)
            for _ in 0..<300 { fake.emit?(ev) }
            done.update { $0 = true }
        }
        await expectA(await eventually(3) { done.value }, "emit() blocked on a client that is not reading")
        _ = slow
    }
    test("ipc/client-gone-mid-broadcast-is-survivable") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        let c = RawClient(path: path)!; _ = c.read(); c.close()
        for _ in 0..<50 { fake.emit?(HelperEvent(state: .connected)) }
        let c2 = RawClient(path: path)!
        expect(c2.read() != nil, "server still serves new clients")
        c2.close()
    }
    test("helperclient/reconnects-after-the-server-restarts") {
        let path = tempPath("restart-\(UUID().uuidString.prefix(6)).sock")
        let fake1 = FakeSession(); let srv1 = IPCServer(path: path, allowedUID: getuid(), session: fake1); try srv1.start()
        let got = Locked(0); let dropped = Locked(0)
        let c = HelperClient(path: path); c.onEvent = { _ in got.update { $0 += 1 } }; c.onDisconnect = { dropped.update { $0 += 1 } }
        expect(c.connect()); await eventually { got.value >= 1 }
        srv1.stop()
        await expectA(await eventually { dropped.value == 1 && !c.isConnected }, "client did not notice the server going away")
        let fake2 = FakeSession(); let srv2 = IPCServer(path: path, allowedUID: getuid(), session: fake2); try srv2.start()
        defer { srv2.stop() }
        var r = HelperRequest(cmd: "connect"); r.host = "1.2.3.4"
        c.send(r)                                                               // send() reconnects on demand
        await expectA(await eventually { fake2.connects.count == 1 }, "request after restart was lost")
    }
    test("helperclient/send-to-a-dead-server-does-not-kill-the-process") {              // SIGPIPE
        let path = tempPath("dead-\(UUID().uuidString.prefix(6)).sock")
        let srv = IPCServer(path: path, allowedUID: getuid(), session: FakeSession()); try srv.start()
        let c = HelperClient(path: path)
        expect(c.connect())
        srv.stop()
        for _ in 0..<5 { c.send(HelperRequest(cmd: "status")) }          // would raise SIGPIPE on a closed socket
    }
}

/// Starts the real `vpngate-helper --daemon` binary (needs `scripts/build.sh helper`, which test.sh runs).
func registerDaemonTests() {
    test("daemon/real-binary-serves-ipc-clients", timeout: 30) {
        let bin = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("build/bin/vpngate-helper").path
        guard FileManager.default.isExecutableFile(atPath: bin) else { fail("helper binary missing: \(bin)"); return }
        let path = tempPath("daemon-\(UUID().uuidString.prefix(6)).sock")
        let p = Process(); p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--daemon", "--socket", path]      // console-user mode, as installed by the package
        let out = Pipe(); p.standardOutput = out; p.standardError = out
        try p.run(); defer { p.terminate(); p.waitUntilExit() }
        await expectA(await eventually(5) { FileManager.default.fileExists(atPath: path) }, "daemon never created its socket")
        try await Task.sleep(nanoseconds: 500_000_000)             // long enough for a released server to have stopped
        let c = RawClient(path: path)
        expect(c != nil, "cannot connect")
        let first = c?.read(timeout: 3)
        expect(first?.contains("disconnected") == true, "no state snapshot from the daemon: \(String(describing: first))")
        c?.write(#"{"cmd":"status"}"# + "\n")
        expect((c?.read(timeout: 3) ?? "").contains("helperVersion"), "status request unanswered")
        // a rejected request must be answered too (this is what the app saw as 'stuck on Connecting')
        c?.write(#"{"cmd":"connect","host":"-bad"}"# + "\n")
        expect((c?.read(timeout: 3) ?? "").contains("Rejected"), "invalid request unanswered")
        c?.close()
    }
}
