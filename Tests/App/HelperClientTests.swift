import Foundation

private func startServer(_ session: FakeHelperSession = FakeHelperSession()) -> (FakeHelperServer, FakeHelperSession, String) {
    let path = tempPath("hc-\(UUID().uuidString.prefix(6)).sock")
    let srv = FakeHelperServer(path: path, session: session)
    try! srv.start()
    return (srv, session, path)
}

private func result(_ servers: [VPNServer] = [parsedServer()], next: Double? = 1800) -> ServerListResult {
    ServerListResult(servers: servers, source: .relaySync, timestampMs: 1_700_000_000_000, isFresh: true, outcome: .synced, nextPollSeconds: next)
}

func registerHelperClientTests() {
    test("helperclient/reconnects-after-the-server-restarts") {
        let path = tempPath("restart-\(UUID().uuidString.prefix(6)).sock")
        let fake1 = FakeHelperSession(); let srv1 = FakeHelperServer(path: path, session: fake1); try srv1.start()
        let got = Locked(0); let dropped = Locked(0)
        let c = HelperClient(path: path); c.onEvent = { _ in got.update { $0 += 1 } }; c.onDisconnect = { dropped.update { $0 += 1 } }
        expect(c.connect()); await eventually { got.value >= 1 }
        srv1.stop()
        await expectA(await eventually { dropped.value == 1 && !c.isConnected }, "client did not notice the server going away")
        let fake2 = FakeHelperSession(); let srv2 = FakeHelperServer(path: path, session: fake2); try srv2.start()
        defer { srv2.stop() }
        var r = HelperRequest(cmd: "connect"); r.host = "1.2.3.4"
        c.send(r)  // send() reconnects on demand
        await expectA(await eventually { fake2.connects.count == 1 }, "request after restart was lost")
    }
    test("helperclient/send-to-a-dead-server-does-not-kill-the-process") {  // SIGPIPE
        let path = tempPath("dead-\(UUID().uuidString.prefix(6)).sock")
        let srv = FakeHelperServer(path: path, session: FakeHelperSession()); try srv.start()
        let c = HelperClient(path: path)
        expect(c.connect())
        srv.stop()
        for _ in 0..<5 { c.send(HelperRequest(cmd: "status")) }  // would raise SIGPIPE on a closed socket
    }
    test("helperclient/snapshots-carry-the-ipc-version") {
        let (srv, _, path) = startServer(); defer { srv.stop() }
        let got = Locked([HelperEvent]())
        let c = HelperClient(path: path); c.onEvent = { e in got.update { $0.append(e) } }
        expect(c.connect())
        await expectA(await eventually { !got.value.isEmpty })
        expectEqual(got.value.first?.ipcVersion, ipcVersion)
    }
    test("helperclient/list-and-refresh-return-typed-results-and-send-the-proxy-and-mirror") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        fake.listResult = result(next: nil); fake.refreshResult = result([parsedServer("a"), parsedServer("b", ip: "5.6.7.8")])
        let c = HelperClient(path: path)
        let cached = try await c.listServers()
        expectEqual(cached.servers.count, 1); expectEqual(cached.nextPollSeconds, nil)
        var px = ProxySettings(); px.kind = .http; px.host = "p"; px.port = 3128
        let fresh = try await c.refreshServers(proxy: px, mirror: "https://m.example/list")
        expectEqual(fresh.servers.map(\.hostName), ["a", "b"]); expectEqual(fresh.nextPollSeconds, 1800)
        expectEqual(fake.refreshes.first?.proxy?.host, "p"); expectEqual(fake.refreshes.first?.mirror, "https://m.example/list")
        _ = try await c.refreshServers(proxy: ProxySettings(), mirror: "")
        expectEqual(fake.refreshes.last?.mirror, nil, "an empty mirror is not sent")
    }
    test("helperclient/an-ok-false-reply-throws-its-reason") {
        let (srv, _, path) = startServer(); defer { srv.stop() }
        let c = HelperClient(path: path)
        do { _ = try await c.listServers(); fail("expected a failure") } catch { expectEqual(error as? HelperRequestError, .failed("No server list")) }
    }
    test("helperclient/concurrent-requests-are-matched-by-id-even-when-answered-out-of-order") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        fake.refreshResult = result([parsedServer("slow")]); fake.refreshDelay = 0.3
        fake.listResult = result([parsedServer("fast")], next: nil)
        let c = HelperClient(path: path)
        async let slow = c.refreshServers(proxy: ProxySettings(), mirror: nil)
        try await Task.sleep(nanoseconds: 50_000_000)
        async let fast = c.listServers()
        let (f, s) = try await (fast, slow)
        expectEqual(f.servers.first?.hostName, "fast"); expectEqual(s.servers.first?.hostName, "slow")
    }
    test("helperclient/probe-sends-targets-and-returns-results-in-order") {
        let (srv, fake, path) = startServer(); defer { srv.stop() }
        fake.probeReply = { ts in
            ts.map {
                ProbeEntry(host: $0.host, ok: $0.host == "1.1.1.1", port: 443, connectMs: 5, helloMs: 9, build: nil, error: $0.host == "1.1.1.1" ? nil : "down")
            }
        }
        let c = HelperClient(path: path)
        let out = try await c.probe([ProbeTarget(host: "1.1.1.1", ports: [443]), ProbeTarget(host: "2.2.2.2")], proxy: ProxySettings())
        expectEqual(out.map(\.host), ["1.1.1.1", "2.2.2.2"]); expectEqual(out.map(\.ok), [true, false])
        expectEqual(fake.probes.first?.first?.ports, [443]); expectEqual(fake.probes.first?[1].ports, nil)
    }
    test("helperclient/requests-fail-when-the-socket-drops-or-never-existed") {
        let c = HelperClient(path: tempPath("nobody-\(UUID().uuidString.prefix(6)).sock"))
        do { _ = try await c.listServers(); fail("expected a failure") } catch { expectEqual(error as? HelperRequestError, .disconnected) }
        let (srv, fake, path) = startServer()
        fake.refreshResult = result(); fake.refreshDelay = 2
        let c2 = HelperClient(path: path)
        let pending = Task { try await c2.refreshServers(proxy: ProxySettings(), mirror: nil) }
        try await Task.sleep(nanoseconds: 200_000_000)
        srv.stop()
        do { _ = try await pending.value; fail("expected a failure") } catch { expectEqual(error as? HelperRequestError, .disconnected) }
    }
}
