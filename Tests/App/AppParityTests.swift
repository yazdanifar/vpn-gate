import Combine
import Foundation

// App-side parity: the reconnect policy of VPN Gate connections, telemetry host label, list text and account file
// tolerance. Everything runs against the fake helper (Tests/Support/FakeHelper.swift): no real network.

private func throwawayDefaults() -> UserDefaults {
    let name = "vpngate-parity-\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    d.set(true, forKey: "hasAgreedToDisclaimer")
    return d
}

private func host(_ i: Int, ports: [UInt16], udp: UInt16? = nil) -> VPNServer {
    VPNServer(hostName: "h\(i)", ip: "10.0.\(i / 200).\(i % 200 + 1)", fqdn: "h\(i).example", sslPorts: ports, udpPort: udp)
}

func registerAppParityTests() {
    test("account/the-invented-hide-key-is-ignored-on-load-and-never-written") {
        let id = UUID().uuidString
        let old = Data("{\"id\":\"\(id)\",\"name\":\"A\",\"host\":\"h\",\"hideFromVpnGateList\":true,\"hub\":\"X\"}".utf8)
        let acc = try JSONDecoder().decode(ClientAccount.self, from: old)
        expectEqual(acc.hub, "X")
        let out = String(decoding: try JSONEncoder().encode(acc), as: UTF8.self)
        expect(!out.contains("hideFromVpnGateList"), out)
    }

    // MARK: 8. list text and dat fields
    test("list/uptime-uses-minutes-up-to-1h-hours-up-to-24h-then-days") {
        expectEqual(ListFormat.uptime(ms: 0), "0 mins")
        expectEqual(ListFormat.uptime(ms: 59_999), "0 mins")
        expectEqual(ListFormat.uptime(ms: 3_599_999), "59 mins")
        expectEqual(ListFormat.uptime(ms: 3_600_000), "60 mins", "exactly 1 h is still minutes (cut-off < 3,600,001)")
        expectEqual(ListFormat.uptime(ms: 3_600_001), "1 hour")
        expectEqual(ListFormat.uptime(ms: 5_400_000), "1 hour")
        expectEqual(ListFormat.uptime(ms: 86_400_000), "24 hours", "exactly 24 h is still hours (cut-off < 86,400,001)")
        expectEqual(ListFormat.uptime(ms: 86_400_001), "1 day")
        expectEqual(ListFormat.uptime(ms: 542_874_958), "6 days")
    }
    test("list/pings-udp-and-status-line") {
        expectEqual(ListFormat.sessions(1), "1 session"); expectEqual(ListFormat.sessions(12), "12 sessions")
        expectEqual(ListFormat.logins(1234567), "1,234,567 logins")
        expectEqual(ListFormat.logging("No Log"), "No Logs"); expectEqual(ListFormat.logging("2 Weeks"), "2 Weeks")
        expectEqual(ListFormat.logging("Permanent"), "Permanent"); expectEqual(ListFormat.logging(""), "-")
        expectEqual(ListFormat.pings(google: 8, japan: 9), "8 ms, 9 ms")
        expectEqual(ListFormat.pings(google: 0, japan: 9), "-, 9 ms")
        expectEqual(ListFormat.udp(50226), "UDP OK"); expectEqual(ListFormat.udp(nil), "-")
        let ts = Date(timeIntervalSince1970: 1_000_000)
        expect(ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(86_400.0)), "24 h is still OK")
        expect(!ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(86_400.001)), "beyond 24 h is stale")
        expect(ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(-3600)), "the difference is absolute")
        expect(!ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(30 * 3600)), "30 h: accepted for download (36 h) but stale in the UI")
    }
    // MARK: 6. reconnect of VPN Gate connections
    func ready(_ m: AppModel, _ fake: FakeHelperSession) async {
        await expectA(
            await eventuallyA(3) {
                await MainActor.run { m.pollHelper() }; return await MainActor.run { m.helperRunning }
            }, "helper never connected")
    }
    func makeModel(_ path: String, defaults: UserDefaults? = nil, delay: TimeInterval = 0.03) async -> AppModel {
        await MainActor.run {
            AppModel(
                socketPath: path, defaults: defaults ?? throwawayDefaults(), autoStart: false, openInstaller: { true },
                accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("pacc-\(UUID().uuidString.prefix(6)).json"))),
                connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("phist-\(UUID().uuidString.prefix(6)).json"))),
                reconnectDelay: delay)
        }
    }
    func startFake(_ path: String) -> (FakeHelperServer, FakeHelperSession) {
        let fake = FakeHelperSession()
        var snap = HelperEvent(state: .disconnected); snap.helperVersion = helperVersion
        fake.snapshot = snap
        let srv = FakeHelperServer(path: path, session: fake)
        try! srv.start()
        return (srv, fake)
    }
    @Sendable func vpnServer(_ ip: String = "5.6.7.8") -> VPNServer {
        parsedServer(ip: ip)
    }
    func drop(_ fake: FakeHelperSession, _ why: String = "Link closed") {
        var down = HelperEvent(state: .disconnected); down.error = why
        fake.emit?(down)
    }
    test("poll/the-next-refresh-is-scheduled-at-the-delay-the-daemon-chose") {
        let path = tempPath("poll-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        fake.refreshResult = ServerListResult(
            servers: (1...200).map { host($0, ports: [443]) }, source: .httpApi, timestampMs: 1_700_000_000_000, isFresh: true,
            outcome: .synced, nextPollSeconds: 1234)
        let m = await makeModel(path)
        await ready(m, fake)
        await MainActor.run { m.refresh() }
        await expectA(await eventuallyA(5) { await MainActor.run { m.listSource == .httpApi && m.scheduledPollDelay != nil } }, "refresh never finished")
        let (count, delay, loading) = await MainActor.run { (m.servers.count, m.scheduledPollDelay!, m.loading) }
        expectEqual(count, 200); expectEqual(delay, 1234); expect(!loading)
        expectEqual(fake.refreshes.count, 1)
    }
    test("poll/a-failed-refresh-keeps-the-list-and-retries-in-ten-minutes") {
        let path = tempPath("poll-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }  // no scripted result: the daemon answers ok:false
        let m = await makeModel(path)
        await ready(m, fake)
        await MainActor.run {
            m.servers = [host(1, ports: [443])]; m.refresh()
        }
        await expectA(await eventuallyA(5) { await MainActor.run { m.scheduledPollDelay != nil } }, "refresh never finished")
        let (count, delay, err) = await MainActor.run { (m.servers.count, m.scheduledPollDelay!, m.loadError) }
        expectEqual(count, 1, "the list on screen survives a failed refresh"); expectEqual(delay, AppModel.retryPollSeconds); expect(err == nil)
    }
    test("list/a-v9-helper-is-asked-for-the-cached-list-then-a-refresh-when-it-identifies-itself") {
        let path = tempPath("list-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        fake.listResult = ServerListResult(
            servers: [host(1, ports: [443])], source: .cache, timestampMs: nil, isFresh: false, outcome: .noRelays, nextPollSeconds: nil)
        fake.refreshResult = ServerListResult(
            servers: [host(1, ports: [443]), host(2, ports: [995])], source: .relaySync, timestampMs: 1_700_000_000_000, isFresh: true, outcome: .synced,
            nextPollSeconds: 3600)
        let m = await MainActor.run {
            AppModel(
                socketPath: path, defaults: throwawayDefaults(), autoStart: false, openInstaller: { true },
                accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("pacc3-\(UUID().uuidString.prefix(6)).json"))),
                connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("phist3-\(UUID().uuidString.prefix(6)).json"))),
                listOnConnect: true)
        }
        await ready(m, fake)
        await expectA(
            await eventuallyA(5) { await MainActor.run { m.servers.count == 2 && m.listSource == .relaySync } }, "the list never arrived: \(fake.commands)")
        expectEqual(Array(fake.commands.prefix(2)), ["listServers", "refreshServers"])
    }
    test("list/a-v8-helper-gets-no-v9-requests-and-is-offered-an-update") {
        let path = tempPath("list-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        fake.reportedIPCVersion = nil
        let m = await MainActor.run {
            AppModel(
                socketPath: path, defaults: throwawayDefaults(), autoStart: false, openInstaller: { true },
                accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("pacc4-\(UUID().uuidString.prefix(6)).json"))),
                connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("phist4-\(UUID().uuidString.prefix(6)).json"))),
                listOnConnect: true)
        }
        await ready(m, fake)
        await expectA(await eventuallyA(3) { await MainActor.run { m.event.helperVersion != nil } }, "no snapshot")
        await MainActor.run { m.connect(vpnServer()) }
        let (prompt, outdated) = await MainActor.run { (m.setupPrompt, m.helperOutdated) }
        expect(outdated); expect(prompt == .update)
        expect(!fake.commands.contains("listServers") && !fake.commands.contains("refreshServers"), "\(fake.commands)")
    }
    test("probe/results-reach-their-rows") {
        let path = tempPath("probe-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        fake.probeReply = { ts in
            ts.map {
                ProbeEntry(
                    host: $0.host, ok: $0.host == "10.0.0.2", port: 443, connectMs: 12, helloMs: 30, build: 9807, error: $0.host == "10.0.0.2" ? nil : "down")
            }
        }
        let m = await makeModel(path)
        await ready(m, fake)
        let list = [host(1, ports: [995, 443]), host(2, ports: [443])]
        await MainActor.run { m.measure(list) }
        await expectA(
            await eventuallyA(5) { await MainActor.run { m.probes[list[0].id]?.isOK == true || m.probes[list[1].id]?.isOK == true } }, "no probe result")
        let p = await MainActor.run { m.probes }
        expectEqual(p[list[1].id], .failed("down")); expectEqual(p[list[0].id], .ok(port: 443, connectMs: 12, helloMs: 30, build: 9807))
        let sent = fake.probes.flatMap { $0 }
        expectEqual(Set(sent.map(\.host)), ["10.0.0.2", "10.0.0.3"])
        expectEqual(sent.first { $0.host == "10.0.0.2" }?.ports, [443, 995], "the relay's ports in the Windows client's priority order")
    }
    test("probe/one-relay-per-request-so-each-result-shows-up-when-ready") {
        let path = tempPath("probeb-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        fake.probeReply = { ts in ts.map { ProbeEntry(host: $0.host, ok: true, port: 443, connectMs: 12, helloMs: 30, build: nil, error: nil) } }
        let m = await makeModel(path)
        await ready(m, fake)
        let list = (1...20).map { host($0, ports: [443]) }
        await MainActor.run { m.measure(list) }
        await expectA(
            await eventuallyA(5) { await MainActor.run { list.allSatisfy { m.probes[$0.id]?.isOK == true } } }, "not every relay tested")
        expectEqual(fake.probes.map(\.count), Array(repeating: 1, count: 20))
        expectEqual(Set(fake.probes.flatMap { $0.map(\.host) }), Set(list.map(\.ip)), "every relay tested once")
    }
    // The toolbar's open Filter menu is closed by macOS whenever its observed objects publish. These tests count what
    // each one publishes while unrelated things happen.
    test("filter/toolbar-state-is-silent-while-a-test-connection-runs") {
        let path = tempPath("filt-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        fake.probeReply = { ts in ts.map { ProbeEntry(host: $0.host, ok: true, port: 443, connectMs: 12, helloMs: 30, build: nil, error: nil) } }
        let m = await makeModel(path)
        await ready(m, fake)
        let list = (1...20).map { host($0, ports: [443]) }
        try await Task.sleep(nanoseconds: 300_000_000)  // let the helper's first snapshot settle
        let (counts, subs) = await MainActor.run { () -> (Counter, [AnyCancellable]) in
            let c = Counter()
            return (
                c,
                [
                    m.facets.objectWillChange.sink { _ in c.facets += 1 },
                    m.objectWillChange.sink { _ in c.model += 1 },
                    m.probeStore.objectWillChange.sink { _ in c.probes += 1 },
                ]
            )
        }
        _ = subs
        let started = Date()
        await MainActor.run { m.measure(list) }
        await expectA(
            await eventuallyA(5) { await MainActor.run { list.allSatisfy { m.probes[$0.id]?.isOK == true } } }, "not every relay tested")
        let seconds = Date().timeIntervalSince(started)
        expectEqual(counts.facets, 0, "the toolbar's state published during a run")
        expectEqual(counts.model, 0, "the model published during a run")
        // One publish for the queued state, then at most one per flush interval.
        let allowed = 1 + Int(seconds * 1000 / Double(ProbeStore.flushMilliseconds)) + 2
        expect(counts.probes >= 2 && counts.probes <= allowed, "probe store published \(counts.probes) times in \(seconds) s (allowed \(allowed))")
    }
    test("filter/toolbar-state-is-silent-for-log-lines-traffic-and-polling") {
        let path = tempPath("filt2-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path)
        await ready(m, fake)
        let counts = await MainActor.run { () -> Counter in
            let c = Counter(); m.facets.objectWillChange.sink { _ in c.facets += 1 }.store(in: &c.bag); return c
        }
        for i in 0..<10 {
            var e = HelperEvent(state: .connecting); e.log = "line \(i)"
            fake.emit?(e)
            await MainActor.run { m.pollHelper() }
        }
        try await Task.sleep(nanoseconds: 300_000_000)
        let lines = await MainActor.run { m.logLines.count }
        expect(lines >= 10, "the log lines did not arrive (\(lines))")
        expectEqual(counts.facets, 0, "log lines or polling published the toolbar's state")
    }
    test("filter/facets-change-only-when-the-list-or-the-filter-does") {
        let path = tempPath("filt3-\(UUID().uuidString.prefix(6)).sock")
        let m = await makeModel(path)
        let counts = await MainActor.run { () -> Counter in
            let c = Counter(); m.facets.objectWillChange.sink { _ in c.facets += 1 }.store(in: &c.bag); return c
        }
        var a = host(1, ports: [443]); a.countryLong = "Japan"
        var b = host(2, ports: [443]); b.countryLong = "France"
        var c2 = host(3, ports: [443]); c2.countryLong = "Japan"
        await MainActor.run { m.servers = [a, b, c2] }
        let first = await MainActor.run { m.facets.countries }
        expectEqual(first, ["All", "France", "Japan"])
        expectEqual(counts.facets, 1)
        await MainActor.run { m.servers = [c2, a, b] }  // same countries, other order
        expectEqual(counts.facets, 1, "same countries republished")
        await MainActor.run {
            m.maxLogWeeks = 2; m.maxLogWeeks = 2
        }
        expectEqual(counts.facets, 2, "a repeated logging choice republished")
        await MainActor.run { m.servers = [a] }
        let last = await MainActor.run { m.facets.countries }
        expectEqual(last, ["All", "Japan"])
        expectEqual(counts.facets, 3)
    }
    test("reconnect/off-means-no-retry") {
        let path = tempPath("rc-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path)
        await ready(m, fake)
        await MainActor.run {
            m.autoReconnect = false; m.connect(vpnServer())
        }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 })
        drop(fake)
        try await Task.sleep(nanoseconds: 400_000_000)
        expectEqual(fake.connects.count, 1)
        let st = await MainActor.run { m.event.state }
        expect(st == .disconnected, "\(st)")
    }
    test("reconnect/ports-are-sent-in-priority-order") {
        let path = tempPath("rc-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path)
        await ready(m, fake)
        await MainActor.run { m.connect(host(1, ports: [1195, 22, 995, 465, 443])) }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 })
        expectEqual(fake.portLists.first ?? nil, [443, 995, 465, 22, 1195])
        expectEqual(fake.connects.first?.port, 443)
    }

    // MARK: AppModel poll scheduling
    test("reconnect/shows-reconnecting-while-waiting") {
        let path = tempPath("rc-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path, delay: 0.4)
        await ready(m, fake)
        await MainActor.run { m.connect(vpnServer()) }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 })
        drop(fake, "boom")
        await expectA(await eventuallyA(3) { await MainActor.run { m.event.state == .reconnecting } })
        expectEqual(fake.connects.count, 1, "waits before the next attempt")
        await expectA(await eventuallyA(3) { fake.connects.count == 2 })
    }
    test("reconnect/stock-interval-is-15-seconds") {
        expectEqual(AppModel.reconnectInterval, 15)
    }
    test("reconnect/user-disconnect-stops-it") {
        let path = tempPath("rc-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path, delay: 0.3)
        await ready(m, fake)
        await MainActor.run { m.connect(vpnServer()) }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 })
        drop(fake)
        await expectA(await eventuallyA(3) { await MainActor.run { m.event.state == .reconnecting } })
        await MainActor.run { m.disconnect() }
        let st = await MainActor.run { m.event.state }
        expect(st == .disconnected, "\(st)")
        try await Task.sleep(nanoseconds: 600_000_000)
        expectEqual(fake.connects.count, 1, "no attempt after the user disconnected")
        drop(fake)  // a late error from the helper must not revive it either
        try await Task.sleep(nanoseconds: 300_000_000)
        expectEqual(fake.connects.count, 1)
    }
    test("reconnect/vpn-gate-connection-retries-forever-and-the-helper-is-told-not-to") {
        let path = tempPath("rc-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path)
        await ready(m, fake)
        let s = vpnServer()
        await MainActor.run { m.connect(s) }
        await expectA(await eventuallyA(3) { fake.connects.count == 1 })
        expectEqual(fake.autoReconnects, [false], "the app does the retrying so the interval is 15 s, not the helper's 3 s x 8")
        // 12 consecutive failures: more than the old cap of 8, each followed by a new attempt at the same server
        for n in 1...12 {
            drop(fake)
            await expectA(await eventuallyA(3) { fake.connects.count == n + 1 }, "attempt \(n + 1) never started")
        }
        expect(fake.connects.allSatisfy { $0.host == "5.6.7.8" })
        let state = await MainActor.run { m.event.state }
        expect(state == .connecting || state == .reconnecting, "\(state)")
        // a successful connection resets the counter
        var up = HelperEvent(state: .connected); up.server = "5.6.7.8"
        fake.emit?(up)
        await expectA(await eventuallyA(3) { await MainActor.run { m.reconnectAttempts == 0 && m.isConnected } })
    }
    test("telemetry/host-label-uses-key-characters-2-and-3") {
        let url = VGStatistics.telemetryURL(hostKey: "0123456789abcdef0123456789abcdef")
        expect(url.host == "x2.x3.statistics.api.vpngate2.jp", url.host ?? "")
        expect(VGStatistics.telemetryURL(hostKey: "ab").host == "x0.x0.statistics.api.vpngate2.jp", "short keys fall back to 0")
    }

    // MARK: 7. old files with the removed hide key
}

/// Counts what the observed objects publish in a test (written from the main actor, read after the work is done).
final class Counter: @unchecked Sendable {
    var facets = 0, model = 0, probes = 0
    var bag: Set<AnyCancellable> = []
}
