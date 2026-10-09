import Foundation
import VPNGateCore

// Parity with the Windows VPN Gate client (tunables, poll schedule, relay choice, HTTP API, list text, reconnect).
// Everything runs against fakes or loopback: no test here opens a real network connection.

private func fixtureFileURL(_ name: String, file: String = #filePath) -> URL {
    URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/" + name)
}

private func tmpDir() -> URL {
    let d = FileManager.default.temporaryDirectory.appendingPathComponent("vpngate-parity-\(UUID().uuidString)", isDirectory: true)
    try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
    return d
}

private func throwawayDefaults() -> UserDefaults {
    let name = "vpngate-parity-\(UUID().uuidString)"
    let d = UserDefaults(suiteName: name)!
    d.removePersistentDomain(forName: name)
    d.set(true, forKey: "hasAgreedToDisclaimer")
    return d
}

private struct NoNetwork: Error {}
private let neverHTTP: HTTPGet = { _, _, _, _ in throw NoNetwork() }

/// A relay stream that serves `payload` (like the real one), or fails at once when `payload` is nil.
private final class ScriptedStream: ByteStream {
    var buffer = ByteBuffer()
    var isCancelled = false
    private var served = false
    let payload: Data?
    init(payload: Data?) { self.payload = payload }
    func start() async throws { if payload == nil { throw StreamError.closed } }
    func send(_ data: Data) async throws {}
    func readChunk() async throws -> Data {
        guard let payload else { throw StreamError.closed }
        guard !served else { return Data([1]) }
        served = true
        var resp = Data(); var len = UInt32(payload.count).bigEndian
        withUnsafeBytes(of: &len) { resp.append(contentsOf: $0) }
        return resp + payload
    }
    func cancel() { isCancelled = true }
}

private func host(_ i: Int, ports: [UInt16], udp: UInt16? = nil) -> VPNServer {
    VPNServer(hostName: "h\(i)", ip: "10.0.\(i / 200).\(i % 200 + 1)", fqdn: "h\(i).example", sslPorts: ports, udpPort: udp)
}

private func dynList(_ entries: [(String, UInt64)]) -> Data {
    var p = Pack()
    for (k, v) in entries { p.addInt64(k, v) }
    return p.serialize()
}

func registerParityTests() {
    let rawDat = fixtureData("VPNGate.dat")

    // MARK: 1. DynList tunables
    test("tunables/the-shipped-dat-carries-the-dynlist-and-it-parses") {
        let file = try VGDat.parse(data: rawDat)
        expectEqual(file.tunables.value("VGC_HTTP_POLL_INTERVAL_OK", default: 3_600_000), 7_200_000)
        expectEqual(file.tunables.values["vg_ddns_update_interval_min"], 1_800_000)
        expectEqual(file.tunables.values["vg_ddns_update_interval_max"], 7_200_000)
        expectEqual(file.tunables.values.count, 3)
        // names it does not mention keep the compiled-in default
        expectEqual(file.tunables.value("VGC_HTTP_POLL_INTERVAL_ERROR", default: 600_000), 600_000)
    }
    test("tunables/lookup-clamps-to-a-fifth-and-fifty-times-the-default") {
        let t = VGTunables(dynList: dynList([("A", 1), ("B", 1_000_000_000), ("C", 0), ("D", 700), ("Mixed_Case", 400)]))
        expectEqual(t.value("A", default: 1000), 200, "below default/5")
        expectEqual(t.value("B", default: 1000), 50_000, "above default*50")
        expectEqual(t.value("C", default: 1000), 1000, "0 means unset")
        expectEqual(t.value("D", default: 1000), 700, "in range is taken as is")
        expectEqual(t.value("mixed_case", default: 1000), 400, "names compare case-insensitively")
        expectEqual(t.value("missing", default: 1000), 1000)
        expectEqual(t.value("A", default: UInt64.max), UInt64.max / 5 > 1 ? UInt64.max / 5 : 1, "no overflow on huge defaults")
        // an int (not int64) element reads as 0 in the original = default
        var p = Pack(); p.addInt("E", 5000)
        expectEqual(VGTunables(dynList: p.serialize()).value("E", default: 1000), 1000)
        expect(VGTunables(dynList: Data([1, 2, 3])).values.isEmpty, "garbage is ignored")
    }
    test("tunables/later-lists-overwrite-only-the-names-they-mention") {
        var t = VGTunables(dynList: dynList([("X", 100), ("Y", 200)]))
        t.merge(VGTunables(dynList: dynList([("Y", 300)])))
        expectEqual(t.values["x"], 100); expectEqual(t.values["y"], 300)
    }

    // MARK: 2. poll schedule
    test("poll/next-poll-is-rand-mod-interval-with-the-dat-override") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let f = VGDatFetcher(httpGet: neverHTTP, cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [], defaults: throwawayDefaults())
        // built-in defaults: OK 3600 s, relays failed 600 s, nothing to ask 600 s
        expectEqual(f.nextPollDelay(after: .synced, random: 3_600_000 + 5), 0.005)
        expectEqual(f.nextPollDelay(after: .synced, random: 0), 0)
        expectEqual(f.nextPollDelay(after: .relaysFailed, random: 650_000), 50.0)
        expectEqual(f.nextPollDelay(after: .noRelays, random: 599_999), 599.999)
        // after adopting the shipped list's DynList the OK interval is 7200 s
        f.adopt(try VGDat.parse(data: rawDat))
        expectEqual(f.nextPollDelay(after: .synced, random: 7_199_999), 7199.999)
        expectEqual(f.nextPollDelay(after: .synced, random: 7_200_000 + 7), 0.007)
        expectEqual(f.nextPollDelay(after: .relaysFailed, random: 650_000), 50.0, "error interval not overridden by that list")
        // uniform jitter, not a fixed value
        let samples = Set((0..<50).map { _ in f.nextPollDelay(after: .synced) })
        expect(samples.count > 40, "random delays must differ: \(samples.count)")
        expect(samples.allSatisfy { $0 >= 0 && $0 < 7200 })
    }

    // MARK: 3. relay choice
    test("relays/port-priority-order-matches-the-windows-client") {
        expectEqual(VPNServer.portPriority([9008, 22, 993, 465, 1195, 443, 585, 995, 992]),
                    [443, 992, 995, 465, 585, 993, 22, 9008, 1195])
        expectEqual(VPNServer.portPriority([1195, 9008]), [1195, 9008])
        expectEqual(VPNServer.portPriority([]), [])
        let s = host(1, ports: [465, 995, 1195])
        expectEqual(s.connectPort, 995, "connect port follows the priority too")
    }
    test("relays/selection-443-first-up-to-13-then-others-up-to-13-on-their-best-port") {
        var servers = [VPNServer]()
        for i in 0..<20 { servers.append(host(i, ports: [8000, 443])) }            // 20 with 443 -> only 13 used
        for i in 20..<40 { servers.append(host(i, ports: [22, 993, 1195, 585])) }  // best port is 585
        servers.append(host(99, ports: []))                                         // no SSL port: never asked
        let t = VGDatFetcher.selectTargets(from: servers, limit: 12, shuffle: { $0 })
        expectEqual(t.count, 26)
        expect(t.prefix(13).allSatisfy { $0.port == 443 }, "443 hosts first")
        expectEqual(t.prefix(13).map(\.ip), servers.prefix(13).map(\.ip))
        expect(t.suffix(13).allSatisfy { $0.port == 585 }, "others on the first port of the priority order")
        expect(!t.contains { $0.ip == servers.last!.ip })
        // lists without any SSL port (CSV) keep working through the OpenVPN-config port
        let csv = ServerList.parse("#h\nv,1.2.3.4,1,1,1,Japan,JP,1,1,1,1,2weeks,Op,msg,\(Data("proto tcp\nremote 1.2.3.4 1443\n".utf8).base64EncodedString())\n")
        expectEqual(VGDatFetcher.selectTargets(from: csv, limit: 12, shuffle: { $0 }), [RelayTarget(ip: "1.2.3.4", port: 1443)])
    }
    test("relays/fetch-asks-in-that-order-and-the-count-follows-the-dat-tunable") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let asked = Locked([RelayTarget]())
        let servers = (0..<30).map { host($0, ports: [443, 22]) } + (30..<60).map { host($0, ports: [22, 993]) }
        let f = VGDatFetcher(makeStream: { h, p, _ in asked.update { $0.append(RelayTarget(ip: h, port: p)) }; return ScriptedStream(payload: nil) },
                             httpGet: neverHTTP, cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [],
                             defaults: throwawayDefaults(), shuffle: { $0 })
        do { _ = try await f.fetchFromRelays(candidates: servers, proxy: ProxySettings()); expect(false, "all relays fail") } catch {}
        expectEqual(asked.value.count, 26)
        expectEqual(asked.value.prefix(13).map(\.port), Array(repeating: 443, count: 13))
        expectEqual(asked.value.suffix(13).map(\.port), Array(repeating: 993, count: 13))
        // VGC_NUM_TCP_TARGET_HOSTS = 24 (inside [2, 600]) -> 25 per pass
        asked.update { $0 = [] }
        f.adoptTunables(VGTunables(dynList: dynList([("VGC_NUM_TCP_TARGET_HOSTS", 24)])))
        do { _ = try await f.fetchFromRelays(candidates: servers, proxy: ProxySettings()); expect(false, "all relays fail") } catch {}
        expectEqual(asked.value.count, 50)
    }
    test("relays/last-good-relay-is-remembered-tried-first-and-forgotten-when-it-fails") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let defaults = throwawayDefaults()
        let servers = (0..<6).map { host($0, ports: [443]) }
        let good = servers[3].ip
        let asked = Locked([String]())
        let working = Locked(true)
        let fileTime = try VGDat.parse(data: rawDat).timestamp
        func fetcher() -> VGDatFetcher {
            VGDatFetcher(makeStream: { h, _, _ in
                asked.update { $0.append(h) }
                return ScriptedStream(payload: (h == good && working.value) ? rawDat : nil)
            }, httpGet: neverHTTP, cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [],
                         now: { fileTime.addingTimeInterval(60) }, defaults: defaults, shuffle: { $0 })
        }
        let first = fetcher()
        _ = try await first.fetchFromRelays(candidates: servers, proxy: ProxySettings())
        expectEqual(asked.value, servers.prefix(4).map(\.ip), "walks the list until one answers")
        expectEqual(first.lastGoodRelay, RelayTarget(ip: good, port: 443))
        expectEqual(defaults.string(forKey: "lastGoodRelay"), "\(good):443", "persisted in the injected defaults")

        asked.update { $0 = [] }
        _ = try await fetcher().fetchFromRelays(candidates: servers, proxy: ProxySettings())     // a new fetcher = a new launch
        expectEqual(asked.value, [good], "last-good first, and nothing else needed")

        asked.update { $0 = [] }; working.update { $0 = false }
        let third = fetcher()
        do { _ = try await third.fetchFromRelays(candidates: servers, proxy: ProxySettings()); expect(false, "all fail now") } catch {}
        expectEqual(asked.value.first, good); expectEqual(asked.value.count, 6, "no host asked twice")
        expect(third.lastGoodRelay == nil, "a failed last-good relay is forgotten")
    }

    // MARK: 4. HTTP API
    test("http-api/url-shape-and-signed-dat-body") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let fileTime = try VGDat.parse(data: rawDat).timestamp
        let urls = Locked([URL]())
        let f = VGDatFetcher(httpGet: { url, connect, data, max in
            urls.update { $0.append(url) }
            expectEqual(connect, 7.0); expectEqual(data, 60.0); expectEqual(max, 32 * 1024 * 1024)
            return rawDat
        }, cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [], now: { fileTime.addingTimeInterval(60) },
                             defaults: throwawayDefaults(), apiDigits: ("a", "7"))
        let dat = try await f.fetchFromHTTPApi()
        expectEqual(dat.servers.count, 200)
        let u = urls.value[0].absoluteString
        expect(u.hasPrefix("http://xa.x7.client.api.vpngate2.jp/api/?session_id="), u)
        expect(UInt64(u.components(separatedBy: "session_id=")[1]) != nil, "session_id is a decimal u64")
        expectEqual(f.tunables.value("VGC_HTTP_POLL_INTERVAL_OK", default: 3_600_000), 7_200_000, "tunables adopted from the HTTP list")
        expect(FileManager.default.fileExists(atPath: dir.appendingPathComponent("c.dat").path), "fresh verified list cached")
        _ = try await f.fetchFromHTTPApi()
        expect(urls.value[0] != urls.value[1], "a new random session id every request")
    }
    test("http-api/sync-prefers-it-and-never-touches-the-relays") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let fileTime = try VGDat.parse(data: rawDat).timestamp
        let streams = Locked(0)
        let f = VGDatFetcher(makeStream: { _, _, _ in streams.update { $0 += 1 }; return ScriptedStream(payload: nil) },
                             httpGet: { _, _, _, _ in rawDat }, cacheURL: dir.appendingPathComponent("c.dat"),
                             bundleURLs: [fixtureFileURL("VPNGate.dat")], now: { fileTime.addingTimeInterval(60) }, defaults: throwawayDefaults())
        let r = await f.sync(currentServers: [host(1, ports: [443])], proxy: ProxySettings())
        expect(r.source == .httpApi); expectEqual(r.servers.count, 200); expectEqual(streams.value, 0)
        expect(r.outcome == .synced)
    }
    test("http-api/bad-replies-fall-back-to-the-relays") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let fileTime = try VGDat.parse(data: rawDat).timestamp
        var tampered = rawDat; tampered[0x200] ^= 0x55
        let bodies: [(String, Data?, TimeInterval)] = [("unreachable", nil, 60), ("corrupt", tampered, 60), ("not a list", Data("<html>".utf8), 60),
                                                         ("stale", rawDat, 40 * 3600)]
        for (label, body, age) in bodies {
            let streams = Locked(0)
            let f = VGDatFetcher(makeStream: { _, _, _ in streams.update { $0 += 1 }; return ScriptedStream(payload: rawDat) },
                                 httpGet: { _, _, _, _ in if let body { return body }; throw NoNetwork() },
                                 cacheURL: dir.appendingPathComponent("c-\(label).dat"), bundleURLs: [fixtureFileURL("VPNGate.dat")],   // never fall through to the CSV mirror (network)
                                 now: { fileTime.addingTimeInterval(age) }, defaults: throwawayDefaults(), shuffle: { $0 })
            // for the stale case the relay serves the same old list, so it is rejected there too and the bundle is used
            let r = await f.sync(currentServers: [host(1, ports: [443])], proxy: ProxySettings())
            expectEqual(streams.value, 1, "\(label): the relays are asked after a bad HTTP reply")
            if label != "stale" { expect(r.source == .relaySync, "\(label): \(r.source)") }
        }
    }
    test("http-api/alternative-mode-adds-https-and-an-app-proxy-skips-http-entirely") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        for alt in [false, true] {
            let urls = Locked([String]())
            let f = VGDatFetcher(httpGet: { url, _, _, _ in urls.update { $0.append(url.scheme!) }; throw NoNetwork() },
                                 cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [fixtureFileURL("VPNGate.dat")],
                                 defaults: throwawayDefaults(), alternativeMode: alt)
            _ = try? await f.fetchFromHTTPApi()
            expectEqual(urls.value, alt ? ["http", "https"] : ["http"])
        }
        let calls = Locked(0)
        let f = VGDatFetcher(httpGet: { _, _, _, _ in calls.update { $0 += 1 }; throw NoNetwork() },
                             cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [fixtureFileURL("VPNGate.dat")], defaults: throwawayDefaults())
        var proxy = ProxySettings(); proxy.kind = .socks5; proxy.host = "127.0.0.1"; proxy.port = 1080
        _ = await f.sync(currentServers: [], proxy: proxy)
        expectEqual(calls.value, 0, "URLSession cannot honour the app's proxy, so the API is not asked")
    }
    test("http-api/default-client-checks-status-and-size-on-loopback") {
        let ok = LocalHTTPServer(body: rawDat); defer { ok.stop() }
        let body = try await VGDatFetcher.urlSessionGet(ok.url, 5, 5, 1 << 20)
        expectEqual(body, rawDat)
        let bad = LocalHTTPServer(status: 500, body: rawDat); defer { bad.stop() }
        do { _ = try await VGDatFetcher.urlSessionGet(bad.url, 5, 5, 1 << 20); expect(false, "500 must throw") } catch {}
        do { _ = try await VGDatFetcher.urlSessionGet(ok.url, 5, 5, 1000); expect(false, "oversized body must throw") } catch {}
    }

    // MARK: 5. telemetry host digits
    test("telemetry/host-label-uses-key-characters-2-and-3") {
        let url = VGStatistics.telemetryURL(hostKey: "0123456789abcdef0123456789abcdef")
        expect(url.host == "x2.x3.statistics.api.vpngate2.jp", url.host ?? "")
        expect(VGStatistics.telemetryURL(hostKey: "ab").host == "x0.x0.statistics.api.vpngate2.jp", "short keys fall back to 0")
    }

    // MARK: 7. old files with the removed hide key
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
        expectEqual(ListFormat.uptime(ms: 0), "0 min")
        expectEqual(ListFormat.uptime(ms: 59_999), "0 min")
        expectEqual(ListFormat.uptime(ms: 3_599_999), "59 min")
        expectEqual(ListFormat.uptime(ms: 3_600_000), "60 min", "exactly 1 h is still minutes (cut-off < 3,600,001)")
        expectEqual(ListFormat.uptime(ms: 3_600_001), "1 h")
        expectEqual(ListFormat.uptime(ms: 5_400_000), "1 h")
        expectEqual(ListFormat.uptime(ms: 86_400_000), "24 h", "exactly 24 h is still hours (cut-off < 86,400,001)")
        expectEqual(ListFormat.uptime(ms: 86_400_001), "1 d")
        expectEqual(ListFormat.uptime(ms: 542_874_958), "6 d")
    }
    test("list/pings-udp-and-status-line") {
        expectEqual(ListFormat.pings(google: 8, japan: 9), "8 ms, 9 ms")
        expectEqual(ListFormat.pings(google: 0, japan: 9), "-, 9 ms")
        expectEqual(ListFormat.udp(50226), "Yes"); expectEqual(ListFormat.udp(nil), "-")
        let ts = Date(timeIntervalSince1970: 1_000_000)
        expect(ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(86_400.0)), "24 h is still OK")
        expect(!ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(86_400.001)), "beyond 24 h is stale")
        expect(ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(-3600)), "the difference is absolute")
        expect(!ListFormat.isListOK(timestamp: ts, now: ts.addingTimeInterval(30 * 3600)), "30 h: accepted for download (36 h) but stale in the UI")
    }
    test("list/dat-fields-that-used-to-be-ignored-are-parsed") {
        let s = try VGDat.parse(data: rawDat).servers[0]
        expectEqual(s.pingToGoogle, 8); expectEqual(s.name, "vpn118756292")
        expectEqual(s.sendSize, 9_157_554_378_763); expectEqual(s.recvSize, 988_618_984_066)
        expectEqual(s.totalTraffic, 9_157_554_378_763 + 988_618_984_066)
        expect(s.isKernelModeNAT)
        expectEqual(s.prioritizedSslPorts, [995, 465, 1195, 1897, 9008])
        expectEqual(s.connectPort, 995); expectEqual(s.listedPort, 995)
        let back = try JSONDecoder().decode(VPNServer.self, from: try JSONEncoder().encode(s))
        expectEqual(back, s)
        // caches written before these fields existed still load
        var json = try JSONSerialization.jsonObject(with: JSONEncoder().encode(s)) as! [String: Any]
        for k in ["name", "pingToGoogle", "sendSize", "recvSize", "isKernelModeNAT"] { json[k] = nil }
        let old = try JSONDecoder().decode(VPNServer.self, from: JSONSerialization.data(withJSONObject: json))
        expectEqual(old.pingToGoogle, 0); expectEqual(old.sendSize, 0); expect(old.name == nil)
    }

    // MARK: 6. reconnect of VPN Gate connections
    func ready(_ m: AppModel, _ fake: FakeSession) async {
        await expectA(await eventuallyA(3) { await MainActor.run { m.pollHelper() }; return await MainActor.run { m.helperRunning } }, "helper never connected")
    }
    func makeModel(_ path: String, defaults: UserDefaults? = nil, delay: TimeInterval = 0.03) async -> AppModel {
        await MainActor.run {
            AppModel(socketPath: path, defaults: defaults ?? throwawayDefaults(), autoStart: false, openInstaller: { true },
                     accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("pacc-\(UUID().uuidString.prefix(6)).json"))),
                     connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("phist-\(UUID().uuidString.prefix(6)).json"))),
                     datFetcher: VGDatFetcher(httpGet: neverHTTP, cacheURL: URL(fileURLWithPath: tempPath("pc-\(UUID().uuidString.prefix(6)).dat")),
                                              bundleURLs: [], defaults: throwawayDefaults()),
                     reconnectDelay: delay)
        }
    }
    func startFake(_ path: String) -> (IPCServer, FakeSession) {
        let fake = FakeSession()
        var snap = HelperEvent(state: .disconnected); snap.helperVersion = helperVersion
        fake.snapshot = snap
        let srv = IPCServer(path: path, allowedUID: getuid(), session: fake)
        try! srv.start()
        return (srv, fake)
    }
    @Sendable func vpnServer(_ ip: String = "5.6.7.8") -> VPNServer {
        ServerList.parse("#h\nvpn1,\(ip),1,1,1,Japan,JP,1,1,1,1,2weeks,Op,msg,\(Data("proto tcp\nremote \(ip) 443\n".utf8).base64EncodedString())\n")[0]
    }
    func drop(_ fake: FakeSession, _ why: String = "Link closed") {
        var down = HelperEvent(state: .disconnected); down.error = why
        fake.emit?(down)
    }

    test("reconnect/stock-interval-is-15-seconds") {
        expectEqual(AppModel.reconnectInterval, 15)
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
        drop(fake)                                  // a late error from the helper must not revive it either
        try await Task.sleep(nanoseconds: 300_000_000)
        expectEqual(fake.connects.count, 1)
    }
    test("reconnect/off-means-no-retry") {
        let path = tempPath("rc-\(UUID().uuidString.prefix(6)).sock")
        let (srv, fake) = startFake(path); defer { srv.stop() }
        let m = await makeModel(path)
        await ready(m, fake)
        await MainActor.run { m.autoReconnect = false; m.connect(vpnServer()) }
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
    test("poll/app-model-schedules-a-random-delay-from-the-dat-interval") {
        let dir = tmpDir(); defer { try? FileManager.default.removeItem(at: dir) }
        let fileTime = try VGDat.parse(data: rawDat).timestamp
        let m = await MainActor.run {
            AppModel(socketPath: tempPath("p.sock"), defaults: throwawayDefaults(), autoStart: false, openInstaller: { true },
                     accountManager: AccountManager(fileURL: URL(fileURLWithPath: tempPath("pacc2-\(UUID().uuidString.prefix(6)).json"))),
                     connectionLog: ConnectionLogStore(fileURL: URL(fileURLWithPath: tempPath("phist2-\(UUID().uuidString.prefix(6)).json"))),
                     datFetcher: VGDatFetcher(httpGet: { _, _, _, _ in rawDat }, cacheURL: dir.appendingPathComponent("c.dat"), bundleURLs: [],
                                              now: { fileTime.addingTimeInterval(60) }, defaults: throwawayDefaults()))
        }
        await MainActor.run { m.refresh() }
        await expectA(await eventuallyA(5) { await MainActor.run { m.listSource == .httpApi && m.scheduledPollDelay != nil } }, "refresh never finished")
        let (count, delay) = await MainActor.run { (m.servers.count, m.scheduledPollDelay!) }
        expectEqual(count, 200)
        expect(delay >= 0 && delay < 7200, "delay \(delay) must be inside [0, 7200 s) of the dat's OK interval")
    }
}
