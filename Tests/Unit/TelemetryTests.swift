import Foundation
import VPNGateCore

func registerTelemetryTests() {
    test("telemetry/pack-fields-and-serialization") {
        let hostKey = "0123456789abcdef0123456789abcdef"

        let pack = VGStatistics.makeTelemetryPack(hostKey: hostKey)
        expectEqual(pack.str("HostKey"), hostKey)
        expectEqual(pack.int("Build"), 9807)
        expectEqual(pack.int("ClientVer"), 444)
        expectEqual(pack.int("ClientBuild"), 9807)
        expectEqual(pack.str("ClientOsName"), "macOS")
        expectEqual(pack.int("IsClient"), 1)

        let bytes = pack.serialize()
        expect(bytes.count > 0)
        let roundtrip = try Pack(parsing: bytes)
        expectEqual(roundtrip.str("HostKey"), hostKey)
    }

    test("telemetry/url-generation-and-base36") {
        let key = "abcdef0123456789"
        let url = VGStatistics.telemetryURL(hostKey: key)
        // host digits are the key characters at index 2 and 3 (client_exe.c:12530-12535), not 0 and 1
        expect(url.absoluteString.hasPrefix("https://xc.xd.statistics.api.vpngate2.jp/api/statistics/?rand="), url.absoluteString)
        expect(url.absoluteString.contains("statistics.api.vpngate2.jp"))
        expect(url.absoluteString.contains("rand="))
    }

    test("telemetry/a-real-upload-posts-exactly-the-documented-payload") {
        // End-to-end: start a loopback HTTP server, point a real VGStatistics upload at it, and parse what it
        // actually sent off the wire, independently of the production code's own serializer.
        let server = LocalHTTPServer(body: Data()); defer { server.stop() }
        let defaults = UserDefaults(suiteName: "telemetry-test-\(UUID().uuidString)")!
        let stats = await MainActor.run { VGStatistics(defaults: defaults, startIfEnabled: false) }
        await MainActor.run { stats.isEnabled = true }  // opt in, but nothing is scheduled (startIfEnabled: false)
        let hostKey = await MainActor.run { stats.hostKey }

        let ok = await stats.sendStatistics(overrideURL: server.url)
        expect(ok, "upload to the local server must succeed")
        expectEqual(server.requests, 1)

        guard let req = server.lastRequest else { expect(false, "server captured no request"); return }
        expectEqual(req.method, "POST")
        expectEqual(req.headers["content-type"], "application/octet-stream")
        expect(req.headers["user-agent"]?.contains("opt-in") == true, "the user agent must disclose what this is")

        // Parse the body with the same Pack format a server would, not by re-running our own serializer.
        let sent = try Pack(parsing: req.body)
        expectEqual(sent.str("HostKey"), hostKey)
        expectEqual(sent.int("Build"), 9807)
        expectEqual(sent.int("ClientVer"), 444)
        expectEqual(sent.int("ClientBuild"), 9807)
        expectEqual(sent.str("ClientOsName"), "macOS")
        expectEqual(sent.int("IsClient"), 1)
        // Exactly these six fields: the documented payload must not grow silently.
        expectEqual(Set(sent.elements.map(\.name)), ["HostKey", "Build", "ClientVer", "ClientBuild", "ClientOsName", "IsClient"])

        await MainActor.run { stats.isEnabled = false }
        defaults.removePersistentDomain(forName: "telemetry-test")
    }

    test("telemetry/disabled-sends-nothing-to-a-server-that-would-notice") {
        let server = LocalHTTPServer(body: Data()); defer { server.stop() }
        let defaults = UserDefaults(suiteName: "telemetry-test-\(UUID().uuidString)")!
        let stats = await MainActor.run { VGStatistics(defaults: defaults, startIfEnabled: false) }
        // isEnabled defaults to false (off); sendStatistics must refuse even with an explicit override URL.
        let ok = await stats.sendStatistics(overrideURL: server.url)
        expect(!ok, "a disabled upload must not succeed")
        expectEqual(server.requests, 0, "a disabled upload must not touch the network at all")
    }

    test("connection-log/crud-operations") {
        await MainActor.run {
            let store = ConnectionLogStore()
            store.clear()
            expectEqual(store.entries.count, 0)

            let id = store.recordStart(serverName: "vpn1.example.com", serverIP: "1.2.3.4")
            expectEqual(store.entries.count, 1)
            expectEqual(store.entries[0].serverName, "vpn1.example.com")
            expect(store.entries[0].disconnectedAt == nil)

            store.recordEnd(id: id, bytesIn: 5000, bytesOut: 3000, error: nil)
            expect(store.entries[0].disconnectedAt != nil)
            expectEqual(store.entries[0].bytesIn, 5000)
            expectEqual(store.entries[0].bytesOut, 3000)
            expect(store.entries[0].durationSeconds != nil)

            store.clear()
            expectEqual(store.entries.count, 0)
        }
    }
}
