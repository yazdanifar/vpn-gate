import Foundation
import VPNGateCore

func registerTelemetryTests() {
    test("telemetry/pack-fields-and-serialization") {
        let hostKey = VGStatistics.hostKeyHex
        expect(!hostKey.isEmpty, "host key must not be empty")

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
        expect(url.absoluteString.contains("x\(key.prefix(1)).x"))
        expect(url.absoluteString.contains("statistics.api.vpngate2.jp"))
        expect(url.absoluteString.contains("rand="))
    }

    test("connection-log/crud-operations") {
        Task { @MainActor in
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
