import Foundation
import VPNGateCore

// Parity with the Windows VPN Gate client (tunables, poll schedule, relay choice, HTTP API, list text, reconnect).
// Everything runs against fakes or loopback: no test here opens a real network connection.

private func fixtureFileURL(_ name: String, file: String = #filePath) -> URL {
    URL(fileURLWithPath: file).deletingLastPathComponent().deletingLastPathComponent()
        .appendingPathComponent("Fixtures/" + name)
}

func registerParityTests() {
    let rawDat = fixtureData("VPNGate.dat")

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
}
