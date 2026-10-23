import Foundation
import VPNGateCore

private func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }
private let cfgTCP = b64("client\nproto tcp\nremote 1.2.3.4 995\n")
private let cfgUDP = b64("client\nproto udp\nremote 1.2.3.4 1525\n")
private let header =
    "*vpn_servers\n#HostName,IP,Score,Ping,Speed,CountryLong,CountryShort,NumVpnSessions,Uptime,TotalUsers,TotalTraffic,LogType,Operator,Message,OpenVPN_ConfigData_Base64\n"

private func row(
    host: String = "h1", ip: String = "1.2.3.4", msg: String = "", op: String = "Op",
    log: String = "2weeks", cfg: String = cfgTCP, country: String = "Japan", short: String = "JP"
) -> String {
    "\(host),\(ip),1000,12,5000000,\(country),\(short),5,100,200,300,\(log),\(op),\(msg),\(cfg)"
}

func registerServerListTests() {
    test("serverlist/parses-basic-row") {
        let s = ServerList.parse(header + row(msg: "msg") + "\n*\n")
        expectEqual(s.count, 1)
        expectEqual(s[0].ip, "1.2.3.4"); expectEqual(s[0].connectPort, 995); expectEqual(s[0].message, "msg")
        expectEqual(s[0].flag, "🇯🇵"); expectEqual(s[0].speed, 5_000_000); expectEqual(s[0].uptimeMs, 100)
    }
    test("serverlist/handles-crlf-and-blank-lines") {
        expectEqual(ServerList.parse(header.replacingOccurrences(of: "\n", with: "\r\n") + row() + "\r\n\r\n*\r\n").count, 1)
    }
    test("serverlist/skips-short-and-garbage-rows") {
        expectEqual(ServerList.parse(header + "a,b,c\n" + "\n" + row() + "\n").count, 1)
        expectEqual(ServerList.parse("").count, 0)
    }
    test("serverlist/snapshot-ids-are-unique") {  // B6
        let s = ServerList.parse(fixture("vpngate-snapshot.csv"))
        expectEqual(s.count, 10)
        expectEqual(Set(s.map(\.id)).count, s.count, "ids: \(s.map(\.id))")
    }
    test("serverlist/same-ip-different-servers-are-distinct") {  // B6
        let s = ServerList.parse(header + row(host: "vpnA", ip: "9.9.9.9") + "\n" + row(host: "vpnB", ip: "9.9.9.9") + "\n")
        expect(s.count == 2 && s[0].id != s[1].id, "ids \(s.map(\.id))")
    }
    test("serverlist/plain-text-message-is-not-base64-decoded") {  // B15
        let s = ServerList.parse(header + row(msg: "Hello123") + "\n" + row(host: "h2", msg: "east.vpngate.dnc.ne.jp") + "\n")
        expectEqual(s[0].message, "Hello123")
        expectEqual(s[1].message, "east.vpngate.dnc.ne.jp")
    }
    test("serverlist/unicode-message") {
        let m = "こんにちは! Hello! Здравствуйте! 你好! سلام (^_^)/"
        expectEqual(ServerList.parse(header + row(msg: m) + "\n")[0].message, m)
    }
    test("serverlist/comma-inside-message-does-not-shift-columns") {  // B15
        let s = ServerList.parse(header + row(msg: "hello, world") + "\n")
        expectEqual(s.count, 1)
        expectEqual(s[0].connectPort, 995, "config column must still be the last field")
        expectEqual(s[0].message, "hello, world")
    }
    test("serverlist/udp-only-config-keeps-its-port") {  // B16
        let s = ServerList.parse(header + row(cfg: cfgUDP) + "\n")
        expectEqual(s[0].connectPort, 1525, "listed port must be tried first even for udp configs")
    }
    test("serverlist/no-port-in-config") {
        let s = ServerList.parse(header + row(cfg: b64("client\n")) + "\n")
        expectEqual(s[0].connectPort, nil)
        expectEqual(ServerList.parse(header + row(cfg: "!!notbase64!!") + "\n").count, 1)
    }
    test("serverlist/port-out-of-range-is-ignored") {  // B4
        let s = ServerList.parse(header + row(cfg: b64("proto tcp\nremote 1.2.3.4 99999\n")) + "\n")
        expectEqual(s[0].connectPort, nil)
    }
    test("serverlist/cache-written-by-the-first-version-still-decodes") {
        // first app version: `tcpPort`, no `listedPort`/`listedProto`; losing it left the table empty until a download finished
        let old =
            #"[{"hostName":"vpn1","ip":"1.2.3.4","score":5,"ping":1,"speed":2,"countryLong":"Japan","countryShort":"JP","sessions":3,"uptimeMs":4,"totalUsers":5,"totalTraffic":6,"logType":"2weeks","operatorName":"Op","message":"m","tcpPort":995}]"#
        let l = try JSONDecoder().decode([VPNServer].self, from: Data(old.utf8))
        expectEqual(l.count, 1); expectEqual(l[0].connectPort, 995); expectEqual(l[0].id, "vpn1")
        let min = try JSONDecoder().decode([VPNServer].self, from: Data(#"[{"hostName":"h","ip":"1.1.1.1"}]"#.utf8))
        expectEqual(min.count, 1); expectEqual(min[0].connectPort, nil)
    }
    test("serverlist/cache-roundtrip") {
        let s = ServerList.parse(fixture("vpngate-snapshot.csv"))
        let back = try JSONDecoder().decode([VPNServer].self, from: JSONEncoder().encode(s))
        expectEqual(back, s)
    }
    test("serverlist/rows-with-a-non-ip-address-are-dropped") {
        expectEqual(ServerList.parse(header + row(ip: "-interface") + "\n" + row(ip: "1.2.3.4; reboot") + "\n").count, 0)
    }
    test("serverlist/records-protocol-of-the-listed-port") {
        let s = ServerList.parse(header + row(cfg: cfgUDP) + "\n" + row(host: "t", cfg: cfgTCP) + "\n")
        expectEqual(s[0].listedProto, "udp"); expectEqual(s[1].listedProto, "tcp")
    }
    test("serverlist/fetch-uses-the-mirror-first") {
        let srv = LocalHTTPServer(body: Data(fixture("vpngate-snapshot.csv").utf8)); defer { srv.stop() }
        let list = try await ServerList.fetch(mirror: srv.url)
        expectEqual(list.count, 10)
        expectEqual(srv.requests, 1, "default servers must not be contacted when the mirror answers")
        expectEqual(ServerList.defaultURLs.first?.scheme, "https")
    }

    // ServerFilter
    func servers() -> [VPNServer] {
        ServerList.parse(
            header
                + row(host: "jp1", ip: "1.1.1.1", op: "Alice", log: "2weeks") + "\n"
                + row(host: "kr1", ip: "2.2.2.2", op: "Bob", log: "1month", country: "Korea", short: "KR") + "\n"
                + row(host: "us1", ip: "3.3.3.3", op: "Carol", log: "no", country: "United States", short: "US") + "\n"
                + row(host: "xx1", ip: "4.4.4.4", op: "Dan", log: "weird", country: "Japan") + "\n")
    }
    test("filter/search-country-favorites") {
        var f = ServerFilter()
        expectEqual(f.apply(servers()).count, 4)
        f.search = "bob"; expectEqual(f.apply(servers()).map(\.hostName), ["kr1"])
        f.search = ""; f.country = "Japan"; expectEqual(f.apply(servers()).map(\.hostName), ["jp1", "xx1"])
        f.country = "All"; f.favoritesOnly = true; f.favorites = [servers()[2].id]
        expectEqual(f.apply(servers()).map(\.hostName), ["us1"])
    }
    test("filter/log-policy") {
        var f = ServerFilter()
        f.maxLogWeeks = 2; expectEqual(f.apply(servers()).map(\.hostName), ["jp1", "us1"])
        f.maxLogWeeks = 0; expectEqual(f.apply(servers()).map(\.hostName), ["us1"])
        f.maxLogWeeks = 8; expectEqual(f.apply(servers()).map(\.hostName), ["jp1", "kr1", "us1"])
    }
    test("filter/logWeeks-parsing") {
        expectEqual(ServerFilter.logWeeks("2weeks"), 2); expectEqual(ServerFilter.logWeeks("1week"), 1)
        expectEqual(ServerFilter.logWeeks("1month"), 5); expectEqual(ServerFilter.logWeeks("1year"), 52)
        expectEqual(ServerFilter.logWeeks("10days"), 2); expectEqual(ServerFilter.logWeeks("no"), 0)
        expectEqual(ServerFilter.logWeeks("???"), nil); expectEqual(ServerFilter.logWeeks(""), nil)
    }
}
