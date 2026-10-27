import Foundation

// The app's Codable mirrors (Model/IPCTypes.swift, ClientAccount.swift, ServerModel.swift) against the golden JSON that
// the engine's own tests are pinned to: what the daemon reads and writes, the app must read and write too.

private let goldenDir = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
    .appendingPathComponent("Fixtures/golden", isDirectory: true)

private func golden(_ name: String) throws -> [String: Any] {
    try JSONSerialization.jsonObject(with: Data(contentsOf: goldenDir.appendingPathComponent(name))) as! [String: Any]
}

private func cases(_ file: String, _ name: String) throws -> [String: Any] {
    let all = try golden(file)["cases"] as! [[String: Any]]
    return all.first { $0["name"] as? String == name }!
}

/// Decodes `json` as `T`, encodes it again and compares as JSON values (3 == 3.0, key order ignored).
private func roundTrips<T: Codable>(_ type: T.Type, _ json: Any, _ what: String) {
    do {
        let data = try JSONSerialization.data(withJSONObject: json)
        let back = try JSONSerialization.jsonObject(with: JSONEncoder().encode(JSONDecoder().decode(T.self, from: data)))
        expect(NSDictionary(dictionary: back as! [String: Any]).isEqual(to: json as! [String: Any]), "\(what): \(back) != \(json)")
    } catch { fail("\(what): \(error)") }
}

func registerMirrorTests() {
    test("mirror/ipc-constants") {
        let c = try cases("ipc.json", "constants")
        expectEqual(c["helperVersion"] as? Int, helperVersion); expectEqual(c["helperSocketPath"] as? String, helperSocketPath)
        expectEqual(c["defaultSocksPort"] as? Int, defaultSocksPort)
    }
    test("mirror/connect-config-and-requests-round-trip-the-golden-json") {
        for n in ["connect-config-default", "connect-config-full"] { roundTrips(ConnectConfig.self, try cases("ipc.json", n)["json"]!, n) }
        for r in try cases("ipc.json", "request-encode")["cases"] as! [[String: Any]] { roundTrips(HelperRequest.self, r, "request \(r["cmd"] ?? "")") }
        for d in try cases("ipc.json", "connect-config-decode")["cases"] as! [[String: Any]] {
            let input = Data((d["input"] as! String).utf8)
            if d["config"] == nil { expectThrows(try JSONDecoder().decode(ConnectConfig.self, from: input), "\(d["input"] ?? "")"); continue }
            let cfg = try JSONDecoder().decode(ConnectConfig.self, from: input)
            roundTrips(ConnectConfig.self, d["config"]!, "decode \(d["input"] ?? "")")
            expectEqual(cfg.host, (d["config"] as! [String: Any])["host"] as? String)
        }
    }
    test("mirror/request-and-event-decoding-accepts-and-rejects-what-the-engine-does") {
        for d in try cases("ipc.json", "request-decode")["cases"] as! [[String: Any]] {
            let input = Data((d["input"] as! String).utf8)
            if d["error"] as? Bool == true {
                expectThrows(try JSONDecoder().decode(HelperRequest.self, from: input), "\(d["input"] ?? "")")
            } else {
                let r = try JSONDecoder().decode(HelperRequest.self, from: input)
                roundTrips(HelperRequest.self, d["request"]!, "request \(d["input"] ?? "")");
                expectEqual(r.cmd, (d["request"] as! [String: Any])["cmd"] as? String)
            }
        }
        for d in try cases("ipc.json", "event-decode")["cases"] as! [[String: Any]] {
            let input = Data((d["input"] as! String).utf8)
            if d["error"] as? Bool == true {
                // `extra` keys are ignored by Swift; only the missing/invalid state or counters are errors.
                if (d["input"] as! String).contains("extra") { continue }
                expectThrows(try JSONDecoder().decode(HelperEvent.self, from: input), "\(d["input"] ?? "")")
            } else {
                roundTrips(HelperEvent.self, d["event"]!, "event \(d["input"] ?? "")")
            }
        }
        for e in try cases("ipc.json", "event-encode")["events"] as! [[String: Any]] { roundTrips(HelperEvent.self, e, "event") }
    }
    test("mirror/accounts-round-trip-the-golden-file-format") {
        for n in ["encode-minimal", "encode-full-strips-proxy-password"] { roundTrips(ClientAccount.self, try cases("account.json", n)["json"]!, n) }
        for d in try cases("account.json", "decode")["cases"] as! [[String: Any]] where d["error"] == nil {
            if d["datesDefaulted"] as? Bool == true { continue }
            roundTrips(ClientAccount.self, d["account"]!, "decode \(d["input"] ?? "")")
        }
    }
    test("mirror/servers-round-trip-and-order-ports-like-the-engine") {
        let e = try cases("serverlist.json", "server-json-encode")
        roundTrips(VPNServer.self, e["server"]!, "server")
        let s = try JSONDecoder().decode(VPNServer.self, from: JSONSerialization.data(withJSONObject: e["server"]!))
        expectEqual(s.prioritizedSslPorts.map(Int.init), e["prioritizedSslPorts"] as! [Int]); expectEqual(s.connectPort, e["connectPort"] as? Int)
        expectEqual(s.flag, e["flag"] as? String)
        for c in try cases("serverlist.json", "port-priority")["cases"] as! [[String: Any]] {
            expectEqual(VPNServer.portPriority((c["ports"] as! [Int]).map(UInt16.init)).map(Int.init), c["result"] as! [Int])
        }
    }
    test("mirror/v9-replies-decode-the-shapes-in-IPC-md") {
        let list = #"""
            {"reply":"refreshServers","id":3,"ok":true,"result":{"servers":[{"hostName":"vpn1","ip":"1.2.3.4","fqdn":"vpn1.example","sslPorts":[995,443]}],
            "source":"Relay P2P","timestampMs":1700000000000,"isFresh":true,"outcome":"synced","nextPollSeconds":1800.5}}
            """#
        let r = try JSONDecoder().decode(HelperReply.self, from: Data(list.utf8))
        expect(r.ok); expectEqual(r.id, 3)
        let res = try r.decode(ServerListResult.self)
        expectEqual(res.servers.count, 1); expectEqual(res.source, .relaySync); expectEqual(res.outcome, .synced)
        expectEqual(res.timestamp, Date(timeIntervalSince1970: 1_700_000_000)); expectEqual(res.nextPollSeconds, 1800.5)
        expectEqual(res.servers[0].prioritizedSslPorts, [443, 995])

        let probe =
            #"{"reply":"probe","id":4,"ok":true,"result":{"results":[{"host":"1.2.3.4","ok":true,"port":443,"connectMs":40,"helloMs":90,"build":9807},{"host":"5.6.7.8","ok":false,"error":"No answer in 5 s"}]}}"#
        let p = try JSONDecoder().decode(HelperReply.self, from: Data(probe.utf8)).decode(ProbeResultList.self).results
        expectEqual(p[0].outcome, .ok(port: 443, connectMs: 40, helloMs: 90, build: 9807)); expectEqual(p[1].outcome, .failed("No answer in 5 s"))

        let bad = try JSONDecoder().decode(HelperReply.self, from: Data(#"{"reply":"listServers","id":1,"ok":false,"error":"nope"}"#.utf8))
        expect(!bad.ok); expectEqual(bad.error, "nope")
        // an event is not a reply, and a reply is not an event
        expectThrows(try JSONDecoder().decode(HelperReply.self, from: Data(#"{"state":"connected","bytesIn":0,"bytesOut":0}"#.utf8)))
        expectThrows(try JSONDecoder().decode(HelperEvent.self, from: Data(list.utf8)))
    }
}
