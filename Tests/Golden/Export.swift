import CryptoKit
import Foundation
import VPNGateCore

// Golden vectors for the Rust/C#/Kotlin ports: every case is an input and the exact output the Swift code produces.
// `scripts/gen-golden.sh` writes them to Tests/Fixtures/golden/*.json; `Tests/Unit/GoldenTests.swift` fails when a
// regeneration would change them. Bytes are lowercase hex. Objects have sorted keys, so the files are deterministic.
//
// A case with `"byteExact": false` must be checked by round trip, not by comparing bytes (zlib output differs between
// implementations of the same format).

typealias GJ = [String: Any]

private func gHex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
private func gHex(_ d: Data) -> String { gHex([UInt8](d)) }
private func gBytes(_ s: String) -> [UInt8] { Array(s.utf8) }
private func gErrName(_ e: Error) -> String { String(describing: e) }

/// Codable value to a plain JSON object, with the encoder's own key set (what the IPC / account file carries).
private func gCodable<T: Encodable>(_ v: T) -> Any {
    let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]
    return (try? JSONSerialization.jsonObject(with: e.encode(v), options: [.fragmentsAllowed])) ?? NSNull()
}

private func render(_ module: String, _ note: String, _ cases: [GJ]) throws -> (name: String, data: Data) {
    let doc: GJ = ["module": module, "note": note, "cases": cases]
    var d = try JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    d.append(10)
    return ("\(module).json", d)
}

func goldenFiles(fixturesDir: URL) throws -> [(name: String, data: Data)] {
    [
        try render("pack", "serialize = encode; parse = decode. error = PackError case.", packCases()),
        try render("httphead", "HTTPHead.parse over the header block (bytes before the blank line).", httpCases()),
        try render("validation", "InputValidation: one entry per function, each input with its result (null = nil).", validationCases()),
        try render("softether_error", "SoftEtherError.describe for every code 0...150 plus out-of-range codes.", errorCases()),
        try render("crypto", "RC4 and SHA-0.", cryptoCases()),
        try render("vgdat", "VGDat over Tests/Fixtures/VPNGate.dat, probes, zlib inflate, tunables.", try vgdatCases(fixturesDir)),
        try render("serverlist", "ServerList.parse, ListFormat, ports and ServerFilter.", try serverListCases(fixturesDir)),
        try render("routing", "RoutingRule validation and RoutingMatcher. Regexes are limited to the ICU/Rust-common subset.", routingCases()),
        try render("dataphase", "DataPhase encode and incremental decode.", dataPhaseCases()),
        try render("udpaccel", "UdpAccelPacket with fixed key, IV and ticks.", udpAccelCases()),
        try render("certpin", "CertPin and ServerCertPolicy.", certPinCases()),
        try render("packets", "ARP, IPv4, UDP, DHCP, IPv6 and ICMPv6 builders and parsers.", packetCases()),
        try render("account", "ClientAccount JSON (file format) and toConnectConfig.", accountCases()),
        try render("ipc", "ConnectConfig, HelperRequest and HelperEvent JSON. helperVersion = \(helperVersion).", ipcCases()),
    ]
}

// MARK: - pack

private func packCases() -> [GJ] {
    var out: [GJ] = []
    func ser(_ name: String, _ p: Pack) {
        out.append(["name": name, "op": "serialize", "elements": p.elements.map(describe), "hex": gHex(p.serialize())])
    }
    func describe(_ e: Pack.Element) -> GJ {
        let vals: [GJ] = e.values.map { v in
            switch v {
            case .int(let n): return ["int": n]
            case .data(let d): return ["data": gHex(d)]
            case .str(let s): return ["str": s]
            case .unistr(let s): return ["unistr": s]
            case .int64(let n): return ["int64": n]
            }
        }
        return ["name": e.name, "values": vals]
    }
    var p = Pack(); p.addInt("a", 1); p.addStr("s", "hi"); ser("int-and-str", p)
    p = Pack(); p.addUni("u", "é"); p.addInt64("l", 0x0102030405060708); ser("unistr-and-int64", p)
    p = Pack()
    p.addInt("i", 0xdeadbeef); p.addData("d", Data([1, 2, 3])); p.addStr("s", "héllo")
    p.addUni("u", "ünï"); p.addInt64("l", 0x1122334455667788); p.addIPv4("ip", 0x0a000001)
    p.addBool("b", true); ser("all-types", p)
    p = Pack(); p.addInt("HubName", 1); p.addInt("hubname", 2); ser("duplicate-name-replaced", p)
    p = Pack(); p.addInts("Port", [443, 992, 5555]); p.addData("empty", Data()); ser("multi-value-and-empty", p)

    func parse(_ name: String, _ d: Data) {
        do {
            let r = try Pack(parsing: d)
            out.append(["name": name, "op": "parse", "hex": gHex(d), "elements": r.elements.map(describe), "reserialized": gHex(r.serialize())])
        } catch { out.append(["name": name, "op": "parse", "hex": gHex(d), "error": gErrName(error)]) }
    }
    parse("roundtrip", p.serialize())
    var full = Pack(); full.addStr("s", "hello")
    let fb = full.serialize()
    for n in 0..<fb.count { parse("truncated-\(n)", fb.prefix(n)) }
    parse("bad-type", Data([0, 0, 0, 1, 0, 0, 0, 2, 0x61, 0, 0, 0, 9, 0, 0, 0, 1, 0, 0, 0, 0]))
    parse("name-length-zero", Data([0, 0, 0, 1, 0, 0, 0, 0]))
    parse("name-length-256", Data([0, 0, 0, 1, 0, 0, 1, 0]))
    parse("huge-element-count", Data([0xff, 0xff, 0xff, 0xff]))
    parse("huge-value-count", Data([0, 0, 0, 1, 0, 0, 0, 2, 0x61, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff]))
    parse("unistr-without-nul", Data([0, 0, 0, 1, 0, 0, 0, 2, 0x61, 0, 0, 0, 3, 0, 0, 0, 1, 0, 0, 0, 2, 0x68, 0x69]))
    return out
}

// MARK: - httphead

private func httpCases() -> [GJ] {
    let inputs = [
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 12",
        "HTTP/1.1 404 Not Found",
        "HTTP/1.0 302 Found\r\nLocation: https://x/y\r\nX-Odd:   spaced value  \r\nno-colon-line\r\nSet-Cookie: a=b: c",
        "garbage",
        "HTTP/1.1 abc\r\nA: 1",
        "HTTP/1.1 200\r\nA: 1\r\na: 2",
        "",
    ]
    return inputs.map { s in
        let h = HTTPHead.parse(gBytes(s))
        return ["name": "head", "hex": gHex(gBytes(s)), "status": h.status, "headers": h.headers, "statusCode": h.statusCode as Any? ?? NSNull()]
    }
}

// MARK: - validation

private func validationCases() -> [GJ] {
    func table<T>(_ fn: String, _ inputs: [String], _ f: (String) -> T?) -> GJ {
        ["function": fn, "cases": inputs.map { ["input": $0, "result": f($0) as Any? ?? NSNull()] as GJ }]
    }
    let hosts = [
        "example.com", "a", "1.2.3.4", "256.1.1.1", "1.2.3", "1.2.3.4.5", "-bad", "bad-", ".bad", "bad.", "a..b", "a b", "ü.com",
        "UPPER.Case.org", "123", "1.2.3.", "01.02.03.04", "host_name", String(repeating: "a", count: 253), String(repeating: "a", count: 254), "",
        "localhost",
    ]
    let ips = [
        "127.0.0.1", "127.255.255.255", "169.254.1.1", "169.254", "0.0.0.0", "10.0.0.1", "8.8.8.8", "localhost", "LOCALHOST", "example.com", "172.15.0.1",
    ]
    let nonPublic = [
        "10.1.2.3", "172.16.0.1", "172.31.255.255", "172.32.0.1", "172.15.0.1", "192.168.1.1", "192.169.1.1", "169.254.0.1", "127.0.0.1", "0.0.0.0", "8.8.8.8",
        "abc",
    ]
    let fps = [
        String(repeating: "ab", count: 20), String(repeating: "AB", count: 32), (0..<20).map { String(format: "%02X", $0) }.joined(separator: ":"),
        (0..<20).map { String(format: "%02x", $0) }.joined(separator: " "), (0..<20).map { String(format: "%02x", $0) }.joined(separator: "-"),
        "abc", String(repeating: "zz", count: 20), String(repeating: "a", count: 41), "",
    ]
    let macs = [
        "aa:bb:cc:dd:ee:ff", "AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee", "aa:bb:cc:dd:ee:ff:00", "gg:bb:cc:dd:ee:ff", "a:b:c:d:e:f", "100:bb:cc:dd:ee:ff", "",
        "aa:bb-cc:dd-ee:ff",
    ]
    let idents = [
        "hub", "", String(repeating: "x", count: 255), String(repeating: "x", count: 256), "nul\u{0}byte", "ünï", String(repeating: "é", count: 127),
        String(repeating: "é", count: 128),
    ]
    let iplits = [
        "1.2.3.4", "::1", "2001:db8::1", "fe80::1", "1.2.3.4/24", "::1/128", "1.2.3", "gggg::", "::ffff:1.2.3.4", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8:9", "",
    ]
    return [
        table("isIPv4Literal", hosts + ips, InputValidation.isIPv4Literal),
        table("isValidHost", hosts, InputValidation.isValidHost),
        table("isLocalAddress", ips, InputValidation.isLocalAddress),
        table("isNonPublicIPv4", nonPublic, InputValidation.isNonPublicIPv4),
        table("normalizedFingerprint", fps, InputValidation.normalizedFingerprint),
        table("parseMacAddress", macs) { InputValidation.parseMacAddress($0).map(gHex) },
        table("isValidIdentityField", idents, InputValidation.isValidIdentityField),
        table("isIPLiteral", iplits, InputValidation.isIPLiteral),
        [
            "function": "isValidPort",
            "cases": [-1, 0, 1, 80, 65535, 65536].map { ["input": $0, "result": InputValidation.isValidPort($0)] as GJ } + [
                ["input": NSNull(), "result": false] as GJ
            ],
        ],
    ]
}

// MARK: - softether_error

private func errorCases() -> [GJ] {
    ((-1)...150).map { c in
        let i = SoftEtherError.info(for: c)
        return ["code": c, "describe": SoftEtherError.describe(c), "name": i?.name as Any? ?? NSNull(), "message": i?.message as Any? ?? NSNull()]
    } + [10_000, Int(Int32.max)].map { ["code": $0, "describe": SoftEtherError.describe($0), "name": NSNull(), "message": NSNull()] }
}

// MARK: - crypto

private func cryptoCases() -> [GJ] {
    let seqKey = (0..<16).map(UInt8.init)
    let longData = (0..<1000).map { UInt8(truncatingIfNeeded: $0 &* 7 &+ 3) }
    let rc4: [GJ] = [
        (gBytes("Key"), gBytes("Plaintext")), (gBytes("Wiki"), gBytes("pedia")), (gBytes("Secret"), gBytes("Attack at dawn")),
        (seqKey, longData), ([0], []), ([0xff], [UInt8](repeating: 0, count: 300)), ([], gBytes("empty key is a no-op")),
        ([UInt8](repeating: 0x5a, count: 300), longData),  // key longer than the 256-byte state
    ].map { ["key": gHex($0.0), "input": gHex($0.1), "output": gHex(RC4.cipher(key: $0.0, data: $0.1))] }
    let sha0: [GJ] =
        ([0, 1, 3, 55, 56, 57, 63, 64, 65, 119, 120, 128, 1000].map { n in (0..<n).map { UInt8(truncatingIfNeeded: $0 &* 31 &+ 7) } }
        + [gBytes("abc"), gBytes("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")])
        .map { ["input": gHex($0), "digest": gHex(SHA0.hash($0))] }
    return [["name": "rc4", "cases": rc4], ["name": "sha0", "cases": sha0]]
}

// MARK: - vgdat

private func vgdatCases(_ dir: URL) throws -> [GJ] {
    let url = dir.appendingPathComponent("VPNGate.dat")
    let data = try Data(contentsOf: url)
    var out: [GJ] = []
    let first = try VGDat.parse(data: data)
    let now = Date(timeIntervalSince1970: Double(first.timestampMs) / 1000.0 + 3600)
    let f = try VGDat.parse(data: data, now: now)
    out.append([
        "name": "fixture", "file": "VPNGate.dat", "nowMs": first.timestampMs + 3_600_000, "headerText": f.headerText, "soapURL": f.soapURL,
        "timestampMs": f.timestampMs, "isSignatureValid": f.isSignatureValid, "isFresh": f.isFresh, "serverCount": f.servers.count,
        "servers": f.servers.map { gCodable($0) }, "innerPackElementNames": f.rawInnerPack.elements.map(\.name),
    ])
    let stale = try VGDat.parse(data: data, now: Date(timeIntervalSince1970: Double(first.timestampMs) / 1000.0 + 37 * 3600))
    out.append(["name": "freshness-37h", "nowMs": first.timestampMs + 37 * 3_600_000, "isFresh": stale.isFresh])
    let edge = try VGDat.parse(data: data, now: Date(timeIntervalSince1970: Double(first.timestampMs) / 1000.0 + 36 * 3600))
    out.append(["name": "freshness-36h", "nowMs": first.timestampMs + 36 * 3_600_000, "isFresh": edge.isFresh])

    // Mutations the Rust side applies to the fixture bytes; the expected result is the Swift error.
    func mutated(_ name: String, _ m: String, _ d: Data) {
        do { _ = try VGDat.parse(data: d, now: now); out.append(["name": name, "mutation": m, "error": NSNull()]) } catch {
            out.append(["name": name, "mutation": m, "error": gErrName(error)])
        }
    }
    mutated("truncated-header", "truncate:100", data.prefix(100))
    mutated("truncated-mid-body", "truncate:2000", data.prefix(2000))
    mutated("truncated-last-byte", "truncate:\(data.count - 1)", data.prefix(data.count - 1))
    var bad = data; bad[0] = 0x58; mutated("bad-magic", "set:0=88", bad)
    for off in [0x104, 0x200, 0x1000, data.count - 1] {
        var m = data; m[off] ^= 0x01
        mutated("flip-bit-\(off)", "xor:\(off)=1", m)
    }
    var seed = data; seed[0xF0] ^= 0xff; mutated("flip-seed", "xor:240=255", seed)

    // Probe: 16 bytes = ts(8) + SHA0^3(SHA1(ts))[..8]
    for ts: UInt64 in [0, 1, 1_700_000_000_000, 0x0102030405060708, UInt64.max] {
        out.append(["name": "probe", "timestampMs": ts, "probe": gHex(VGDat.generateProbe(timestampMs: ts))])
    }
    let probeTs: UInt64 = 1_700_000_000_000
    let probe = VGDat.generateProbe(timestampMs: probeTs)
    var tampered = probe; tampered[15] ^= 1
    for (n, p, nowMs) in [
        ("verify-ok", probe, probeTs), ("verify-ok-35h", probe, probeTs + 35 * 3_600_000), ("verify-too-old", probe, probeTs + 37 * 3_600_000),
        ("verify-future-ok", probe, probeTs - 3_600_000), ("verify-future-too-far", probe, probeTs - 40 * 3_600_000), ("verify-tampered", tampered, probeTs),
        ("verify-short", Array(probe.prefix(15)), probeTs), ("verify-long", probe + [0], probeTs),
    ] {
        out.append(["name": n, "probe": gHex(p), "nowMs": nowMs, "valid": VGDat.verifyProbe(p, now: Date(timeIntervalSince1970: Double(nowMs) / 1000.0))])
    }

    // zlib inflate: stream = 0x78 header + deflate + adler32
    let plain = [UInt8](Array(repeating: gBytes("hello vpngate "), count: 20).joined())
    let z: [UInt8] = [
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0x2b, 0xc8, 0x4b, 0x4f, 0x2c, 0x49, 0x55, 0xc8, 0x18, 0xe5, 0x41, 0x79, 0x00, 0x25, 0x32, 0x69,
        0xb5,
    ]
    var badAdler = z; badAdler[badAdler.count - 1] ^= 1
    var badHeader = z; badHeader[1] = 0x9d
    var dict = z; dict[1] = 0xbb  // FDICT set (0x7800 | 0xbb is a multiple of 31)
    for (n, input, size) in [
        ("inflate-ok", z, plain.count), ("inflate-size-too-small", z, plain.count - 1), ("inflate-size-too-large", z, plain.count + 1),
        ("inflate-bad-adler", badAdler, plain.count),
        ("inflate-bad-header", badHeader, plain.count), ("inflate-preset-dict", dict, plain.count), ("inflate-too-short", Array(z.prefix(5)), plain.count),
        ("inflate-zero-size", z, 0), ("inflate-over-max", z, VGDat.maxInflatedSize + 1),
    ] {
        do { out.append(["name": n, "input": gHex(input), "expectedSize": size, "output": gHex(try VGDat.decompress(data: input, expectedSize: size))]) } catch
        { out.append(["name": n, "input": gHex(input), "expectedSize": size, "error": gErrName(error)]) }
    }

    // Tunables: DynList = Pack of name -> int64
    var dyn = Pack(); dyn.addInt64("ConnectTimeout", 10_000); dyn.addInt64("Zero", 0); dyn.addInt64("Huge", UInt64.max); dyn.addInt64("Tiny", 1)
    dyn.addInt("NotInt64", 7); dyn.addInt64("MixedCase", 5000)
    let t = VGTunables(dynList: dyn.serialize())
    var older = VGTunables();
    older.merge(
        VGTunables(
            dynList: {
                var p = Pack(); p.addInt64("a", 100); p.addInt64("b", 200); return p.serialize()
            }()))
    older.merge(
        VGTunables(
            dynList: {
                var p = Pack(); p.addInt64("B", 300); return p.serialize()
            }()))
    out.append([
        "name": "tunables", "dynList": gHex(dyn.serialize()),
        "values": t.values,
        "lookups": [
            ("connecttimeout", 5000), ("CONNECTTIMEOUT", 5000), ("Zero", 5000), ("Missing", 5000), ("Huge", 5000), ("Tiny", 5000), ("MixedCase", 1000),
            ("MixedCase", 100_000), ("Huge", UInt64.max / 10),
        ]
        .map { (n: String, d: UInt64) -> GJ in ["name": n, "default": d, "value": t.value(n, default: d), "seconds": t.seconds(n, defaultMs: d)] },
        "unparseable": VGTunables(dynList: Data([1, 2, 3])).values,
        "merged": older.values,
    ])
    return out
}

// MARK: - serverlist

private func serverListCases(_ dir: URL) throws -> [GJ] {
    var out: [GJ] = []
    let csv = try String(contentsOf: dir.appendingPathComponent("vpngate-snapshot.csv"), encoding: .utf8)
    let servers = ServerList.parse(csv)
    out.append(["name": "parse-snapshot", "file": "vpngate-snapshot.csv", "count": servers.count, "servers": servers.map { gCodable($0) }])

    func b64(_ s: String) -> String { Data(s.utf8).base64EncodedString() }
    let cfg = "client\r\nproto tcp\r\nremote 1.2.3.4 1443\r\n"
    let line = { (f: [String]) in f.joined(separator: ",") }
    let base = ["h1", "1.2.3.4", "100", "5", "1000", "Japan", "JP", "3", "60000", "10", "2000", "2weeks", "op", "msg"]
    let lines = [
        "*vpn_servers", "#HostName,IP,...", "", line(base + [b64(cfg)]),
        line(base.dropLast() + ["a,b,c", b64("proto udp\nremote 5.6.7.8 1194\n")]),  // commas in the message
        line(base + ["!!!not base64"]), line(base + [b64("remote 1.1.1.1 0\nproto tcp-client\n")]),
        line(base + [b64("remote 1.1.1.1 70000\n")]), line(base + [b64("remote x\nproto\n")]),
        line(["h2", "not.an.ip"] + base.dropFirst(2) + [b64(cfg)]), line(["h3", "9.9.9.9", "x", "y", "z"] + base.dropFirst(5) + [b64(cfg)]),
        "short,1.2.3.4,1", line(["", "4.4.4.4"] + base.dropFirst(2) + [b64(cfg)]),
        "# comment", line(base + [b64(cfg)]) + "\r",
    ]
    out.append([
        "name": "parse-edge-lines", "csv": lines.joined(separator: "\n"), "servers": ServerList.parse(lines.joined(separator: "\n")).map { gCodable($0) },
    ])
    out.append([
        "name": "parse-crlf", "csv": lines.joined(separator: "\r\n"), "servers": ServerList.parse(lines.joined(separator: "\r\n")).map { gCodable($0) },
    ])

    // VPNServer JSON, including the old `tcpPort` key and missing optional fields
    let legacy = ["{\"hostName\":\"old\",\"ip\":\"1.1.1.1\",\"tcpPort\":995}", "{\"hostName\":\"min\",\"ip\":\"2.2.2.2\"}", "{\"ip\":\"3.3.3.3\"}"]
    out.append([
        "name": "server-json-decode",
        "cases": legacy.map { s -> GJ in
            guard let v = try? JSONDecoder().decode(VPNServer.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            return ["input": s, "server": gCodable(v), "connectPort": v.connectPort as Any? ?? NSNull()]
        },
    ])
    let full = VPNServer(
        hostName: "vpn1", ip: "1.2.3.4", score: 9, ping: 2, speed: 3, countryLong: "Japan", countryShort: "jp", sessions: 4, uptimeMs: 5, totalUsers: 6,
        totalTraffic: 7,
        logType: "2weeks", operatorName: "op", message: "m", listedPort: 1443, listedProto: "tcp", fqdn: "vpn1.opengw.net",
        sslPorts: [22, 995, 443, 1443, 992], udpPort: 4000,
        openVpnUdpPorts: [1194], l2tp: true, os: "Linux", soft: "v4.43", build: 9800, owner: "o", abuse: "a@b", numLogin: 12, noLog: true, logPermanent: false,
        name: "n", pingToGoogle: 8, sendSize: 10, recvSize: 11, isKernelModeNAT: true)
    out.append([
        "name": "server-json-encode", "server": gCodable(full), "flag": full.flag, "prioritizedSslPorts": full.prioritizedSslPorts.map(Int.init),
        "connectPort": full.connectPort as Any? ?? NSNull(),
    ])

    // Ports
    let portSets: [[UInt16]] = [[], [443], [22, 993, 443], [1443, 5555], [5555, 22, 995, 1443, 443, 992, 465, 585, 993], [0], [443, 443]]
    out.append(["name": "port-priority", "cases": portSets.map { ["ports": $0.map(Int.init), "result": VPNServer.portPriority($0).map(Int.init)] as GJ }])
    func srv(_ ssl: [UInt16], listed: Int) -> VPNServer { VPNServer(hostName: "x", ip: "1.1.1.1", listedPort: listed, sslPorts: ssl) }
    out.append([
        "name": "connect-port",
        "cases": [([UInt16](), 0), ([], 443), ([], 70000), ([], -1), ([22], 1194), ([0], 995), ([0, 995], 1)]
            .map { (p, l) in ["sslPorts": p.map(Int.init), "listedPort": l, "result": srv(p, listed: l).connectPort as Any? ?? NSNull()] as GJ },
    ])
    out.append([
        "name": "flag",
        "cases": ["jp", "US", "", "x", "123", "ΩΩ"].map { ["countryShort": $0, "flag": VPNServer(hostName: "h", ip: "1.1.1.1", countryShort: $0).flag] as GJ },
    ])

    // ListFormat
    let ups = [
        -5, 0, 59_999, 60_000, 119_999, 3_599_999, 3_600_000, 3_600_001, 3_660_000, 7_200_000, 86_399_999, 86_400_000, 86_400_001, 172_800_000, 31_536_000_000,
    ]
    out.append(["name": "format-uptime", "cases": ups.map { ["ms": $0, "text": ListFormat.uptime(ms: $0)] as GJ }])
    out.append(["name": "format-sessions", "cases": [0, 1, 2, 1000].map { ["n": $0, "text": ListFormat.sessions($0)] as GJ }])
    out.append(["name": "format-logins", "cases": [0, 1, 2, 999, 1000, 1_234_567, -1234].map { ["n": $0, "text": ListFormat.logins($0)] as GJ }])
    out.append([
        "name": "format-logging",
        "cases": ["", "no", "No", "none", "2weeks", "2 weeks", "12weeks", "permanent", "Perm", "3months", "x"].map {
            ["logType": $0, "text": ListFormat.logging($0)] as GJ
        },
    ])
    out.append([
        "name": "format-pings",
        "cases": [(0, 0), (5, 0), (0, 7), (12, 34)].map { ["google": $0.0, "japan": $0.1, "text": ListFormat.pings(google: $0.0, japan: $0.1)] as GJ },
    ])
    out.append([
        "name": "format-udp",
        "cases": [nil, 0, 4000].map { (p: Int?) -> GJ in ["port": p as Any? ?? NSNull(), "text": ListFormat.udp(p.map { UInt16($0) })] },
    ])
    let t0 = Date(timeIntervalSince1970: 1_700_000_000)
    out.append([
        "name": "format-list-ok",
        "cases": [0.0, 86_399.0, 86_400.0, 86_400.001, -86_399.0, -90_000.0].map { d in
            ["ageSeconds": d, "ok": ListFormat.isListOK(timestamp: t0, now: t0.addingTimeInterval(d))] as GJ
        },
    ])

    // logWeeks
    let lw = [
        "no", "None", "nolog", "0", "2weeks", "2 weeks", "1week", "1day", "7days", "8days", "3months", "1 month", "12months", "1year", "2years", "", "abc",
        "10", "5 fortnights", " 4weeks ",
    ]
    out.append(["name": "log-weeks", "cases": lw.map { ["input": $0, "weeks": ServerFilter.logWeeks($0) as Any? ?? NSNull()] as GJ }])

    // ServerFilter: localizedCaseInsensitiveContains is the Swift behaviour the ports must match (case + diacritic-insensitive is NOT guaranteed; recorded as is)
    let pool = [
        VPNServer(hostName: "tokyo-1", ip: "1.1.1.1", countryLong: "Japan", logType: "2weeks", operatorName: "Alice"),
        VPNServer(hostName: "osaka-2", ip: "2.2.2.2", countryLong: "Japan", logType: "no", operatorName: "Müller"),
        VPNServer(hostName: "seoul-3", ip: "3.3.3.3", countryLong: "Korea Republic of", logType: "3months", operatorName: "bob"),
        VPNServer(hostName: "NYC-4", ip: "4.4.4.4", countryLong: "United States", logType: "permanent", operatorName: "Carol"),
        VPNServer(hostName: "paris-5", ip: "5.5.5.5", countryLong: "France", logType: "", operatorName: "ÉLODIE"),
    ]
    func filter(_ name: String, _ mut: (inout ServerFilter) -> Void, _ desc: GJ) {
        var f = ServerFilter(); mut(&f)
        out.append(["name": "filter-" + name, "params": desc, "result": f.apply(pool).map(\.hostName)])
    }
    out.append(["name": "filter-pool", "servers": pool.map { gCodable($0) }])
    filter("none", { _ in }, [:])
    filter("search-host", { $0.search = "tok" }, ["search": "tok"])
    filter("search-case", { $0.search = "NYC" }, ["search": "NYC"])
    filter("search-ip", { $0.search = "3.3" }, ["search": "3.3"])
    filter("search-country", { $0.search = "korea" }, ["search": "korea"])
    filter("search-operator-umlaut", { $0.search = "MÜLLER" }, ["search": "MÜLLER"])
    filter("search-operator-accent-fold", { $0.search = "elodie" }, ["search": "elodie"])
    filter("search-none", { $0.search = "zzz" }, ["search": "zzz"])
    filter("country", { $0.country = "Japan" }, ["country": "Japan"])
    filter("country-all", { $0.country = "All" }, ["country": "All"])
    filter(
        "favorites",
        {
            $0.favoritesOnly = true; $0.favorites = ["osaka-2", "NYC-4", "gone"]
        }, ["favoritesOnly": true, "favorites": ["osaka-2", "NYC-4", "gone"]])
    filter("favorites-empty", { $0.favoritesOnly = true }, ["favoritesOnly": true, "favorites": [String]()])
    filter("max-log-0", { $0.maxLogWeeks = 0 }, ["maxLogWeeks": 0])
    filter("max-log-2", { $0.maxLogWeeks = 2 }, ["maxLogWeeks": 2])
    filter("max-log-13", { $0.maxLogWeeks = 13 }, ["maxLogWeeks": 13])
    filter(
        "combined",
        {
            $0.country = "Japan"; $0.maxLogWeeks = 2; $0.search = "o"
        }, ["country": "Japan", "maxLogWeeks": 2, "search": "o"])
    return out
}

// MARK: - routing

/// Rule identity without its id: the generated private-network rules get a random UUID.
private func gMatched(_ r: RoutingRule?) -> Any {
    r.map { ["type": $0.type.rawValue, "value": $0.value, "action": $0.action.rawValue] as GJ } ?? NSNull()
}

private let gFixedIDs = (1...30).map { UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", $0))! }

private func routingCases() -> [GJ] {
    var out: [GJ] = []
    let valid: [(RoutingRuleType, String)] = [
        (.domainSuffix, "example.com"), (.domainSuffix, " example.com "), (.domainSuffix, ".example.com"), (.domainSuffix, "example.com."),
        (.domainSuffix, "a..b"), (.domainSuffix, "exa mple.com"),
        (.domainSuffix, "ünï.com"), (.domainSuffix, ""), (.domainSuffix, "   "), (.domainFull, "www.example.com"), (.domainFull, "under_score.com"),
        (.domainKeyword, "anything at all"),
        (.domainKeyword, ""), (.domainRegex, "^(a|b)+\\.example\\.com$"), (.domainRegex, "("), (.domainRegex, "["), (.domainRegex, "*abc"), (.domainRegex, ""),
        (.ip, "1.2.3.4"),
        (.ip, "::1"), (.ip, "1.2.3.4/8"), (.ip, "999.1.1.1"), (.ip, "2001:db8::1"), (.ip, "fe80::1%en0"), (.cidr, "10.0.0.0/8"), (.cidr, "10.0.0.0"),
        (.cidr, "10.0.0.0/33"), (.cidr, "::/0"),
        (.cidr, "2001:db8::/129"), (.cidr, "2001:db8::/32"), (.cidr, "1.2.3.4/-1"), (.cidr, "1.2.3.4/x"), (.cidr, "1.2.3.4/8/9"), (.cidr, "0.0.0.0/0"),
    ]
    out.append([
        "name": "validation",
        "cases": valid.map { ["type": $0.0.rawValue, "value": $0.1, "error": RoutingRule.validationError(type: $0.0, value: $0.1) as Any? ?? NSNull()] as GJ },
    ])

    let rules: [RoutingRule] = [
        RoutingRule(id: gFixedIDs[0], type: .domainFull, value: "exact.example.com", action: .direct),
        RoutingRule(id: gFixedIDs[1], type: .domainSuffix, value: "example.com", action: .proxy),
        RoutingRule(id: gFixedIDs[2], type: .domainKeyword, value: "ads", action: .block),
        RoutingRule(id: gFixedIDs[3], type: .domainRegex, value: "^cdn[0-9]+\\.site\\.org$", action: .direct),
        RoutingRule(id: gFixedIDs[4], type: .ip, value: "8.8.8.8", action: .direct),
        RoutingRule(id: gFixedIDs[5], type: .cidr, value: "203.0.113.0/24", action: .block),
        RoutingRule(id: gFixedIDs[6], type: .cidr, value: "2001:db8::/32", action: .direct),
        RoutingRule(id: gFixedIDs[7], type: .domainSuffix, value: "disabled.net", action: .block, enabled: false),
        RoutingRule(id: gFixedIDs[8], type: .cidr, value: "10.1.0.0/16", action: .proxy),
        RoutingRule(id: gFixedIDs[9], type: .domainSuffix, value: "BAD..", action: .block),  // invalid value is skipped silently
        RoutingRule(id: gFixedIDs[10], type: .cidr, value: "garbage", action: .block),
    ]
    let configs: [(String, RoutingConfig)] = [
        ("rules-default-proxy", RoutingConfig(rules: rules)),
        ("rules-default-direct", RoutingConfig(rules: rules, defaultAction: .direct)),
        ("rules-bypass-private", RoutingConfig(rules: rules, defaultAction: .block, bypassPrivateNetworks: true)),
        ("empty", RoutingConfig()),
    ]
    let domains = [
        "exact.example.com", "EXACT.EXAMPLE.COM.", "example.com", "www.example.com", "notexample.com", "a.b.example.com", "tracker.ads.net", "ADS",
        "cdn12.site.org", "cdn.site.org", "xcdn1.site.org",
        "disabled.net", "www.disabled.net", "unknown.test", "", ".", "..example.com..",
    ]
    let ips = [
        "8.8.8.8", "8.8.8.9", "203.0.113.77", "203.0.114.1", "2001:db8::1", "2001:db9::1", "10.1.2.3", "10.2.2.3", "192.168.0.1", "127.0.0.1", "100.64.1.1",
        "172.16.5.5", "172.32.0.1", "169.254.9.9",
        "::1", "fe80::1", "fd00::1", "::ffff:1.2.3.4", "not an ip", "1.2.3.4/24", "",
    ]
    for (n, cfg) in configs {
        out.append([
            "name": n, "config": gCodable(cfg), "effectiveRules": cfg.effectiveRules.map { $0.value }, "isEmpty": cfg.isEmpty,
            "domain": domains.map { d -> GJ in
                ["input": d, "matched": gMatched(RoutingMatcher.match(domain: d, in: cfg)), "action": RoutingMatcher.action(domain: d, in: cfg).rawValue]
            },
            "ip": ips.map { i -> GJ in
                ["input": i, "matched": gMatched(RoutingMatcher.match(ip: i, in: cfg)), "action": RoutingMatcher.action(ip: i, in: cfg).rawValue]
            },
            "both": [("exact.example.com", "203.0.113.1"), ("unknown.test", "203.0.113.1"), ("unknown.test", "9.9.9.9"), ("tracker.ads.net", "8.8.8.8")].map {
                (d, i) -> GJ in
                ["domain": d, "ip": i, "action": RoutingMatcher.action(domain: d, ip: i, in: cfg).rawValue]
            },
        ])
    }
    out.append(["name": "private-ranges", "ranges": RoutingConfig.privateNetworkRanges])

    // Codable tolerance
    let jsons = [
        "{\"type\":\"cidr\",\"value\":\"10.0.0.0/8\",\"action\":\"direct\"}",
        "{\"id\":\"\(gFixedIDs[0].uuidString)\",\"type\":\"ip\",\"value\":\"1.1.1.1\",\"action\":\"block\",\"enabled\":false}",
        "{\"type\":\"nope\",\"value\":\"x\",\"action\":\"block\"}",
    ]
    out.append([
        "name": "rule-json",
        "cases": jsons.map { s -> GJ in
            guard let r = try? JSONDecoder().decode(RoutingRule.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            var c = r; if s.contains("\"id\"") == false { c.id = gFixedIDs[29] }
            return ["input": s, "idPresent": s.contains("\"id\""), "rule": gCodable(c)]
        },
    ])
    let cfgJsons = ["{}", "{\"rules\":[],\"defaultAction\":\"block\"}", "{\"bypassPrivateNetworks\":true}", "{\"defaultAction\":\"x\"}"]
    out.append([
        "name": "config-json",
        "cases": cfgJsons.map { s -> GJ in
            guard let c = try? JSONDecoder().decode(RoutingConfig.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            return ["input": s, "config": gCodable(c)]
        },
    ])
    return out
}

// MARK: - dataphase

private func dataPhaseCases() -> [GJ] {
    var out: [GJ] = []
    let frames: [[UInt8]] = [[], [1], Array(0..<60), (0..<1514).map { UInt8(truncatingIfNeeded: $0) }, [UInt8](repeating: 0xaa, count: 3200)]
    for (i, f) in frames.enumerated() { out.append(["name": "encode-single-\(i)", "frames": [gHex(f)], "hex": gHex(DataPhase.encode(frames: [f]))]) }
    out.append(["name": "encode-multi", "frames": [gHex(frames[1]), gHex(frames[2])], "hex": gHex(DataPhase.encode(frames: [frames[1], frames[2]]))])
    out.append(["name": "encode-none", "frames": [String](), "hex": gHex(DataPhase.encode(frames: []))])
    for junk in [[], [1, 2, 3], [UInt8](repeating: 9, count: 4095)] {
        out.append(["name": "keepalive-encode", "junk": gHex(junk), "hex": gHex(DataPhase.encodeKeepAlive(junk: junk))])
    }

    // zlib: compare by round trip only
    for (i, f) in [gBytes("hello vpngate "), Array(repeating: UInt8(7), count: 1400), frames[3], []].enumerated() {
        let z = try? DataPhase.compressFrame(f)
        out.append([
            "name": "compress-\(i)", "byteExact": false, "frame": gHex(f), "swiftCompressed": z.map(gHex) as Any? ?? NSNull(),
            "roundTrip": z.flatMap { try? DataPhase.uncompressFrame($0) }.map(gHex) as Any? ?? NSNull(),
        ])
    }
    let zfix: [UInt8] = [
        0x78, 0x9c, 0xcb, 0x48, 0xcd, 0xc9, 0xc9, 0x57, 0x28, 0x2b, 0xc8, 0x4b, 0x4f, 0x2c, 0x49, 0x55, 0xc8, 0x18, 0xe5, 0x41, 0x79, 0x00, 0x25, 0x32, 0x69,
        0xb5,
    ]
    for (n, input, maxLen) in [
        ("uncompress-ok", zfix, 4096), ("uncompress-small-buffer", zfix, 10), ("uncompress-garbage", [1, 2, 3, 4], 4096), ("uncompress-empty", [], 4096),
    ] {
        do { out.append(["name": n, "input": gHex(input), "maxLen": maxLen, "output": gHex(try DataPhase.uncompressFrame(input, maxLen: maxLen))]) } catch {
            out.append(["name": n, "input": gHex(input), "maxLen": maxLen, "error": gErrName(error)])
        }
    }

    // Decoder: chunks fed in order; result per feed, stops at the first error.
    func dec(_ name: String, compress: Bool = false, _ chunks: [[UInt8]]) {
        var d = DataPhaseDecoder(useCompress: compress)
        var steps: [GJ] = []
        for c in chunks {
            do {
                let items = try d.feed(c)
                steps.append([
                    "items": items.map { i -> GJ in
                        switch i {
                        case .frame(let f): return ["frame": gHex(f)];
                        case .keepAlive: return ["keepAlive": true]
                        }
                    }
                ])
            } catch { steps.append(["error": gErrName(error)]); break }
        }
        out.append(["name": "decode-" + name, "useCompress": compress, "chunks": chunks.map(gHex), "steps": steps])
    }
    let two = DataPhase.encode(frames: [frames[1], frames[2]])
    dec("whole", [two])
    dec("byte-by-byte", two.map { [$0] })
    dec("split-mid-frame", [Array(two.prefix(9)), Array(two.dropFirst(9))])
    dec("zero-count-skipped", [be32(0) + DataPhase.encode(frames: [frames[1]])])
    dec("keepalive", [DataPhase.encodeKeepAlive(junk: [1, 2, 3]) + two])
    dec(
        "keepalive-split",
        [Array(DataPhase.encodeKeepAlive(junk: [1, 2, 3, 4, 5]).prefix(6)), Array(DataPhase.encodeKeepAlive(junk: [1, 2, 3, 4, 5]).dropFirst(6))])
    dec("keepalive-too-long", [be32(0xFFFF_FFFF) + be32(4096)])
    dec("bad-block-count", [be32(4096)])
    dec("max-block-count-ok", [be32(4095)])
    dec("oversized-block", [be32(1) + be32(3201)])
    dec("max-block-ok", [be32(1) + be32(3200) + [UInt8](repeating: 1, count: 3200)])
    dec("empty-frame", [be32(1) + be32(0)])
    dec("after-error-state", [be32(4096), two])
    let cframes = (try? frames.prefix(3).map { try DataPhase.compressFrame($0) }) ?? []
    dec("compressed", compress: true, [DataPhase.encode(frames: cframes)])
    dec("compressed-bad-zlib", compress: true, [DataPhase.encode(frames: [[1, 2, 3]])])
    dec("compressed-keepalive", compress: true, [DataPhase.encodeKeepAlive(junk: [0])])
    return out
}

// MARK: - udpaccel

private func udpAccelCases() -> [GJ] {
    var out: [GJ] = []
    let key = (0..<32).map { UInt8($0 + 1) }
    let iv = (0..<12).map { UInt8(0xa0 + $0) }
    func enc(
        _ name: String, payload: [UInt8], cookie: UInt32 = 0xdeadbeef, my: UInt64 = 0x0102030405060708, your: UInt64 = 0x1112131415161718,
        compressed: Bool = false, pad: Int = 0, plain: Bool = false, key32: [UInt8]? = nil, iv: [UInt8]? = nil
    ) {
        let k = key32 ?? key, v = iv ?? (0..<12).map { UInt8(0xa0 + $0) }
        var c: GJ = [
            "name": name, "key": gHex(k), "iv": gHex(v), "cookie": cookie, "myTick": my, "yourTick": your, "compressed": compressed, "payload": gHex(payload),
            "padding": pad, "plainMode": plain,
        ]
        do {
            let r = try UdpAccelPacket.encode(
                key32: k, iv: v, cookie: cookie, myTick: my, yourTick: your, compressed: compressed, payload: payload, paddingSize: pad, plainMode: plain)
            c["packet"] = gHex(r.packet); c["nextIV"] = gHex(r.nextIV)
            let d = try UdpAccelPacket.decode(packet: r.packet, key32: k, plainMode: plain)
            c["decoded"] =
                [
                    "cookie": d.header.cookie, "myTick": d.header.myTick, "yourTick": d.header.yourTick, "size": d.header.size,
                    "compressed": d.header.compressed, "payload": gHex(d.payload),
                ] as GJ
        } catch { c["error"] = gErrName(error) }
        out.append(c)
    }
    enc("empty-keepalive", payload: [])
    enc("small", payload: gBytes("hello"))
    enc("compressed-flag", payload: [1, 2, 3], compressed: true)
    enc("padded", payload: gBytes("pad me"), pad: 31)
    enc("padding-clamped-32", payload: gBytes("pad me"), pad: 100)
    enc("tick-zero-becomes-1", payload: [9], my: 0)
    enc("max-ticks", payload: [9], cookie: UInt32.max, my: UInt64.max, your: UInt64.max)
    enc("mtu-sized", payload: (0..<1400).map { UInt8(truncatingIfNeeded: $0) })
    enc("plain-mode", payload: gBytes("plain"), pad: 10, plain: true)
    enc("key-longer-than-32", payload: [1], key32: key + [99, 98])
    enc("short-key", payload: [1], key32: [UInt8](key.prefix(31)))
    enc("short-iv", payload: [1], iv: [1, 2, 3])

    // decode-only cases
    let good = (try? UdpAccelPacket.encode(key32: key, iv: iv, cookie: 1, myTick: 2, yourTick: 3, compressed: false, payload: gBytes("x")))?.packet ?? []
    func dec(_ name: String, _ packet: [UInt8], key32: [UInt8]? = nil, plain: Bool = false) {
        var c: GJ = ["name": name, "key": gHex(key32 ?? key), "packet": gHex(packet), "plainMode": plain]
        do {
            let d = try UdpAccelPacket.decode(packet: packet, key32: key32 ?? key, plainMode: plain)
            c["decoded"] =
                [
                    "cookie": d.header.cookie, "myTick": d.header.myTick, "yourTick": d.header.yourTick, "size": d.header.size,
                    "compressed": d.header.compressed, "payload": gHex(d.payload),
                ] as GJ
        } catch { c["error"] = gErrName(error) }
        out.append(c)
    }
    dec("decode-good", good)
    var t = good; t[20] ^= 1; dec("decode-tampered-ciphertext", t)
    t = good; t[t.count - 1] ^= 1; dec("decode-tampered-tag", t)
    t = good; t[0] ^= 1; dec("decode-tampered-iv", t)
    dec("decode-wrong-key", good, key32: [UInt8](repeating: 7, count: 32))
    dec("decode-short-key", good, key32: [1, 2, 3])
    dec("decode-too-short", Array(good.prefix(50)))
    dec("decode-empty", [])
    dec("decode-plain-too-short", [UInt8](repeating: 0, count: 22), plain: true)
    dec("decode-plain-truncated-payload", [UInt8](repeating: 0, count: 20) + [0x01, 0x00, 0, 0, 0], plain: true)  // size says 256, only 3 bytes follow
    dec("decode-plain-trailing-padding-ignored", [0, 0, 0, 1] + [UInt8](repeating: 0, count: 16) + [0, 1, 0, 0xee, 0, 0, 0], plain: true)

    out.append([
        "name": "constants", "ivSize": UdpAccelPacket.ivSize, "macSize": UdpAccelPacket.macSize, "minPlaintextSize": UdpAccelPacket.minPlaintextSize,
        "minPacketSize": UdpAccelPacket.minPacketSize, "maxPadding": UdpAccelPacket.maxPadding,
    ])
    // paddingSize with the random source pinned: records the bound it asks for and returns bound-1
    out.append([
        "name": "padding-size",
        "cases": [(0, 1500), (1000, 1500), (1449, 1500), (1450, 1500), (1451, 1500), (2000, 1500), (0, 60), (0, 51), (0, 40)].map { (d, m) -> GJ in
            var bound: Int? = nil
            let r = UdpAccelPacket.paddingSize(dataSize: d, maxSize: m) { b in
                bound = b; return b - 1
            }
            return ["dataSize": d, "maxSize": m, "randomBound": bound as Any? ?? NSNull(), "result": r]
        },
    ])
    return out
}

// MARK: - certpin

private func certPinCases() -> [GJ] {
    var out: [GJ] = []
    let der = Data((0..<300).map { UInt8(truncatingIfNeeded: $0 &* 13) })
    let sha1 = Insecure.SHA1.hash(data: der).map { String(format: "%02x", $0) }.joined()
    let sha256 = SHA256.hash(data: der).map { String(format: "%02x", $0) }.joined()
    let colon = { (s: String) in
        stride(from: 0, to: s.count, by: 2).map { i in String(s[s.index(s.startIndex, offsetBy: i)..<s.index(s.startIndex, offsetBy: i + 2)]) }.joined(
            separator: ":")
    }
    out.append(["name": "cert", "derHex": gHex(der), "sha1": sha1, "sha256": sha256])
    let texts = [
        sha1, sha1.uppercased(), colon(sha1), colon(sha256.uppercased()), sha256, " " + sha1 + " ", String(sha1.dropLast(2)), sha1 + "0",
        "zz" + sha1.dropFirst(2), "", String(repeating: "0", count: 40), "ab-cd" + String(repeating: "0", count: 36),
    ]
    out.append([
        "name": "pin-parse",
        "cases": texts.map { t -> GJ in
            let p = CertPin(t)
            return [
                "input": t, "digest": p.map { gHex($0.digest) } as Any? ?? NSNull(), "matchesCert": p?.matches(certDER: der) as Any? ?? NSNull(),
                "matchesOther": p?.matches(certDER: Data([1, 2, 3])) as Any? ?? NSNull(),
            ]
        },
    ])
    func pol(_ check: Bool, _ fp: String?) -> GJ {
        let p = ServerCertPolicy(checkServerCert: check, fingerprint: fp)
        let kind: String
        switch p {
        case .acceptAny: kind = "acceptAny";
        case .pinned: kind = "pinned";
        case .invalidPin: kind = "invalidPin";
        case .systemTrust: kind = "systemTrust"
        }
        return [
            "checkServerCert": check, "fingerprint": fp as Any? ?? NSNull(), "policy": kind, "rejectGood": p.rejection(leafDER: der) as Any? ?? NSNull(),
            "rejectOther": p.rejection(leafDER: Data([9])) as Any? ?? NSNull(), "rejectNone": p.rejection(leafDER: nil) as Any? ?? NSNull(),
        ]
    }
    out.append([
        "name": "policy",
        "cases": [
            pol(false, nil), pol(true, nil), pol(false, ""), pol(true, "   "), pol(false, sha1), pol(true, sha256), pol(false, "nothex"), pol(true, "nothex"),
            pol(false, "  " + sha1 + " "),
        ],
    ])
    return out
}

// MARK: - packets

private func packetCases() -> [GJ] {
    var out: [GJ] = []
    let macA: MAC = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55], macB: MAC = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]
    let v4 = { (a: UInt32, b: UInt32, c: UInt32, d: UInt32) in a << 24 | b << 16 | c << 8 | d }
    out.append([
        "name": "checksum",
        "cases": [[], [0], [1, 2], [1, 2, 3], [0xff, 0xff], [0xff, 0xff, 0xff, 0xff, 0xff], Array(0..<100)].map {
            ["input": gHex($0 as [UInt8]), "result": checksum($0)] as GJ
        },
    ])
    out.append([
        "name": "helpers", "ipString": [0, 0x01020304, UInt32.max].map { ["v": $0, "text": ipString($0)] as GJ },
        "packIP": [0, 0x01020304, 0x0a000001].map {
            [
                "v": $0, "text": packIPString($0),
                "back": packIPValue([UInt8($0 & 0xff), UInt8($0 >> 8 & 0xff), UInt8($0 >> 16 & 0xff), UInt8($0 >> 24)].reversed()),
            ] as GJ
        },
        "be16": [0, 1, 0x1234, 0xffff].map { ["v": $0, "hex": gHex(be16($0))] as GJ },
        "be32": [0, 1, 0x12345678, UInt32.max].map { ["v": $0, "hex": gHex(be32($0))] as GJ },
    ])
    out.append(["name": "ethernet", "hex": gHex(Ethernet.frame(dst: macB, src: macA, type: 0x0806, payload: [1, 2, 3]))])

    let arp = ARPPacket(op: 1, senderMAC: macA, senderIP: v4(10, 0, 0, 2), targetMAC: [0, 0, 0, 0, 0, 0], targetIP: v4(10, 0, 0, 1))
    func arpParse(_ name: String, _ b: [UInt8]) {
        let p = ARPPacket(b)
        out.append([
            "name": name, "hex": gHex(b),
            "parsed": p.map {
                ["op": $0.op, "senderMAC": gHex($0.senderMAC), "senderIP": $0.senderIP, "targetMAC": gHex($0.targetMAC), "targetIP": $0.targetIP] as GJ
            } as Any? ?? NSNull(),
        ])
    }
    out.append([
        "name": "arp-encode", "op": 1, "senderMAC": gHex(macA), "senderIP": arp.senderIP, "targetMAC": gHex([UInt8](repeating: 0, count: 6)),
        "targetIP": arp.targetIP, "hex": gHex(arp.encode()),
    ])
    out.append([
        "name": "arp-encode-reply", "op": 2, "senderMAC": gHex(macB), "senderIP": v4(10, 0, 0, 1), "targetMAC": gHex(macA), "targetIP": v4(10, 0, 0, 2),
        "hex": gHex(ARPPacket(op: 2, senderMAC: macB, senderIP: v4(10, 0, 0, 1), targetMAC: macA, targetIP: v4(10, 0, 0, 2)).encode()),
    ])
    arpParse("arp-parse-roundtrip", arp.encode())
    arpParse("arp-parse-short", Array(arp.encode().prefix(27)))
    var bad = arp.encode(); bad[1] = 6; arpParse("arp-parse-wrong-hwtype", bad)
    bad = arp.encode(); bad[3] = 0x86; arpParse("arp-parse-wrong-proto", bad)
    arpParse("arp-parse-trailing-bytes", arp.encode() + [1, 2, 3, 4])

    let ip = IPv4.packet(proto: 17, src: v4(10, 0, 0, 2), dst: v4(8, 8, 8, 8), payload: gBytes("payload"))
    func ipParse(_ name: String, _ b: [UInt8]) {
        let p = IPv4.parse(b)
        out.append([
            "name": name, "hex": gHex(b),
            "parsed": p.map { ["proto": Int($0.proto), "src": $0.src, "dst": $0.dst, "payload": gHex($0.payload)] as GJ } as Any? ?? NSNull(),
        ])
    }
    out.append(["name": "ipv4-build", "proto": 17, "src": v4(10, 0, 0, 2), "dst": v4(8, 8, 8, 8), "payload": gHex(gBytes("payload")), "hex": gHex(ip)])
    out.append(["name": "ipv4-build-empty", "proto": 1, "src": 1, "dst": 2, "payload": "", "hex": gHex(IPv4.packet(proto: 1, src: 1, dst: 2, payload: []))])
    ipParse("ipv4-parse-roundtrip", ip)
    ipParse("ipv4-parse-short", Array(ip.prefix(19)))
    ipParse("ipv4-parse-v6-nibble", [0x65] + ip.dropFirst())
    ipParse("ipv4-parse-trailing-ethernet-padding", ip + [0, 0, 0, 0])
    ipParse(
        "ipv4-parse-total-length-beyond-data",
        {
            var b = ip; b[2] = 0xff; b[3] = 0xff; return b
        }())
    ipParse(
        "ipv4-parse-ihl-options",
        {
            var b = ip; b[0] = 0x46; return b
        }())
    ipParse(
        "ipv4-parse-ihl-too-small",
        {
            var b = ip; b[0] = 0x44; return b
        }())
    ipParse(
        "ipv4-parse-total-below-ihl",
        {
            var b = ip; b[2] = 0; b[3] = 10; return b
        }())

    let udp = UDP.datagram(src: v4(10, 0, 0, 2), dst: v4(8, 8, 8, 8), sport: 5353, dport: 53, payload: gBytes("q"))
    func udpParse(_ name: String, _ b: [UInt8]) {
        let p = UDP.parse(b)
        out.append([
            "name": name, "hex": gHex(b), "parsed": p.map { ["sport": $0.sport, "dport": $0.dport, "payload": gHex($0.payload)] as GJ } as Any? ?? NSNull(),
        ])
    }
    out.append(["name": "udp-build", "src": v4(10, 0, 0, 2), "dst": v4(8, 8, 8, 8), "sport": 5353, "dport": 53, "payload": gHex(gBytes("q")), "hex": gHex(udp)])
    out.append([
        "name": "udp-build-odd-length", "src": 1, "dst": 2, "sport": 1, "dport": 2, "payload": gHex([1, 2, 3]),
        "hex": gHex(UDP.datagram(src: 1, dst: 2, sport: 1, dport: 2, payload: [1, 2, 3])),
    ])
    udpParse("udp-parse-roundtrip", udp)
    udpParse("udp-parse-short", [1, 2, 3])
    udpParse("udp-parse-length-below-8", [0, 1, 0, 2, 0, 7, 0, 0, 9])
    udpParse("udp-parse-length-beyond-data", [0, 1, 0, 2, 0xff, 0xff, 0, 0, 9, 9])

    // DHCP
    func dhcpEnc(_ name: String, _ m: DHCPMessage) {
        out.append([
            "name": name, "type": Int(m.type.rawValue), "xid": m.xid, "mac": gHex(m.mac), "ciaddr": m.ciaddr, "serverID": m.serverID as Any? ?? NSNull(),
            "requestedIP": m.requestedIP as Any? ?? NSNull(), "hex": gHex(m.encode()),
        ])
    }
    var d = DHCPMessage(type: .discover, xid: 0x12345678, mac: macA); dhcpEnc("dhcp-encode-discover", d)
    d = DHCPMessage(type: .request, xid: 0xcafebabe, mac: macA); d.requestedIP = v4(10, 0, 0, 77); d.serverID = v4(10, 0, 0, 1); d.ciaddr = v4(10, 0, 0, 77);
    dhcpEnc("dhcp-encode-request", d)

    func dhcpParse(_ name: String, _ b: [UInt8]) {
        let p = DHCPMessage(b)
        out.append([
            "name": name, "hex": gHex(b),
            "parsed": p.map { m -> GJ in
                [
                    "type": Int(m.type.rawValue), "xid": m.xid, "yiaddr": m.yiaddr, "mac": gHex(m.mac), "serverID": m.serverID as Any? ?? NSNull(),
                    "subnetMask": m.subnetMask as Any? ?? NSNull(),
                    "router": m.router as Any? ?? NSNull(), "dns": m.dns, "leaseSeconds": m.leaseSeconds as Any? ?? NSNull(),
                    "mtu": m.mtu.map { Int($0) } as Any? ?? NSNull(),
                ]
            } as Any? ?? NSNull(),
        ])
    }
    func reply(type: UInt8, xid: UInt32 = 0x12345678, yi: UInt32 = v4(10, 0, 0, 77), options: [UInt8]) -> [UInt8] {
        var b: [UInt8] =
            [2, 1, 6, 0] + be32(xid) + [0, 0, 0x80, 0] + be32(0) + be32(yi) + be32(0) + be32(0) + macA + [UInt8](repeating: 0, count: 10)
            + [UInt8](repeating: 0, count: 192)
        b += [99, 130, 83, 99] + [53, 1, type] + options + [255]
        return b
    }
    let full: [UInt8] =
        [54, 4] + be32(v4(10, 0, 0, 1)) + [1, 4] + be32(0xffffff00) + [3, 4] + be32(v4(10, 0, 0, 1)) + [6, 8] + be32(v4(8, 8, 8, 8)) + be32(v4(8, 8, 4, 4)) + [
            51, 4,
        ] + be32(86400) + [26, 2, 5, 220]
    dhcpParse("dhcp-parse-offer-full", reply(type: 2, options: full))
    dhcpParse("dhcp-parse-ack-pad-bytes", reply(type: 5, options: [0, 0] + full))
    dhcpParse("dhcp-parse-nak", reply(type: 6, options: []))
    dhcpParse("dhcp-parse-mtu-too-small", reply(type: 5, options: [26, 2, 2, 0x3f]))
    dhcpParse("dhcp-parse-mtu-too-big", reply(type: 5, options: [26, 2, 0x0b, 0xb8]))
    dhcpParse("dhcp-parse-mtu-min-max", reply(type: 5, options: [26, 2, 2, 0x40]))
    dhcpParse("dhcp-parse-mtu-1500", reply(type: 5, options: [26, 2, 5, 0xdc]))
    dhcpParse("dhcp-parse-dns-odd-length", reply(type: 5, options: [6, 6] + be32(1) + [9, 9]))
    dhcpParse("dhcp-parse-router-list", reply(type: 5, options: [3, 8] + be32(7) + be32(8)))
    dhcpParse("dhcp-parse-truncated-option", reply(type: 5, options: [54, 4, 1, 2]).dropLast(2).map { $0 })
    dhcpParse(
        "dhcp-parse-no-type",
        {
            var b = reply(type: 5, options: []); b[241] = 99; return b
        }())
    dhcpParse("dhcp-parse-unknown-type", reply(type: 9, options: []))
    dhcpParse(
        "dhcp-parse-bad-cookie",
        {
            var b = reply(type: 5, options: []); b[236] = 0; return b
        }())
    dhcpParse(
        "dhcp-parse-request-op",
        {
            var b = reply(type: 5, options: []); b[0] = 1; return b
        }())
    dhcpParse("dhcp-parse-short", [UInt8](repeating: 0, count: 239))

    // IPv6 / ICMPv6
    let src: [UInt8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
    let dst: [UInt8] = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34]
    let h = IPv6.header(src: src, dst: dst, nextHeader: 58, payloadLen: 12)
    out.append([
        "name": "ipv6-header", "src": gHex(src), "dst": gHex(dst), "nextHeader": 58, "payloadLen": 12, "hex": gHex(h),
        "ndpHex": gHex(IPv6.ndpPacket(src: src, dst: dst, icmp: [1, 2, 3])),
    ])
    func v6Parse(_ name: String, _ b: [UInt8]) {
        let p = IPv6.parse(b)
        out.append([
            "name": name, "hex": gHex(b),
            "parsed": p.map { ["nextHeader": Int($0.nextHeader), "src": gHex($0.src), "dst": gHex($0.dst), "payload": gHex($0.payload)] as GJ } as Any?
                ?? NSNull(),
        ])
    }
    v6Parse("ipv6-parse-roundtrip", h + [UInt8](repeating: 5, count: 12))
    v6Parse("ipv6-parse-payload-len-beyond-data", h + [1, 2])
    v6Parse("ipv6-parse-short", [UInt8](h.prefix(39)))
    v6Parse("ipv6-parse-v4", [0x45] + h.dropFirst())
    let macs: [MAC] = [macA, macB, [0, 0, 0, 0, 0, 0], [1, 2, 3]]
    out.append([
        "name": "ipv6-eui64",
        "cases": macs.map { m -> GJ in
            [
                "mac": gHex(m), "linkLocal": gHex(IPv6.linkLocal(mac: m)),
                "slaac": gHex(IPv6.slaac(prefix: [0x20, 0x01, 0x0d, 0xb8, 0, 1, 0, 2, 9, 9, 9, 9, 9, 9, 9, 9], mac: m)),
                "slaacShortPrefix": gHex(IPv6.slaac(prefix: [1, 2, 3], mac: m)),
            ]
        },
    ])
    let addrs: [[UInt8]] = [
        src, dst, [UInt8](repeating: 0, count: 16), [0xfe, 0xbf] + [UInt8](repeating: 0, count: 14), [0xfe, 0xc0] + [UInt8](repeating: 0, count: 14),
        [1, 2, 3],
    ]
    out.append([
        "name": "ipv6-address-helpers",
        "cases": addrs.map { a -> GJ in
            [
                "addr": gHex(a), "isLinkLocal": IPv6.isLinkLocal(a), "string": IPv6.string(a),
                "solicitedNodeMulticast": gHex(IPv6.solicitedNodeMulticast(ip: a)), "multicastMAC": gHex(IPv6.multicastMAC(ip: a)),
            ]
        },
    ])
    let allNodes: [UInt8] = [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [1]
    let solicited = IPv6.solicitedNodeMulticast(ip: dst)
    let rs = ICMPv6.routerSolicitation(srcMAC: macA, srcIP: src)
    let ns = ICMPv6.neighborSolicitation(targetIP: dst, srcMAC: macA, srcIP: src, dstIP: solicited)
    let nsDad = ICMPv6.neighborSolicitation(targetIP: dst, srcMAC: macA, srcIP: [UInt8](repeating: 0, count: 16), dstIP: solicited)
    let na = ICMPv6.neighborAdvertisement(targetIP: dst, targetMAC: macA, srcIP: dst, dstIP: src)
    let naDad = ICMPv6.neighborAdvertisement(targetIP: dst, targetMAC: macA, srcIP: dst, dstIP: allNodes, solicited: false)
    out.append([
        "name": "icmpv6-build",
        "routerSolicitation": [
            "srcMAC": gHex(macA), "srcIP": gHex(src), "hex": gHex(rs),
            "checksumValid": ICMPv6.isChecksumValid(src: src, dst: [0xff, 0x02] + [UInt8](repeating: 0, count: 13) + [2], icmp: rs),
        ] as GJ,
        "neighborSolicitation": [
            "targetIP": gHex(dst), "srcMAC": gHex(macA), "srcIP": gHex(src), "dstIP": gHex(solicited), "hex": gHex(ns),
            "checksumValid": ICMPv6.isChecksumValid(src: src, dst: solicited, icmp: ns),
        ] as GJ,
        "neighborSolicitationDAD": ["srcIP": gHex([UInt8](repeating: 0, count: 16)), "dstIP": gHex(solicited), "hex": gHex(nsDad)] as GJ,
        "neighborAdvertisement": [
            "targetMAC": gHex(macA), "srcIP": gHex(dst), "dstIP": gHex(src), "hex": gHex(na),
            "checksumValid": ICMPv6.isChecksumValid(src: dst, dst: src, icmp: na),
        ] as GJ,
        "neighborAdvertisementDAD": ["dstIP": gHex(allNodes), "hex": gHex(naDad)] as GJ,
    ])
    out.append([
        "name": "icmpv6-checksum",
        "cases": [[], [1], [1, 2], [0xff, 0xff, 0, 0, 1]].map { p -> GJ in
            [
                "src": gHex(src), "dst": gHex(dst), "icmp": gHex(p), "checksum": ICMPv6.checksum(src: src, dst: dst, icmpPayload: p),
                "valid": ICMPv6.isChecksumValid(src: src, dst: dst, icmp: p),
            ]
        },
    ])
    return out
}

// MARK: - account

private let gFixedDate = Date(timeIntervalSinceReferenceDate: 750_000_000)

private func accountCases() -> [GJ] {
    var out: [GJ] = []
    var proxy = ProxySettings(); proxy.kind = .http; proxy.host = "proxy.local"; proxy.port = 8080; proxy.username = "u"; proxy.password = "secret"
    var routing = RoutingConfig(
        rules: [RoutingRule(id: gFixedIDs[0], type: .domainSuffix, value: "example.com", action: .direct)], defaultAction: .proxy, bypassPrivateNetworks: true)
    routing.defaultAction = .block
    let minimal = ClientAccount(id: gFixedIDs[1], name: "min", host: "h.example.com", createdAt: gFixedDate, updatedAt: gFixedDate)
    let full = ClientAccount(
        id: gFixedIDs[2], name: "full", host: "1.2.3.4", portList: [443, 992], hub: "VPN", username: "bob", authType: .certificate, proxy: proxy,
        checkServerCert: true,
        serverCertFingerprint: String(repeating: "ab", count: 20), maxConnection: 8, halfConnection: true, compression: true, udpAcceleration: false,
        disableQoS: true,
        autoReconnect: false, reconnectInterval: 7.5, reconnectCount: 3, virtualMacAddress: "aa:bb:cc:dd:ee:ff", mtu: 1400, routing: routing,
        createdAt: gFixedDate, updatedAt: gFixedDate)
    out.append(["name": "encode-minimal", "json": gCodable(minimal)])
    out.append(["name": "encode-full-strips-proxy-password", "json": gCodable(full)])
    for (n, a) in [("minimal", minimal), ("full", full)] {
        out.append([
            "name": "connect-config-\(n)", "password": "pw", "certDer": "0102", "privateKeyDer": "0304", "blockIPv6": false, "globalRouting": gCodable(routing),
            "tunnelMode": "socksProxy", "socksPort": 9050,
            "config": gCodable(
                a.toConnectConfig(
                    password: "pw", certDer: Data([1, 2]), privateKeyDer: Data([3, 4]), blockIPv6: false, globalRouting: routing, tunnelMode: .socksProxy,
                    socksPort: 9050)),
        ])
    }
    out.append(["name": "connect-config-defaults", "config": gCodable(full.toConnectConfig())])

    let base = "\"id\":\"\(gFixedIDs[3].uuidString)\",\"name\":\"n\",\"host\":\"h\""
    let inputs: [String] = [
        "{\(base)}",
        "{\(base),\"portList\":[],\"maxConnection\":99}",
        "{\(base),\"maxConnection\":0}",
        "{\(base),\"maxConnection\":-5}",
        "{\(base),\"hideFromVpnGateList\":true,\"futureField\":{\"x\":1},\"authType\":\"Plain Password\"}",
        "{\(base),\"authType\":\"Anonymous\",\"createdAt\":1.5,\"updatedAt\":2.5}",
        "{\(base),\"proxy\":{\"kind\":\"socks5\",\"host\":\"p\",\"port\":1080,\"password\":\"leak\"}}",
        "{\(base),\"authType\":\"nope\"}",
        "{\"name\":\"n\",\"host\":\"h\"}",
        "{\(base),\"portList\":[70000]}",
    ]
    out.append([
        "name": "decode",
        "cases": inputs.map { s -> GJ in
            guard var a = try? JSONDecoder().decode(ClientAccount.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            // createdAt/updatedAt default to "now" when absent: pin them so the vector is stable
            if !s.contains("createdAt") { a.createdAt = gFixedDate; a.updatedAt = gFixedDate }
            return ["input": s, "datesDefaulted": !s.contains("createdAt"), "account": gCodable(a)]
        },
    ])
    out.append([
        "name": "init-clamps",
        "cases": [(0, 1), (1, 1), (32, 32), (33, 32), (-1, 1)].map { (m, e) -> GJ in
            ["maxConnection": m, "result": ClientAccount(name: "n", host: "h", maxConnection: m).maxConnection]
        }
            + [["portList": [Int](), "result": ClientAccount(name: "n", host: "h", portList: []).portList.map(Int.init)] as GJ],
    ])
    out.append(["name": "auth-types", "cases": AccountAuthType.allCases.map { ["raw": $0.rawValue] as GJ }])
    return out
}

// MARK: - ipc

private func ipcCases() -> [GJ] {
    var out: [GJ] = []
    var proxy = ProxySettings(); proxy.kind = .socks5; proxy.host = "p"; proxy.port = 1080; proxy.username = "u"; proxy.password = "pw"
    let routing = RoutingConfig(
        rules: [RoutingRule(id: gFixedIDs[0], type: .cidr, value: "10.0.0.0/8", action: .direct, enabled: false)], defaultAction: .block,
        bypassPrivateNetworks: true)
    let full = ConnectConfig(
        host: "h", ports: [443, 992], hubName: "HUB", userName: "u", authType: "cert", password: "pw", certDer: Data([1, 2, 3]), privateKeyDer: Data([4, 5]),
        ticket: Data([6]), proxy: proxy,
        maxConnection: 4, useCompress: true, useUdpAccel: false, disableQoS: true, halfConnection: true, autoReconnect: false, reconnectInterval: 2.5,
        reconnectCount: 5, blockIPv6: false,
        checkServerCert: true, serverCertFingerprint: "ab", mtu: 1400, virtualMacAddress: "aa:bb:cc:dd:ee:ff", routing: routing, tunnelMode: .socksProxy,
        socksPort: 9050)
    out.append(["name": "connect-config-default", "json": gCodable(ConnectConfig(host: "h"))])
    out.append(["name": "connect-config-full", "json": gCodable(full)])
    let cfgIn = [
        "{\"host\":\"h\"}", "{\"host\":\"h\",\"ports\":[1],\"unknown\":1}", "{\"ports\":[1]}", "{\"host\":\"h\",\"tunnelMode\":\"bogus\"}",
        "{\"host\":\"h\",\"certDer\":\"AQID\",\"routing\":{}}", "{\"host\":\"h\",\"certDer\":\"!!\"}",
    ]
    out.append([
        "name": "connect-config-decode",
        "cases": cfgIn.map { s -> GJ in
            guard let c = try? JSONDecoder().decode(ConnectConfig.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            return ["input": s, "config": gCodable(c)]
        },
    ])

    var r = HelperRequest(cmd: "connect"); r.host = "h"; r.port = 443; r.ports = [443, 992]; r.proxy = proxy; r.autoReconnect = true; r.blockIPv6 = false;
    r.routing = routing; r.tunnelMode = .fullTunnel; r.socksPort = 1080; r.config = full
    out.append(["name": "request-encode", "cases": [gCodable(HelperRequest(cmd: "status")), gCodable(HelperRequest(cmd: "disconnect")), gCodable(r)]])
    let reqIn = [
        "{\"cmd\":\"status\"}", "{\"cmd\":\"connect\",\"host\":\"h\",\"port\":1}", "{\"host\":\"h\"}", "not json",
        "{\"cmd\":\"x\",\"config\":{\"host\":\"c\"}}", "{\"cmd\":\"connect\",\"port\":\"1\"}",
    ]
    out.append([
        "name": "request-decode",
        "cases": reqIn.map { s -> GJ in
            guard let q = try? JSONDecoder().decode(HelperRequest.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            return ["input": s, "request": gCodable(q)]
        },
    ])

    var e = HelperEvent(state: .connected); e.server = "s"; e.virtualIP = "10.0.0.2"; e.bytesIn = 123; e.bytesOut = UInt64.max; e.log = "l"; e.error = "e";
    e.helperVersion = helperVersion
    out.append(["name": "event-encode", "cases": ConnectionState.allCases(), "events": [gCodable(HelperEvent(state: .disconnected)), gCodable(e)]])
    let evIn = [
        "{\"state\":\"connecting\"}", "{\"state\":\"dhcp\",\"bytesIn\":5,\"bytesOut\":6}", "{\"state\":\"bogus\"}", "{}",
        "{\"state\":\"connected\",\"helperVersion\":8,\"extra\":1}",
    ]
    out.append([
        "name": "event-decode",
        "cases": evIn.map { s -> GJ in
            guard let q = try? JSONDecoder().decode(HelperEvent.self, from: Data(s.utf8)) else { return ["input": s, "error": true] }
            return ["input": s, "event": gCodable(q)]
        },
    ])
    out.append(["name": "constants", "helperSocketPath": helperSocketPath, "helperVersion": helperVersion, "defaultSocksPort": defaultSocksPort])
    out.append(["name": "proxy-settings", "json": gCodable(proxy), "default": gCodable(ProxySettings())])
    return out
}

private extension ConnectionState {
    static func allCases() -> [String] { ["disconnected", "connecting", "authenticating", "dhcp", "connected", "reconnecting"] }
}
