import Foundation
import VPNGateCore

func registerPackTests() {
    test("pack/golden-bytes") {
        var p = Pack(); p.addInt("a", 1); p.addStr("s", "hi")
        let expect: [UInt8] = [0,0,0,2,
            0,0,0,2, 0x61, 0,0,0,0, 0,0,0,1, 0,0,0,1,
            0,0,0,2, 0x73, 0,0,0,2, 0,0,0,1, 0,0,0,2, 0x68, 0x69]
        expectEqual([UInt8](p.serialize()), expect)
    }
    test("pack/golden-unistr-and-int64") {
        var p = Pack(); p.addUni("u", "é"); p.addInt64("l", 0x0102030405060708)
        let b = [UInt8](p.serialize())
        // unistr: len+1 (3) then UTF-8 bytes + NUL
        expectEqual(Array(b[17..<24]), [0, 0, 0, 3, 0xC3, 0xA9, 0])
        expectEqual(Array(b.suffix(8)), [1, 2, 3, 4, 5, 6, 7, 8])
    }
    test("pack/roundtrip-all-types") {
        var q = Pack()
        q.addInt("i", 0xdeadbeef); q.addData("d", Data([1, 2, 3])); q.addStr("s", "héllo")
        q.addUni("u", "ünï"); q.addInt64("l", 0x1122334455667788); q.addIPv4("ip", 0x0a000001)
        let r = try Pack(parsing: q.serialize())
        expectEqual(r, q)
        expectEqual(r.int("ip"), 0x0a000001)
        expectEqual(r.str("u"), "ünï")
        expectEqual(r.data("d"), Data([1, 2, 3]))
        expectEqual(r.int("l"), 0x55667788)
        expectEqual(r.int("s"), nil)
    }
    test("pack/names-are-case-insensitive-and-unique") {
        var p = Pack(); p.addInt("HubName", 1); p.addInt("hubname", 2)
        expectEqual(p.elements.count, 1)
        expectEqual(p.int("HUBNAME"), 2)
    }
    test("pack/rejects-truncated") {
        expectThrows(try Pack(parsing: Data([0, 0, 0, 1, 0, 0])))
        var p = Pack(); p.addStr("s", "hello")
        let full = p.serialize()
        for n in 0..<full.count { expectThrows(try Pack(parsing: full.prefix(n)), "prefix \(n)") }
    }
    test("pack/rejects-bad-type-and-name") {
        // one element, name "a", type 9
        expectThrows(try Pack(parsing: Data([0,0,0,1, 0,0,0,2, 0x61, 0,0,0,9, 0,0,0,1, 0,0,0,0])))
        // name length 0 (len+1 == 0 underflow)
        expectThrows(try Pack(parsing: Data([0,0,0,1, 0,0,0,0])))
        // absurd name length
        expectThrows(try Pack(parsing: Data([0,0,0,1, 0,0,1,0])))
    }
    test("pack/rejects-huge-counts") {
        expectThrows(try Pack(parsing: Data([0xff, 0xff, 0xff, 0xff])))
        expectThrows(try Pack(parsing: Data([0,0,0,1, 0,0,0,2, 0x61, 0,0,0,0, 0xff,0xff,0xff,0xff])))
    }
    test("login/pack-has-no-duplicate-names") {
        let c = SoftEtherClient(host: "h", port: 443, proxy: ProxySettings())
        let names = c.loginPack().elements.map { $0.name.lowercased() }
        expectEqual(Set(names).count, names.count, "duplicate element names (server answers error 3)")
    }
    test("login/pack-required-fields") {
        let p = SoftEtherClient(host: "h", port: 443, proxy: ProxySettings()).loginPack()
        expectEqual(p.str("method"), "login")
        expectEqual(p.str("hubname"), "VPNGATE")
        expectEqual(p.str("username"), "vpn")
        expectEqual(p.int("authtype"), 0)
        expectEqual(p.int("use_encrypt"), 1)
        expectEqual(p.int("use_compress"), 0)
        expectEqual(p.data("unique_id")?.count, 20)
    }
    test("login/hostile-proxy-port-does-not-trap") {          // B4
        var proxy = ProxySettings(); proxy.kind = .http; proxy.host = "p"; proxy.port = -1
        let p = SoftEtherClient(host: "h", port: 443, proxy: proxy).loginPack()
        expect(p.int("ProxyPort") != nil)
        proxy.port = 70000
        _ = SoftEtherClient(host: "h", port: 443, proxy: proxy).loginPack()
    }
}
