import Foundation
import VPNGateCore

func registerValidationTests() {
    test("validation/ports") {
        for p in [1, 443, 65535] { expect(InputValidation.isValidPort(p), "\(p)") }
        for p in [0, -1, 65536, 70000, Int.max] { expect(!InputValidation.isValidPort(p), "\(p)") }
        expect(!InputValidation.isValidPort(nil))
    }
    test("validation/mac-addresses") {
        expectEqual(InputValidation.parseMacAddress("00:AC:DE:12:34:56"), [0x00, 0xAC, 0xDE, 0x12, 0x34, 0x56])
        expectEqual(InputValidation.parseMacAddress("00-AC-DE-12-34-56"), [0x00, 0xAC, 0xDE, 0x12, 0x34, 0x56])
        expectEqual(InputValidation.parseMacAddress("ff:ff:ff:ff:ff:ff"), [UInt8](repeating: 0xFF, count: 6))
        expectEqual(
            InputValidation.parseMacAddress("0:a:b:c:d:e"), [0x00, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E],
            "single hex digits are accepted leniently")
        for bad in ["", "00:AC:DE:12:34", "00:AC:DE:12:34:56:78", "GG:AC:DE:12:34:56", "00AC.DE12.3456"] {
            expect(InputValidation.parseMacAddress(bad) == nil, bad)
        }
    }
    test("validation/hosts") {
        for h in ["1.2.3.4", "219.100.37.7", "vpn927125019.opengw.net", "a", "my-host.example.com"] {
            expect(InputValidation.isValidHost(h), h)
        }
        for h in [
            "", "-interface", "-host", "1.2.3", "1.2.3.256", "a b", "a;b", "a$(b)", "..", ".a", "a.", "a..b",
            "ho\nst", "höst", String(repeating: "a", count: 254), "1.2.3.4/32",
        ] {
            expect(!InputValidation.isValidHost(h), "should reject \(h.debugDescription)")
        }
    }
    test("validation/local-addresses") {
        for h in ["127.0.0.1", "127.9.9.9", "169.254.1.1", "0.0.0.0", "localhost"] { expect(InputValidation.isLocalAddress(h), h) }
        for h in ["1.2.3.4", "192.168.1.1", "128.0.0.1"] { expect(!InputValidation.isLocalAddress(h), h) }
    }
    test("ipc/message-codable-roundtrip") {
        var r = HelperRequest(cmd: "connect"); r.host = "1.2.3.4"; r.port = 443; r.blockIPv6 = false
        var p = ProxySettings(); p.kind = .socks5; p.host = "h"; p.port = 1080; p.username = "u"; p.password = "pw"
        r.proxy = p
        let back = try JSONDecoder().decode(HelperRequest.self, from: JSONEncoder().encode(r))
        expectEqual(back.proxy, p); expectEqual(back.blockIPv6, false); expectEqual(back.host, "1.2.3.4")
        // old clients without the new keys still decode
        let old = Data(#"{"cmd":"disconnect"}"#.utf8)
        let dec = try JSONDecoder().decode(HelperRequest.self, from: old)
        expectEqual(dec.cmd, "disconnect")
    }
}
