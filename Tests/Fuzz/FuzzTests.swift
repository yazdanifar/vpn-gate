import Foundation
import VPNGateCore

private let iterations = ProcessInfo.processInfo.environment["FUZZ_ITERATIONS"].flatMap(Int.init) ?? 20000

private func seed(_ name: String) -> UInt64 {
    if let s = ProcessInfo.processInfo.environment["FUZZ_SEED"].flatMap(UInt64.init) { return s }
    return UInt64(truncatingIfNeeded: name.hashValue) ^ 0x1234_5678
}

private func randomBytes(_ rng: inout SeededRNG, max: Int) -> [UInt8] {
    (0..<Int.random(in: 0...max, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
}

private func randomPack(_ rng: inout SeededRNG) -> Pack {
    var p = Pack()
    for i in 0..<Int.random(in: 0...12, using: &rng) {
        let n = "e\(i)_" + String((0..<Int.random(in: 0...20, using: &rng)).map { _ in Character(UnicodeScalar(UInt8.random(in: 97...122, using: &rng))) })
        switch Int.random(in: 0..<5, using: &rng) {
        case 0: p.addInt(n, UInt32.random(in: 0...UInt32.max, using: &rng))
        case 1: p.addData(n, Data(randomBytes(&rng, max: 300)))
        case 2: p.addStr(n, String((0..<Int.random(in: 0...30, using: &rng)).map { _ in Character(UnicodeScalar(UInt8.random(in: 32...126, using: &rng))) }))
        case 3: p.addUni(n, ["", "é", "日本語", "😀 emoji", "plain"].randomElement(using: &rng)!)
        default: p.addInt64(n, UInt64.random(in: 0...UInt64.max, using: &rng))
        }
    }
    return p
}

func registerFuzzTests() {
    test("fuzz/pack-parse-random-bytes-never-crashes", timeout: 60) {
        var rng = SeededRNG(seed("pack-random"))
        for _ in 0..<iterations { _ = try? Pack(parsing: Data(randomBytes(&rng, max: 200))) }
    }
    test("fuzz/pack-parse-mutated-valid-packs-never-crashes", timeout: 60) {
        var rng = SeededRNG(seed("pack-mutate"))
        for _ in 0..<iterations {
            var b = [UInt8](randomPack(&rng).serialize())
            for _ in 0..<Int.random(in: 1...4, using: &rng) where !b.isEmpty {
                switch Int.random(in: 0..<3, using: &rng) {
                case 0: b[Int.random(in: 0..<b.count, using: &rng)] = UInt8.random(in: 0...255, using: &rng)
                case 1: b.removeLast(Int.random(in: 0...min(8, b.count), using: &rng))
                default: b.insert(UInt8.random(in: 0...255, using: &rng), at: Int.random(in: 0...b.count, using: &rng))
                }
            }
            _ = try? Pack(parsing: Data(b))
        }
    }
    test("fuzz/pack-roundtrip-holds-for-random-packs", timeout: 60) {
        var rng = SeededRNG(seed("pack-roundtrip"))
        for i in 0..<iterations {
            let p = randomPack(&rng)
            let back = try Pack(parsing: p.serialize())
            if back != p { fail("roundtrip mismatch at iteration \(i)"); return }
        }
    }
    test("fuzz/dataphase-decoder-never-crashes-and-errors-are-sticky-safe", timeout: 60) {
        var rng = SeededRNG(seed("dp-random"))
        for _ in 0..<iterations {
            var d = DataPhaseDecoder()
            for _ in 0..<Int.random(in: 1...6, using: &rng) { if (try? d.feed(randomBytes(&rng, max: 64))) == nil { break } }
        }
    }
    test("fuzz/dataphase-valid-streams-survive-random-chunking", timeout: 60) {
        var rng = SeededRNG(seed("dp-chunk"))
        for _ in 0..<(iterations / 20) {
            let frames = (0..<Int.random(in: 1...6, using: &rng)).map { _ in randomBytes(&rng, max: 400) }
            let stream = DataPhase.encode(frames: frames) + DataPhase.encodeKeepAlive(junk: randomBytes(&rng, max: 100))
            var d = DataPhaseDecoder(); var got: [[UInt8]] = []; var i = 0
            while i < stream.count {
                let n = Int.random(in: 1...20, using: &rng)
                for it in try d.feed(Array(stream[i..<min(i + n, stream.count)])) { if case .frame(let f) = it { got.append(f) } }
                i += n
            }
            if got != frames { fail("frames mismatch"); return }
        }
    }
    test("fuzz/packet-parsers-never-crash", timeout: 60) {
        var rng = SeededRNG(seed("packets"))
        for _ in 0..<iterations {
            let b = randomBytes(&rng, max: 400)
            _ = IPv4.parse(b); _ = UDP.parse(b); _ = ARPPacket(b); _ = DHCPMessage(b); _ = HTTPHead.parse(b)
            // structurally plausible DHCP with random options
            var d = DHCPMessage(type: .offer, xid: 1, mac: [1, 2, 3, 4, 5, 6]).encode(); d[0] = 2
            d.removeSubrange(240...); d += b
            _ = DHCPMessage(d)
        }
    }
    test("fuzz/bridge-survives-random-frames", timeout: 60) {
        var rng = SeededRNG(seed("bridge"))
        let net = FakeNetworkServer(); let b = EthernetBridge(timing: BridgeTiming(dhcpTimeout: 0.5, dhcpRetries: 1))
        wire(b, to: net)
        _ = try await b.acquireLease()
        b.deliverIPv4 = { _ in }
        let sent = Locked(0); b.sendFrame = { _ in sent.update { $0 += 1 } }
        for _ in 0..<iterations {
            var f = randomBytes(&rng, max: 120)
            if Bool.random(using: &rng), f.count >= 14 {
                f[12] = [0x08, 0x08, 0x86][Int.random(in: 0..<3, using: &rng)]; f[13] = [0x00, 0x06, 0xDD][Int.random(in: 0..<3, using: &rng)]
            }
            b.fromHub(f)
            b.fromHost(randomBytes(&rng, max: 80))
        }
    }
    test("fuzz/server-list-parser-never-crashes", timeout: 60) {
        var rng = SeededRNG(seed("csv"))
        let base = fixture("vpngate-snapshot.csv")
        for _ in 0..<(iterations / 20) {
            var chars = Array(base.prefix(3000))
            for _ in 0..<Int.random(in: 0...30, using: &rng) where !chars.isEmpty {
                chars[Int.random(in: 0..<chars.count, using: &rng)] = [",", "\n", "\r", "a", "=", "é", " "].randomElement(using: &rng)!
            }
            _ = ServerList.parse(String(chars))
        }
        _ = ServerList.parse(String(decoding: randomBytes(&rng, max: 500), as: UTF8.self))
    }
    test("fuzz/input-validation-never-crashes", timeout: 30) {
        var rng = SeededRNG(seed("validation"))
        for _ in 0..<iterations {
            let s = String(decoding: randomBytes(&rng, max: 40), as: UTF8.self)
            _ = InputValidation.isValidHost(s); _ = InputValidation.isLocalAddress(s); _ = ServerFilter.logWeeks(s)
            if InputValidation.isValidHost(s) { expect(s.first != "-", "valid host starting with '-': \(s)") }
        }
    }
}
