import Foundation
import VPNGateCore

func registerDataPhaseTests() {
    test("dataphase/golden-encode") {
        expectEqual(DataPhase.encode(frames: [[1, 2], [3]]), [0,0,0,2, 0,0,0,2, 1,2, 0,0,0,1, 3])
        expectEqual(DataPhase.encodeKeepAlive(junk: [7, 8]), [0xff,0xff,0xff,0xff, 0,0,0,2, 7, 8])
    }
    test("dataphase/decode-frames-and-keepalive") {
        var d = DataPhaseDecoder()
        let bytes = DataPhase.encode(frames: [[1, 2], [3]]) + DataPhase.encodeKeepAlive(junk: [9, 9, 9])
            + DataPhase.encode(frames: [[4]])
        let items = try d.feed(bytes)
        expectEqual(items, [.frame([1, 2]), .frame([3]), .keepAlive, .frame([4])])
    }
    test("dataphase/any-chunking-gives-same-result") {
        var rng = SeededRNG(42)
        var bytes: [UInt8] = []
        var expected: [DataPhaseItem] = []
        for _ in 0..<30 {
            if Int.random(in: 0..<4, using: &rng) == 0 {
                bytes += DataPhase.encodeKeepAlive(junk: (0..<Int.random(in: 0..<50, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) })
                expected.append(.keepAlive)
            } else {
                let frames = (0..<Int.random(in: 1...5, using: &rng)).map { _ in
                    (0..<Int.random(in: 0...1500, using: &rng)).map { _ in UInt8.random(in: 0...255, using: &rng) }
                }
                bytes += DataPhase.encode(frames: frames)
                expected += frames.map { .frame($0) }
            }
        }
        for chunk in [1, 2, 3, 7, 100, 4096, bytes.count] {
            var d = DataPhaseDecoder(); var got: [DataPhaseItem] = []
            var i = 0
            while i < bytes.count { got += try d.feed(Array(bytes[i..<min(i + chunk, bytes.count)])); i += chunk }
            expectEqual(got, expected, "chunk size \(chunk)")
        }
    }
    test("dataphase/rejects-oversized-block") {
        var d = DataPhaseDecoder()
        expectThrows(try d.feed([0,0,0,1, 0,0,0x0C,0x81]))            // 3201 > 3200
        var ok = DataPhaseDecoder()
        _ = try ok.feed([0,0,0,1, 0,0,0x0C,0x80])                      // exactly 3200 is fine (waiting for body)
    }
    test("dataphase/rejects-absurd-counts-and-keepalives") {
        var d = DataPhaseDecoder(); expectThrows(try d.feed([0, 0, 0x10, 0x00]))
        var k = DataPhaseDecoder(); expectThrows(try k.feed([0xff,0xff,0xff,0xff, 0,0,0x10,0]))
    }
    test("dataphase/zero-block-batch-is-ignored") {
        var d = DataPhaseDecoder()
        let items = try d.feed([0,0,0,0] + DataPhase.encode(frames: [[5]]))
        expectEqual(items, [.frame([5])])
    }
    test("dataphase/errors-are-human-readable") {
        for e in [DataPhaseError.oversizedBlock(5000), .badBlockCount(9999), .badKeepAlive(9999)] {
            expect(!(e.errorDescription ?? "").isEmpty && e.errorDescription!.contains(where: \.isNumber), "\(e)")
        }
    }
    test("dataphase/keepalive-split-across-feeds") {
        var d = DataPhaseDecoder()
        let ka = DataPhase.encodeKeepAlive(junk: [1, 2, 3, 4, 5])
        let first = try d.feed(Array(ka[0..<6])), second = try d.feed(Array(ka[6...]))
        expectEqual(first, []); expectEqual(second, [.keepAlive])
    }
    test("bytebuffer/take-and-marker") {
        var b = ByteBuffer(); b.append([1, 2, 3, 13, 10, 13, 10, 9])
        expectEqual(b.take(upTo: HTTPHead.terminator), [1, 2, 3])
        expectEqual(b.count, 1)
        expect(b.take(2) == nil)
        expectEqual(b.take(1), [9]); expectEqual(b.count, 0)
        expect(b.take(upTo: [1]) == nil)
    }
    test("bytebuffer/consuming-many-small-reads-is-linear") {          // B17
        var b = ByteBuffer(); b.append([UInt8](repeating: 7, count: 8_000_000))
        let start = Date()
        var n = 0
        while b.take(4) != nil { n += 1 }
        expectEqual(n, 2_000_000)
        expect(Date().timeIntervalSince(start) < 5, "2M small reads took \(Date().timeIntervalSince(start))s")
    }
    test("httphead/parse") {
        let h = HTTPHead.parse(Array("HTTP/1.1 200 OK\r\nContent-Length: 12\r\nContent-Type: a/b ".utf8))
        expectEqual(h.statusCode, 200); expectEqual(h.headers["content-length"], "12"); expectEqual(h.headers["content-type"], "a/b")
        expectEqual(HTTPHead.parse(Array("garbage".utf8)).statusCode, nil)
    }
}
