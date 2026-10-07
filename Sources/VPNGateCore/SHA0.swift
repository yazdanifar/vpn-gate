import Foundation

/// SHA-0 cryptographic hash function (FIPS PUB 180, 1993).
/// SoftEther uses SHA-0 for authtype 1 (secure password) authentication and
/// internal probe signatures. Unlike SHA-1, SHA-0 does NOT rotate left by 1
/// during message schedule expansion.
public enum SHA0 {
    public static let digestLength = 20

    public static func hash(_ data: [UInt8]) -> [UInt8] {
        var h0: UInt32 = 0x67452301
        var h1: UInt32 = 0xefcdab89
        var h2: UInt32 = 0x98badcfe
        var h3: UInt32 = 0x10325476
        var h4: UInt32 = 0xc3d2e1f0

        let bitCount = UInt64(data.count) &* 8
        var padded = data
        padded.append(0x80)
        while (padded.count % 64) != 56 {
            padded.append(0)
        }
        var beBits = bitCount.bigEndian
        withUnsafeBytes(of: &beBits) { padded.append(contentsOf: $0) }

        var w = [UInt32](repeating: 0, count: 80)
        let chunkCount = padded.count / 64

        for c in 0..<chunkCount {
            let offset = c * 64
            for i in 0..<16 {
                let idx = offset + i * 4
                let val = (UInt32(padded[idx]) << 24)
                    | (UInt32(padded[idx + 1]) << 16)
                    | (UInt32(padded[idx + 2]) << 8)
                    | UInt32(padded[idx + 3])
                w[i] = val
            }
            // SHA-0 message schedule: no 1-bit rotate!
            for i in 16..<80 {
                w[i] = w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4

            for i in 0..<80 {
                let f: UInt32
                let k: UInt32
                if i < 20 {
                    f = (b & c) | ((~b) & d)
                    k = 0x5a827999
                } else if i < 40 {
                    f = b ^ c ^ d
                    k = 0x6ed9eba1
                } else if i < 60 {
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8f1bbcdc
                } else {
                    f = b ^ c ^ d
                    k = 0xca62c1d6
                }
                let temp = (a.rotateLeft(5) &+ f &+ e &+ k &+ w[i])
                e = d
                d = c
                c = b.rotateLeft(30)
                b = a
                a = temp
            }

            h0 = h0 &+ a
            h1 = h1 &+ b
            h2 = h2 &+ c
            h3 = h3 &+ d
            h4 = h4 &+ e
        }

        var out = [UInt8](repeating: 0, count: 20)
        let words = [h0, h1, h2, h3, h4]
        for (i, word) in words.enumerated() {
            out[i * 4] = UInt8((word >> 24) & 0xff)
            out[i * 4 + 1] = UInt8((word >> 16) & 0xff)
            out[i * 4 + 2] = UInt8((word >> 8) & 0xff)
            out[i * 4 + 3] = UInt8(word & 0xff)
        }
        return out
    }

    public static func hash(_ data: Data) -> Data {
        Data(hash([UInt8](data)))
    }
}

private extension UInt32 {
    func rotateLeft(_ n: UInt32) -> UInt32 {
        (self << n) | (self >> (32 - n))
    }
}
