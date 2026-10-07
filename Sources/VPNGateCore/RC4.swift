import Foundation

/// RC4 (ARC4) stream cipher.
/// SoftEther uses RC4 for VPNGate.dat body decryption (key = SHA1(seed)) and
/// legacy password hashing/scrambling.
public struct RC4 {
    private var s: [UInt8] = Array(0...255)
    private var i: UInt8 = 0
    private var j: UInt8 = 0

    public init(key: [UInt8]) {
        guard !key.isEmpty else { return }
        var jIndex: UInt8 = 0
        for iIndex in 0..<256 {
            let k = key[iIndex % key.count]
            jIndex = jIndex &+ s[iIndex] &+ k
            s.swapAt(iIndex, Int(jIndex))
        }
    }

    public init(key: Data) {
        self.init(key: [UInt8](key))
    }

    /// Process (encrypt/decrypt) data in-place.
    public mutating func process(_ bytes: inout [UInt8]) {
        for idx in 0..<bytes.count {
            i = i &+ 1
            j = j &+ s[Int(i)]
            s.swapAt(Int(i), Int(j))
            let t = s[Int(i)] &+ s[Int(j)]
            bytes[idx] ^= s[Int(t)]
        }
    }

    /// Process (encrypt/decrypt) data and return result.
    public mutating func process(_ data: [UInt8]) -> [UInt8] {
        var copy = data
        process(&copy)
        return copy
    }

    /// Process (encrypt/decrypt) Data and return result.
    public mutating func process(_ data: Data) -> Data {
        var bytes = [UInt8](data)
        process(&bytes)
        return Data(bytes)
    }

    /// One-shot convenience cipher.
    public static func cipher(key: [UInt8], data: [UInt8]) -> [UInt8] {
        var rc4 = RC4(key: key)
        return rc4.process(data)
    }

    public static func cipher(key: Data, data: Data) -> Data {
        var rc4 = RC4(key: key)
        return rc4.process(data)
    }
}
