import CryptoKit
import Foundation

public struct UdpAccelHeader {
    public var cookie: UInt32
    public var myTick: UInt64
    public var yourTick: UInt64
    public var size: UInt16
    /// The flag byte is upstream's COMPRESS flag (UdpAccel.c:353, :914): nonzero means the payload is zlib-compressed.
    /// A keep-alive is simply an empty payload with flag 0.
    public var compressed: Bool
}

public struct UdpAccelDecodedPacket {
    public var header: UdpAccelHeader
    public var payload: [UInt8]
}

/// UDP acceleration v2 packet framing and encryption (ChaCha20-Poly1305 RFC 8439).
/// Reference: SoftEther src/Cedar/UdpAccel.c (Version 2.0).
public enum UdpAccelPacket {
    public static let ivSize = 12
    public static let macSize = 16
    public static let minPlaintextSize = 4 + 8 + 8 + 2 + 1  // 23 bytes (Cookie + MyTick + YourTick + Size + Flag)
    public static let minPacketSize = ivSize + minPlaintextSize + macSize  // 51 bytes
    public static let maxPadding = 31  // upstream pads rand() % MIN(room, 32)

    /// Padding length for a packet carrying `dataSize` bytes (UdpAccel.c:535-540): zero when the packet already reaches
    /// `maxSize`, else `rand() % min(maxSize - current, 32)`. `random` receives the bound and returns a value below it.
    public static func paddingSize(dataSize: Int, maxSize: Int, random: (Int) -> Int = { Int.random(in: 0..<$0) }) -> Int {
        let current = minPacketSize + dataSize
        guard current < maxSize else { return 0 }
        return random(min(maxSize - current, 32))
    }

    /// Encrypts and encodes a UDP acceleration v2 packet.
    public static func encode(
        key32: [UInt8],
        iv: [UInt8],
        cookie: UInt32,
        myTick: UInt64,
        yourTick: UInt64,
        compressed: Bool,
        payload: [UInt8],
        paddingSize: Int = 0,
        plainMode: Bool = false
    ) throws -> (packet: [UInt8], nextIV: [UInt8]) {
        guard plainMode || key32.count >= 32 else {
            throw StreamError.protocolError("Invalid ChaCha20-Poly1305 key size (\(key32.count) < 32)")
        }
        guard plainMode || iv.count == ivSize else {
            throw StreamError.protocolError("Invalid IV size (\(iv.count) != \(ivSize))")
        }

        var plaintext = [UInt8]()
        plaintext.reserveCapacity(minPlaintextSize + payload.count + paddingSize)

        // 1. Cookie (4 bytes BE)
        var cookieBe = cookie.bigEndian
        withUnsafeBytes(of: &cookieBe) { plaintext.append(contentsOf: $0) }

        // 2. My Tick (8 bytes BE)
        var myTickBe = (myTick == 0 ? 1 : myTick).bigEndian
        withUnsafeBytes(of: &myTickBe) { plaintext.append(contentsOf: $0) }

        // 3. Your Tick (8 bytes BE)
        var yourTickBe = yourTick.bigEndian
        withUnsafeBytes(of: &yourTickBe) { plaintext.append(contentsOf: $0) }

        // 4. Size (2 bytes BE)
        var sizeBe = UInt16(clamping: payload.count).bigEndian
        withUnsafeBytes(of: &sizeBe) { plaintext.append(contentsOf: $0) }

        // 5. Flag (1 byte)
        plaintext.append(compressed ? 1 : 0)

        // 6. Data
        plaintext.append(contentsOf: payload)

        // 7. Padding (0..31 bytes; upstream never pads in plaintext mode)
        if paddingSize > 0, !plainMode {
            plaintext.append(contentsOf: [UInt8](repeating: 0, count: min(paddingSize, 32)))
        }

        // Plaintext mode (udp_acceleration_use_encryption == false): no IV, no AEAD, no MAC (UdpAccel.c:382,526).
        if plainMode { return (plaintext, iv) }

        // 8. ChaCha20-Poly1305 encrypt
        let symKey = SymmetricKey(data: key32.prefix(32))
        let nonce = try ChaChaPoly.Nonce(data: iv)
        let sealed = try ChaChaPoly.seal(plaintext, using: symKey, nonce: nonce)

        // Wire format: IV (12 B) + Ciphertext + Tag (16 B)
        var packet = iv
        packet.append(contentsOf: sealed.ciphertext)
        packet.append(contentsOf: sealed.tag)

        // Next IV: last 12 bytes of ciphertext (before tag), or fresh nonce
        let nextIV: [UInt8]
        if sealed.ciphertext.count >= ivSize {
            nextIV = Array(sealed.ciphertext.suffix(ivSize))
        } else {
            nextIV = iv
        }

        return (packet, nextIV)
    }

    /// Decrypts and decodes a received UDP acceleration v2 packet.
    public static func decode(packet: [UInt8], key32: [UInt8], plainMode: Bool = false) throws -> UdpAccelDecodedPacket {
        let plain: [UInt8]
        if plainMode {
            plain = packet  // no IV, no MAC (UdpAccel.c:738)
        } else {
            plain = try decrypt(packet: packet, key32: key32)
        }
        return try parse(plain)
    }

    private static func decrypt(packet: [UInt8], key32: [UInt8]) throws -> [UInt8] {
        guard packet.count >= minPacketSize else {
            throw StreamError.protocolError("UDP packet too short (\(packet.count) < \(minPacketSize))")
        }
        guard key32.count >= 32 else {
            throw StreamError.protocolError("Invalid ChaCha20-Poly1305 key size (\(key32.count) < 32)")
        }

        let iv = Array(packet[0..<ivSize])
        let ciphertextAndTag = Array(packet[ivSize...])
        guard ciphertextAndTag.count >= macSize else {
            throw StreamError.protocolError("UDP packet missing MAC")
        }

        let ciphertext = Array(ciphertextAndTag.dropLast(macSize))
        let tag = Array(ciphertextAndTag.suffix(macSize))

        let symKey = SymmetricKey(data: key32.prefix(32))
        let nonce = try ChaChaPoly.Nonce(data: iv)
        let box = try ChaChaPoly.SealedBox(nonce: nonce, ciphertext: Data(ciphertext), tag: Data(tag))
        return [UInt8](try ChaChaPoly.open(box, using: symKey))
    }

    private static func parse(_ plain: [UInt8]) throws -> UdpAccelDecodedPacket {
        guard plain.count >= minPlaintextSize else {
            throw StreamError.protocolError("Decrypted UDP packet too short (\(plain.count))")
        }

        let cookie = rd32(plain, 0)
        let myTick = rd64(plain, 4)
        let yourTick = rd64(plain, 12)
        let size = (UInt16(plain[20]) << 8) | UInt16(plain[21])
        let compressed = plain[22] != 0

        let dataOffset = 23
        let dataLen = Int(size)
        guard plain.count >= dataOffset + dataLen else {
            throw StreamError.protocolError("Truncated UDP payload (\(plain.count) < \(dataOffset + dataLen))")
        }

        let payload = Array(plain[dataOffset..<dataOffset + dataLen])
        let header = UdpAccelHeader(cookie: cookie, myTick: myTick, yourTick: yourTick, size: size, compressed: compressed)
        return UdpAccelDecodedPacket(header: header, payload: payload)
    }
}
