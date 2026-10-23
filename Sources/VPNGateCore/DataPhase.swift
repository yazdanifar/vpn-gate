import Foundation
import zlib

public enum DataPhaseItem: Equatable {
    case frame([UInt8])
    case keepAlive
}

public enum DataPhaseError: Error, Equatable, LocalizedError {
    case oversizedBlock(Int)
    case badBlockCount(Int)
    case badKeepAlive(Int)
    case decompressionFailed
    case compressionFailed

    public var errorDescription: String? {
        switch self {
        case .oversizedBlock(let n): return "Oversized block (\(n) bytes)"
        case .badBlockCount(let n): return "Bad block count (\(n))"
        case .badKeepAlive(let n): return "Bad keep-alive length (\(n))"
        case .decompressionFailed: return "Zlib block decompression failed"
        case .compressionFailed: return "Zlib block compression failed"
        }
    }
}

/// Wire format after login (SoftEther Connection.c): `u32 n` then n × (`u32 size` + frame),
/// or the keep-alive marker `0xFFFFFFFF`, `u32 len`, len junk bytes. Big-endian.
public enum DataPhase {
    public static let maxBlock = 3200
    public static let maxBlocksPerBatch = 4095
    public static let keepAliveMagic: UInt32 = 0xFFFF_FFFF
    public static let maxKeepAlive = 4095

    /// Compress an individual Ethernet frame with zlib (deflate).
    /// `capacity` overrides the output buffer size (default `compressBound`); only tests shrink it to force a zlib error.
    public static func compressFrame(_ frame: [UInt8], capacity: Int? = nil) throws -> [UInt8] {
        var destLen = uLongf(capacity ?? Int(compressBound(uLong(frame.count))))
        var dest = [UInt8](repeating: 0, count: Int(destLen))
        let rc = compress(&dest, &destLen, frame, uLong(frame.count))
        guard rc == Z_OK else { throw DataPhaseError.compressionFailed }  // never send the raw frame as if it were a zlib block
        return Array(dest.prefix(Int(destLen)))
    }

    /// Decompress a zlib-compressed Ethernet frame.
    public static func uncompressFrame(_ data: [UInt8], maxLen: Int = 4096) throws -> [UInt8] {
        var destLen = uLongf(maxLen)
        var dest = [UInt8](repeating: 0, count: maxLen)
        let rc = uncompress(&dest, &destLen, data, uLong(data.count))
        guard rc == Z_OK else { throw DataPhaseError.decompressionFailed }
        return Array(dest.prefix(Int(destLen)))
    }

    public static func encode(frames: [[UInt8]]) -> [UInt8] {
        var out = be32(UInt32(frames.count))
        for f in frames {
            out += be32(UInt32(f.count))
            out += f
        }
        return out
    }

    public static func encode(frames: [[UInt8]], useCompress: Bool) throws -> [UInt8] {
        guard useCompress else { return encode(frames: frames) }
        return encode(frames: try frames.map { try compressFrame($0) })
    }

    public static func encodeKeepAlive(junk: [UInt8]) -> [UInt8] {
        be32(keepAliveMagic) + be32(UInt32(junk.count)) + junk
    }
}

/// Incremental decoder: feed it whatever chunks the socket returns.
public struct DataPhaseDecoder {
    private enum State {
        case header
        case keepAliveLength
        case keepAliveBody(Int)
        case blockSize(remaining: Int)
        case blockBody(size: Int, remaining: Int)
    }
    private var buf = ByteBuffer()
    private var state = State.header
    public var useCompress: Bool = false

    public init(useCompress: Bool = false) {
        self.useCompress = useCompress
    }

    private mutating func u32() -> UInt32? {
        guard let b = buf.take(4) else { return nil }
        return rd32(b, 0)
    }

    public mutating func feed(_ bytes: [UInt8]) throws -> [DataPhaseItem] {
        buf.append(bytes)
        var out: [DataPhaseItem] = []
        while true {
            switch state {
            case .header:
                guard let n = u32() else { return out }
                if n == DataPhase.keepAliveMagic {
                    state = .keepAliveLength
                } else if n == 0 {
                    continue
                } else if n > UInt32(DataPhase.maxBlocksPerBatch) {
                    throw DataPhaseError.badBlockCount(Int(n))
                } else {
                    state = .blockSize(remaining: Int(n))
                }
            case .keepAliveLength:
                guard let n = u32() else { return out }
                if n > UInt32(DataPhase.maxKeepAlive) { throw DataPhaseError.badKeepAlive(Int(n)) }
                state = .keepAliveBody(Int(n))
            case .keepAliveBody(let n):
                guard buf.take(n) != nil else { return out }
                out.append(.keepAlive)
                state = .header
            case .blockSize(let remaining):
                guard let n = u32() else { return out }
                if n > UInt32(DataPhase.maxBlock) { throw DataPhaseError.oversizedBlock(Int(n)) }
                state = .blockBody(size: Int(n), remaining: remaining)
            case .blockBody(let size, let remaining):
                guard let raw = buf.take(size) else { return out }
                if useCompress {
                    let frame = try DataPhase.uncompressFrame(raw)
                    out.append(.frame(frame))
                } else {
                    out.append(.frame(raw))
                }
                state = remaining > 1 ? .blockSize(remaining: remaining - 1) : .header
            }
        }
    }
}
