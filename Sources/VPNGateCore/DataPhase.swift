import Foundation

public enum DataPhaseItem: Equatable {
    case frame([UInt8])
    case keepAlive
}

public enum DataPhaseError: Error, Equatable, LocalizedError {
    case oversizedBlock(Int)
    case badBlockCount(Int)
    case badKeepAlive(Int)

    public var errorDescription: String? {
        switch self {
        case .oversizedBlock(let n): return "Oversized block (\(n) bytes)"
        case .badBlockCount(let n): return "Bad block count (\(n))"
        case .badKeepAlive(let n): return "Bad keep-alive length (\(n))"
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

    public static func encode(frames: [[UInt8]]) -> [UInt8] {
        var out = be32(UInt32(frames.count))
        for f in frames { out += be32(UInt32(f.count)); out += f }
        return out
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

    public init() {}

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
                if n == DataPhase.keepAliveMagic { state = .keepAliveLength }
                else if n == 0 { continue }
                else if n > UInt32(DataPhase.maxBlocksPerBatch) { throw DataPhaseError.badBlockCount(Int(n)) }
                else { state = .blockSize(remaining: Int(n)) }
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
                guard let f = buf.take(size) else { return out }
                out.append(.frame(f))
                state = remaining > 1 ? .blockSize(remaining: remaining - 1) : .header
            }
        }
    }
}
