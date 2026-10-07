import Foundation

/// SoftEther PACK value.
public enum PackValue: Equatable {
    case int(UInt32)
    case data(Data)
    case str(String)
    case unistr(String)
    case int64(UInt64)

    var typeCode: UInt32 {
        switch self {
        case .int: return 0
        case .data: return 1
        case .str: return 2
        case .unistr: return 3
        case .int64: return 4
        }
    }
}

public enum PackError: Error { case truncated, badType(UInt32), badName }

/// SoftEther PACK: ordered list of named elements, each with one or more values. Big-endian.
public struct Pack: Equatable {
    public struct Element: Equatable {
        public var name: String
        public var values: [PackValue]
    }
    public private(set) var elements: [Element] = []

    public init() {}

    public mutating func add(_ name: String, _ value: PackValue) {
        // SoftEther compares element names case-insensitively and rejects packs with duplicates.
        elements.removeAll { $0.name.caseInsensitiveCompare(name) == .orderedSame }
        elements.append(Element(name: name, values: [value]))
    }
    public mutating func addInt(_ n: String, _ v: UInt32) { add(n, .int(v)) }
    public mutating func addBool(_ n: String, _ v: Bool) { add(n, .int(v ? 1 : 0)) }
    public mutating func addStr(_ n: String, _ v: String) { add(n, .str(v)) }
    public mutating func addUni(_ n: String, _ v: String) { add(n, .unistr(v)) }
    public mutating func addData(_ n: String, _ v: Data) { add(n, .data(v)) }
    public mutating func addInt64(_ n: String, _ v: UInt64) { add(n, .int64(v)) }

    /// IPv4 address stored the way SoftEther's PackAddIp does it.
    public mutating func addIPv4(_ name: String, _ ip: UInt32) {
        addBool(name + "@ipv6_bool", false)
        addData(name + "@ipv6_array", Data(count: 16))
        addInt(name + "@ipv6_scope_id", 0)
        addInt(name, ip)
    }

    public func value(_ name: String) -> PackValue? {
        elements.first { $0.name.caseInsensitiveCompare(name) == .orderedSame }?.values.first
    }
    public func int(_ name: String) -> UInt32? {
        switch value(name) {
        case .int(let v): return v
        case .int64(let v): return UInt32(truncatingIfNeeded: v)
        default: return nil
        }
    }
    public func str(_ name: String) -> String? {
        switch value(name) {
        case .str(let s), .unistr(let s): return s
        default: return nil
        }
    }
    public func data(_ name: String) -> Data? {
        if case .data(let d)? = value(name) { return d }
        return nil
    }

    // MARK: serialize

    public func serialize() -> Data {
        var out = Data()
        func u32(_ v: UInt32) { withUnsafeBytes(of: v.bigEndian) { out.append(contentsOf: $0) } }
        u32(UInt32(elements.count))
        for e in elements {
            let nameBytes = Array(e.name.utf8)
            u32(UInt32(nameBytes.count + 1))
            out.append(contentsOf: nameBytes)
            u32(e.values.first?.typeCode ?? 0)
            u32(UInt32(e.values.count))
            for v in e.values {
                switch v {
                case .int(let n): u32(n)
                case .data(let d): u32(UInt32(d.count)); out.append(d)
                case .str(let s):
                    let b = Array(s.utf8); u32(UInt32(b.count)); out.append(contentsOf: b)
                case .unistr(let s):
                    let b = Array(s.utf8); u32(UInt32(b.count + 1)); out.append(contentsOf: b); out.append(0)
                case .int64(let n): withUnsafeBytes(of: n.bigEndian) { out.append(contentsOf: $0) }
                }
            }
        }
        return out
    }

    // MARK: parse

    public init(parsing data: Data) throws {
        let bytes = [UInt8](data)
        var pos = 0
        func u32() throws -> UInt32 {
            guard pos + 4 <= bytes.count else { throw PackError.truncated }
            let v = bytes[pos..<pos+4].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
            pos += 4
            return v
        }
        func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, pos + n <= bytes.count else { throw PackError.truncated }
            defer { pos += n }
            return Array(bytes[pos..<pos+n])
        }
        let count = try u32()
        guard count < 4096 else { throw PackError.truncated }
        for _ in 0..<count {
            let nl = Int(try u32()) - 1
            guard nl >= 0, nl < 64 else { throw PackError.badName }
            let name = String(decoding: try take(nl), as: UTF8.self)
            let type = try u32()
            let n = try u32()
            guard n < 65536 else { throw PackError.truncated }
            var vals: [PackValue] = []
            for _ in 0..<n {
                switch type {
                case 0: vals.append(.int(try u32()))
                case 1: vals.append(.data(Data(try take(Int(try u32())))))
                case 2: vals.append(.str(String(decoding: try take(Int(try u32())), as: UTF8.self)))
                case 3:
                    var b = try take(Int(try u32()))
                    if b.last == 0 { b.removeLast() }
                    vals.append(.unistr(String(decoding: b, as: UTF8.self)))
                case 4:
                    let hi = UInt64(try u32()), lo = UInt64(try u32())
                    vals.append(.int64(hi << 32 | lo))
                default: throw PackError.badType(type)
                }
            }
            elements.append(Element(name: name, values: vals))
        }
    }
}
