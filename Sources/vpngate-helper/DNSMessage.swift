import Foundation

/// A tiny, read-mostly DNS message parser/writer: just enough to read a query's question name, pull A-record
/// answers out of a response (for dynamic routing) and build NXDOMAIN/SERVFAIL replies — not a general DNS
/// library. Packets are `[UInt8]`, like the rest of the packet path (EthernetBridge, Utun).
enum DNSMessage {
    struct Header {
        var ancount: Int, qdcount: Int
    }

    static func header(_ p: [UInt8]) -> Header? {
        guard p.count >= 12 else { return nil }
        return Header(ancount: Int(p[6]) << 8 | Int(p[7]), qdcount: Int(p[4]) << 8 | Int(p[5]))
    }

    /// The first question's name, lowercased and dot-joined with no trailing dot; nil if malformed or absent.
    static func queryName(_ p: [UInt8]) -> String? {
        guard let h = header(p), h.qdcount >= 1 else { return nil }
        return readName(p, 12)?.name.lowercased()
    }

    /// A recursive type-A query for `name` (a plain dotted DNS name).
    static func aQuery(name: String, id: UInt16) -> [UInt8] {
        var q: [UInt8] = [UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        for label in name.split(separator: ".") {
            let bytes = Array(label.utf8.prefix(63))
            q.append(UInt8(bytes.count)); q.append(contentsOf: bytes)
        }
        q.append(0)
        q.append(contentsOf: [0, 1, 0, 1])                  // QTYPE A, QCLASS IN
        return q
    }

    /// Resolved IPv4 addresses (type-A records) in the answer section of a response.
    static func resolvedIPv4Addresses(_ p: [UInt8]) -> [String] {
        guard let h = header(p) else { return [] }
        var offset = 12
        for _ in 0..<h.qdcount {
            guard let afterName = skipName(p, offset) else { return [] }
            offset = afterName + 4                               // QTYPE + QCLASS
        }
        var out = [String]()
        for _ in 0..<h.ancount {
            guard let afterName = skipName(p, offset), afterName + 10 <= p.count else { break }
            offset = afterName
            let type = Int(p[offset]) << 8 | Int(p[offset + 1])
            let rdlength = Int(p[offset + 8]) << 8 | Int(p[offset + 9])
            offset += 10
            guard offset + rdlength <= p.count else { break }
            if type == 1 && rdlength == 4 {
                out.append("\(p[offset]).\(p[offset + 1]).\(p[offset + 2]).\(p[offset + 3])")
            }
            offset += rdlength
        }
        return out
    }

    /// NXDOMAIN (RCODE 3): what a `.block` domain gets back.
    static func blockedResponse(for query: [UInt8]) -> [UInt8] { fixedRCodeResponse(for: query, rcode: 3) }
    /// SERVFAIL (RCODE 2): whenever a query cannot be answered safely (no usable upstream, it failed, the query
    /// itself did not parse). Never falls back to answering some other way — that would risk a leak or a lie.
    static func servfailResponse(for query: [UInt8]) -> [UInt8] { fixedRCodeResponse(for: query, rcode: 2) }

    private static func fixedRCodeResponse(for query: [UInt8], rcode: UInt8) -> [UInt8] {
        guard query.count >= 12 else { return query }
        var out = query
        out[2] |= 0x80                                    // QR = 1 (this is a response)
        out[3] = (out[3] & 0xF0) | (rcode & 0x0F)
        out[6] = 0; out[7] = 0                             // ANCOUNT = 0
        out[8] = 0; out[9] = 0                             // NSCOUNT = 0
        out[10] = 0; out[11] = 0                           // ARCOUNT = 0
        // Drop anything past the question section (there should be no answers to drop from a query, but be safe).
        if let afterQuestion = skipName(out, 12).map({ $0 + 4 }), afterQuestion <= out.count {
            return Array(out[0..<afterQuestion])
        }
        return out
    }

    /// Advances past one (possibly pointer-compressed) name; returns the offset right after it.
    private static func skipName(_ p: [UInt8], _ offset: Int) -> Int? {
        var o = offset, steps = 0
        while true {
            guard o < p.count, steps < 128 else { return nil }
            steps += 1
            let len = Int(p[o])
            if len == 0 { return o + 1 }
            if len & 0xC0 == 0xC0 { return o + 2 }         // pointer: 2 bytes, terminal
            o += 1 + len
        }
    }

    /// Like `skipName`, but also decodes the labels (pointers are not followed — not needed for a question name,
    /// which is never compressed in a message a resolver sends us).
    private static func readName(_ p: [UInt8], _ offset: Int) -> (name: String, next: Int)? {
        var o = offset, steps = 0
        var labels = [String]()
        while true {
            guard o < p.count, steps < 128 else { return nil }
            steps += 1
            let len = Int(p[o])
            if len == 0 { return (labels.joined(separator: "."), o + 1) }
            if len & 0xC0 == 0xC0 { return nil }
            guard o + 1 + len <= p.count else { return nil }
            labels.append(String(decoding: p[(o + 1)..<(o + 1 + len)], as: UTF8.self))
            o += 1 + len
        }
    }
}
