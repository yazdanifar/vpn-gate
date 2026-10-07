import Foundation

public typealias MAC = [UInt8]

public func checksum(_ b: [UInt8]) -> UInt16 {
    var sum: UInt32 = 0
    var i = 0
    while i + 1 < b.count { sum += UInt32(b[i]) << 8 | UInt32(b[i+1]); i += 2 }
    if i < b.count { sum += UInt32(b[i]) << 8 }
    while sum >> 16 != 0 { sum = (sum & 0xffff) + (sum >> 16) }
    return ~UInt16(sum)
}

public func be16(_ v: Int) -> [UInt8] { [UInt8(v >> 8 & 0xff), UInt8(v & 0xff)] }
public func be32(_ v: UInt32) -> [UInt8] { (0..<4).map { UInt8(v >> UInt32(24 - 8 * $0) & 0xff) } }
public func rd16(_ b: [UInt8], _ o: Int) -> Int { Int(b[o]) << 8 | Int(b[o+1]) }
public func rd32(_ b: [UInt8], _ o: Int) -> UInt32 { b[o..<o+4].reduce(0) { $0 << 8 | UInt32($1) } }

public let broadcastMAC: MAC = [UInt8](repeating: 0xff, count: 6)

public func ipString(_ ip: UInt32) -> String { be32(ip).map(String.init).joined(separator: ".") }

public enum Ethernet {
    public static func frame(dst: MAC, src: MAC, type: Int, payload: [UInt8]) -> [UInt8] {
        dst + src + be16(type) + payload
    }
}

public struct ARPPacket {
    public var op: Int
    public var senderMAC: MAC, senderIP: UInt32, targetMAC: MAC, targetIP: UInt32

    public init(op: Int, senderMAC: MAC, senderIP: UInt32, targetMAC: MAC, targetIP: UInt32) {
        self.op = op; self.senderMAC = senderMAC; self.senderIP = senderIP
        self.targetMAC = targetMAC; self.targetIP = targetIP
    }
    public func encode() -> [UInt8] {
        [0, 1, 8, 0, 6, 4] + be16(op) + senderMAC + be32(senderIP) + targetMAC + be32(targetIP)
    }
    public init?(_ p: [UInt8]) {
        guard p.count >= 28, rd16(p, 0) == 1, rd16(p, 2) == 0x0800 else { return nil }
        op = rd16(p, 6)
        senderMAC = Array(p[8..<14]); senderIP = rd32(p, 14)
        targetMAC = Array(p[18..<24]); targetIP = rd32(p, 24)
    }
}

public enum IPv4 {
    public static func packet(proto: UInt8, src: UInt32, dst: UInt32, payload: [UInt8]) -> [UInt8] {
        var h: [UInt8] = [0x45, 0] + be16(20 + payload.count) + [0, 0, 0, 0, 64, proto, 0, 0]
            + be32(src) + be32(dst)
        let c = checksum(h)
        h[10] = UInt8(c >> 8); h[11] = UInt8(c & 0xff)
        return h + payload
    }
    /// Returns (protocol, src, dst, payload) for a well-formed IPv4 packet.
    public static func parse(_ p: [UInt8]) -> (proto: UInt8, src: UInt32, dst: UInt32, payload: [UInt8])? {
        guard p.count >= 20, p[0] >> 4 == 4 else { return nil }
        let ihl = Int(p[0] & 0xf) * 4
        let total = min(rd16(p, 2), p.count)
        guard ihl >= 20, total >= ihl else { return nil }
        return (p[9], rd32(p, 12), rd32(p, 16), Array(p[ihl..<total]))
    }
}

public enum DHCPType: UInt8 { case discover = 1, offer = 2, request = 3, ack = 5, nak = 6 }

public struct DHCPMessage {
    public var type: DHCPType
    public var xid: UInt32
    public var yiaddr: UInt32 = 0
    public var ciaddr: UInt32 = 0
    public var mac: MAC
    // options
    public var serverID: UInt32?
    public var requestedIP: UInt32?
    public var subnetMask: UInt32?
    public var router: UInt32?
    public var dns: [UInt32] = []
    public var leaseSeconds: UInt32?

    public init(type: DHCPType, xid: UInt32, mac: MAC) { self.type = type; self.xid = xid; self.mac = mac }

    /// BOOTP/DHCP payload (to be carried in UDP 68 -> 67).
    public func encode() -> [UInt8] {
        var b: [UInt8] = [1, 1, 6, 0] + be32(xid) + [0, 0, 0x80, 0]   // broadcast flag
        b += be32(ciaddr) + [UInt8](repeating: 0, count: 12)           // ciaddr, then yiaddr siaddr giaddr
        b += mac + [UInt8](repeating: 0, count: 10)
        b += [UInt8](repeating: 0, count: 192)                         // sname + file
        b += [99, 130, 83, 99]
        b += [53, 1, type.rawValue]
        if let r = requestedIP { b += [50, 4] + be32(r) }
        if let s = serverID { b += [54, 4] + be32(s) }
        b += [55, 4, 1, 3, 6, 51]
        b += [255]
        return b
    }

    public init?(_ p: [UInt8]) {
        guard p.count >= 240, p[0] == 2, rd32(p, 236) == 0x63825363 else { return nil }
        xid = rd32(p, 4); yiaddr = rd32(p, 16); mac = Array(p[28..<34])
        var t: DHCPType?
        var i = 240
        while i < p.count {
            let c = p[i]
            if c == 255 { break }
            if c == 0 { i += 1; continue }
            guard i + 1 < p.count else { break }
            let l = Int(p[i+1]); let s = i + 2
            guard s + l <= p.count else { break }
            switch c {
            case 53 where l == 1: t = DHCPType(rawValue: p[s])
            case 54 where l == 4: serverID = rd32(p, s)
            case 1 where l == 4: subnetMask = rd32(p, s)
            case 3 where l >= 4: router = rd32(p, s)
            case 6 where l >= 4: dns = stride(from: 0, to: l - 3, by: 4).map { rd32(p, s + $0) }
            case 51 where l == 4: leaseSeconds = rd32(p, s)
            default: break
            }
            i = s + l
        }
        guard let tt = t else { return nil }
        type = tt
    }
}

public enum UDP {
    public static func datagram(src: UInt32, dst: UInt32, sport: Int, dport: Int, payload: [UInt8]) -> [UInt8] {
        var u = be16(sport) + be16(dport) + be16(8 + payload.count) + [0, 0] + payload
        let pseudo = be32(src) + be32(dst) + [0, 17] + be16(u.count)
        var c = checksum(pseudo + u)
        if c == 0 { c = 0xffff }
        u[6] = UInt8(c >> 8); u[7] = UInt8(c & 0xff)
        return u
    }
    public static func parse(_ p: [UInt8]) -> (sport: Int, dport: Int, payload: [UInt8])? {
        guard p.count >= 8 else { return nil }
        let len = min(rd16(p, 4), p.count)
        guard len >= 8 else { return nil }
        return (rd16(p, 0), rd16(p, 2), Array(p[8..<len]))
    }
}
