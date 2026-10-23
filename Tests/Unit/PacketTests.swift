import Foundation
import VPNGateCore

func registerPacketTests() {
    test("packets/checksum-rfc1071") {
        let hdr: [UInt8] = [0x45, 0, 0, 0x73, 0, 0, 0x40, 0, 0x40, 0x11, 0, 0, 0xc0, 0xa8, 0, 1, 0xc0, 0xa8, 0, 0xc7]
        expectEqual(checksum(hdr), 0xb861)
        expectEqual(checksum([]), 0xffff)
        expectEqual(checksum([0xff]), 0x00ff)
    }
    test("packets/ipv4-roundtrip-and-valid-checksum") {
        let ip = IPv4.packet(proto: 17, src: 1, dst: 2, payload: [9, 9])
        expectEqual(checksum(Array(ip[0..<20])), 0)
        let p = IPv4.parse(ip)
        expectEqual(p?.payload, [9, 9]); expectEqual(p?.src, 1); expectEqual(p?.dst, 2); expectEqual(p?.proto, 17)
    }
    test("packets/ipv4-rejects-garbage") {
        expect(IPv4.parse([]) == nil)
        expect(IPv4.parse([UInt8](repeating: 0x60, count: 40)) == nil, "version 6")
        var bad = IPv4.packet(proto: 6, src: 1, dst: 2, payload: [1])
        bad[0] = 0x4F  // IHL 60 > total length
        expect(IPv4.parse(bad) == nil)
    }
    test("packets/arp-roundtrip") {
        let a = ARPPacket(op: 1, senderMAC: [1, 2, 3, 4, 5, 6], senderIP: 5, targetMAC: [0, 0, 0, 0, 0, 0], targetIP: 7)
        let b = ARPPacket(a.encode())
        expectEqual(b?.senderIP, 5); expectEqual(b?.targetIP, 7); expectEqual(b?.op, 1)
        expectEqual(b?.senderMAC, [1, 2, 3, 4, 5, 6])
        expect(ARPPacket([UInt8](repeating: 0, count: 10)) == nil)
    }
    test("packets/udp-roundtrip") {
        let u = UDP.datagram(src: 0, dst: 0xffffffff, sport: 68, dport: 67, payload: [1, 2, 3])
        expectEqual(UDP.parse(u)?.dport, 67); expectEqual(UDP.parse(u)?.payload, [1, 2, 3])
        expect(UDP.parse([1, 2, 3]) == nil)
    }
    test("dhcp/encode-layout") {
        var d = DHCPMessage(type: .request, xid: 0x01020304, mac: [1, 2, 3, 4, 5, 6])
        d.requestedIP = 0x0A000005; d.serverID = 0x0A000001
        let b = d.encode()
        expectEqual(Array(b[0..<8]), [1, 1, 6, 0, 1, 2, 3, 4])
        expectEqual(Array(b[28..<34]), [1, 2, 3, 4, 5, 6])
        expectEqual(Array(b[236..<240]), [99, 130, 83, 99])
        expectEqual(Array(b[240..<243]), [53, 1, 3])
        expect(b.last == 255)
    }
    test("dhcp/parse-server-reply") {
        let d = DHCPMessage(type: .discover, xid: 0x1234, mac: [1, 2, 3, 4, 5, 6])
        var r = d.encode(); r[0] = 2
        r.replaceSubrange(16..<20, with: be32(0x0a000005)); r.removeSubrange(240...)
        r += [53, 1, 5, 54, 4, 10, 0, 0, 1, 1, 4, 255, 255, 255, 0, 3, 4, 10, 0, 0, 1, 6, 8, 8, 8, 8, 8, 1, 1, 1, 1, 51, 4, 0, 0, 14, 16, 255]
        let m = DHCPMessage(r)
        expectEqual(m?.type, .ack); expectEqual(m?.yiaddr, 0x0a000005); expectEqual(m?.router, 0x0a000001)
        expectEqual(m?.dns ?? [], [0x08080808, 0x01010101]); expectEqual(m?.leaseSeconds, 3600)
        expectEqual(m?.subnetMask, 0xffffff00); expectEqual(m?.serverID, 0x0a000001)
    }
    test("dhcp/parse-rejects-garbage") {
        expect(DHCPMessage([UInt8](repeating: 0, count: 300)) == nil, "no cookie")
        var r = DHCPMessage(type: .discover, xid: 1, mac: [1, 2, 3, 4, 5, 6]).encode(); r[0] = 2
        expect(DHCPMessage(r) != nil)
        r[0] = 1
        expect(DHCPMessage(r) == nil, "client op")
        var trunc = DHCPMessage(type: .offer, xid: 1, mac: [1, 2, 3, 4, 5, 6]).encode(); trunc[0] = 2
        trunc.removeLast(); trunc += [6, 200]  // option claims 200 bytes, none present
        _ = DHCPMessage(trunc)  // must not crash
    }
    test("dhcp/ciaddr-is-encoded") {  // used by renewals (RFC 2131 §4.3.2)
        var d = DHCPMessage(type: .request, xid: 1, mac: [1, 2, 3, 4, 5, 6]); d.ciaddr = 0x0A000005
        expectEqual(Array(d.encode()[12..<16]), [10, 0, 0, 5])
    }
    test("packets/ipString-and-flag") {
        expectEqual(ipString(0x0A000001), "10.0.0.1")
        expectEqual(ipString(0xFFFFFFFF), "255.255.255.255")
    }
}
