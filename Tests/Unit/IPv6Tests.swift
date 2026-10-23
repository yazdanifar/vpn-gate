import Foundation
import VPNGateCore

/// IPv6 text -> bytes for test fixtures.
func hex6(_ s: String) -> [UInt8] {
    var a = in6_addr(); precondition(inet_pton(AF_INET6, s, &a) == 1)
    return withUnsafeBytes(of: &a) { Array($0) }
}
func bytes(_ hex: String) -> [UInt8] {
    stride(from: 0, to: hex.count, by: 2).map { UInt8(hex.dropFirst($0).prefix(2), radix: 16)! }
}

func registerIPv6Tests() {
    test("ipv6/link-local-and-multicast-addresses") {
        let mac: MAC = [0x5E, 0x00, 0x01, 0x02, 0x03, 0x04]
        let ll = IPv6.linkLocal(mac: mac)
        expectEqual(ll.count, 16)
        // Bit 1 inverted: 0x5E ^ 0x02 = 0x5C
        expectEqual(ll[0], 0xfe)
        expectEqual(ll[1], 0x80)
        expectEqual(ll[8], 0x5c)
        expectEqual(ll[11], 0xff)
        expectEqual(ll[12], 0xfe)

        let snm = IPv6.solicitedNodeMulticast(ip: ll)
        expectEqual(snm.prefix(12), [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01])

        let mMac = IPv6.multicastMAC(ip: snm)
        expectEqual(mMac.prefix(2), [0x33, 0x33])
    }

    test("ipv6/packet-header-and-parser-roundtrip") {
        let src: [UInt8] = (0..<16).map { UInt8($0 + 1) }
        let dst: [UInt8] = (0..<16).map { UInt8($0 + 17) }
        let payload: [UInt8] = Array("test ipv6 payload".utf8)
        let header = IPv6.header(src: src, dst: dst, nextHeader: 17, payloadLen: payload.count)
        let packet = header + payload

        let parsed = IPv6.parse(packet)
        expect(parsed != nil)
        expectEqual(parsed?.nextHeader, 17)
        expectEqual(parsed?.src, src)
        expectEqual(parsed?.dst, dst)
        expectEqual(parsed?.payload, payload)
    }

    test("ipv6/icmpv6-neighbor-advertisement-generation") {
        let mac: MAC = [0x5E, 0x00, 0x11, 0x22, 0x33, 0x44]
        let ip = IPv6.linkLocal(mac: mac)
        let peerIP: [UInt8] = [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        let na = ICMPv6.neighborAdvertisement(targetIP: ip, targetMAC: mac, srcIP: ip, dstIP: peerIP)
        expectEqual(na[0], 136, "Type must be 136 (Neighbor Advertisement)")
        expectEqual(na[1], 0, "Code must be 0")
        expect(na.count >= 24)
    }

    test("ipv6/icmpv6-checksum-matches-an-independent-implementation") {
        // Reference values computed with a separate RFC 4443 §2.3 implementation (python3).
        let mac: MAC = [0x5E, 0x00, 0x11, 0x22, 0x33, 0x44]
        let ll = IPv6.linkLocal(mac: mac)
        let peer = hex6("fe80::1")
        let na = ICMPv6.neighborAdvertisement(targetIP: ll, targetMAC: mac, srcIP: ll, dstIP: peer)
        expectEqual(na, bytes("880038ec60000000fe800000000000005c0011fffe22334402015e0011223344"))
        let dad = ICMPv6.neighborAdvertisement(targetIP: ll, targetMAC: mac, srcIP: ll, dstIP: hex6("ff02::1"), solicited: false)
        expectEqual(dad, bytes("8800786a20000000fe800000000000005c0011fffe22334402015e0011223344"))
        let ns = ICMPv6.neighborSolicitation(targetIP: ll, srcMAC: [2, 0, 0, 0, 0, 1], srcIP: peer, dstIP: hex6("ff02::1:ff22:3344"))
        expectEqual(ns, bytes("8700a7ce00000000fe800000000000005c0011fffe2233440101020000000001"))
        let rs = ICMPv6.routerSolicitation(srcMAC: mac, srcIP: ll)
        expectEqual(rs, bytes("85003a610000000001015e0011223344"))
        expect(ICMPv6.isChecksumValid(src: ll, dst: peer, icmp: na))
        var bad = na; bad[20] ^= 1
        expect(!ICMPv6.isChecksumValid(src: ll, dst: peer, icmp: bad), "corrupted message accepted")
    }

    test("ipv6/slaac-address-and-text-form") {
        let mac: MAC = [0x5E, 0x00, 0x11, 0x22, 0x33, 0x44]
        let a = IPv6.slaac(prefix: hex6("2001:db8:1:2::"), mac: mac)
        expectEqual(a, bytes("20010db8000100025c0011fffe223344"))
        expectEqual(IPv6.string(a), "2001:db8:1:2:5c00:11ff:fe22:3344")
        expect(IPv6.isLinkLocal(hex6("fe80::1")) && IPv6.isLinkLocal(hex6("febf::1")))
        expect(!IPv6.isLinkLocal(hex6("fec0::1")) && !IPv6.isLinkLocal(hex6("2001:db8::1")))
    }

    test("ipv6/ndp-packets-leave-with-hop-limit-255") {
        let p = IPv6.ndpPacket(src: hex6("fe80::1"), dst: hex6("fe80::2"), icmp: [135, 0, 0, 0])
        expectEqual(p[7], 255, "RFC 4861 §7.1.1"); expectEqual(p[6], 58); expectEqual(rd16(p, 4), 4)
        expectEqual(IPv6.header(src: hex6("::"), dst: hex6("::"), nextHeader: 6, payloadLen: 0)[7], 64, "data packets keep 64")
    }

    test("dhcp/option-26-mtu-is-accepted-only-within-576-to-1500") {
        func parse(_ mtu: Int) -> UInt16?? {
            var d: [UInt8] = [2, 1, 6, 0] + [0, 0, 0, 1] + [UInt8](repeating: 0, count: 20) + [0x5e, 1, 2, 3, 4, 5]
            d += [UInt8](repeating: 0, count: 10 + 192) + [99, 130, 83, 99, 53, 1, 5, 26, 2] + be16(mtu) + [255]
            return DHCPMessage(d).map { $0.mtu }
        }
        for ok in [576, 1280, 1500] { expectEqual(parse(ok), .some(UInt16(ok)), "\(ok)") }
        for bad in [0, 68, 575, 1501, 9000, 65535] { expectEqual(parse(bad), .some(nil), "\(bad) must be ignored") }
    }

    test("dhcp/option-26-mtu-parsing") {
        var baseDHCP: [UInt8] = [2, 1, 6, 0] + [0, 0, 0, 1] + [0, 0, 0, 0]
        baseDHCP += [0, 0, 0, 0] + [10, 0, 0, 1] + [0, 0, 0, 0] + [0, 0, 0, 0]
        baseDHCP += [0x5e, 1, 2, 3, 4, 5] + [UInt8](repeating: 0, count: 10)
        baseDHCP += [UInt8](repeating: 0, count: 192)
        baseDHCP += [99, 130, 83, 99]  // Magic cookie
        baseDHCP += [53, 1, 5]  // ACK
        baseDHCP += [26, 2, 0x05, 0x78]  // Option 26: MTU = 1400 (0x0578)
        baseDHCP += [255]

        let msg = DHCPMessage(baseDHCP)
        expect(msg != nil)
        expectEqual(msg?.mtu, 1400)
    }
}
