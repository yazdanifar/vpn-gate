import Foundation
import VPNGateCore

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

    test("dhcp/option-26-mtu-parsing") {
        var baseDHCP: [UInt8] = [2, 1, 6, 0] + [0, 0, 0, 1] + [0, 0, 0, 0]
        baseDHCP += [0, 0, 0, 0] + [10, 0, 0, 1] + [0, 0, 0, 0] + [0, 0, 0, 0]
        baseDHCP += [0x5e, 1, 2, 3, 4, 5] + [UInt8](repeating: 0, count: 10)
        baseDHCP += [UInt8](repeating: 0, count: 192)
        baseDHCP += [99, 130, 83, 99] // Magic cookie
        baseDHCP += [53, 1, 5]        // ACK
        baseDHCP += [26, 2, 0x05, 0x78] // Option 26: MTU = 1400 (0x0578)
        baseDHCP += [255]

        let msg = DHCPMessage(baseDHCP)
        expect(msg != nil)
        expectEqual(msg?.mtu, 1400)
    }
}
