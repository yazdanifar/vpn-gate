import Foundation
import VPNGateCore

/// The "VPN side" of the L2 hub: answers DHCP and ARP like a SoftEther virtual router would.
final class FakeNetworkServer {
    var offeredIP: UInt32 = 0x0AE991B6  // 10.233.145.182
    var mask: UInt32 = 0xFFFF0000
    var router: UInt32 = 0x0AE9FEFE  // 10.233.254.254
    var dns: [UInt32] = [0x0AE9FEFE, 0x08080808]
    var leaseSeconds: UInt32 = 3600
    var serverID: UInt32 = 0x0AE9FEFE
    var gatewayMAC: MAC = [0x00, 0xAC, 0x11, 0x22, 0x33, 0x44]
    var answerARP = true
    var silent = false  // ignore DHCP entirely
    /// Number of upcoming REQUESTs to answer with NAK.
    var nakCount = 0
    /// IP handed out for REQUESTs with ciaddr set (renewals); nil = same as offered.
    var renewIP: UInt32?

    private let lock = NSLock()
    private var _dhcp: [(type: DHCPType, payload: [UInt8])] = []
    private var _arp: [UInt32] = []
    private var _ipv4: [[UInt8]] = []
    var dhcpMessages: [(type: DHCPType, payload: [UInt8])] { lock.lock(); defer { lock.unlock() }; return _dhcp }
    var arpRequestTargets: [UInt32] { lock.lock(); defer { lock.unlock() }; return _arp }
    var ipv4Packets: [[UInt8]] { lock.lock(); defer { lock.unlock() }; return _ipv4 }
    func count(_ t: DHCPType) -> Int { dhcpMessages.filter { $0.type == t }.count }

    /// Returns the frames the hub sends back for a frame from the client.
    func handle(_ f: [UInt8]) -> [[UInt8]] {
        guard f.count >= 14 else { return [] }
        let type = rd16(f, 12), payload = Array(f[14...])
        let srcMAC = Array(f[6..<12])
        if type == 0x0806, let a = ARPPacket(payload), a.op == 1 {
            lock.lock(); _arp.append(a.targetIP); lock.unlock()
            guard answerARP, a.targetIP == router else { return [] }
            let r = ARPPacket(op: 2, senderMAC: gatewayMAC, senderIP: router, targetMAC: a.senderMAC, targetIP: a.senderIP)
            return [Ethernet.frame(dst: srcMAC, src: gatewayMAC, type: 0x0806, payload: r.encode())]
        }
        guard type == 0x0800, let ip = IPv4.parse(payload) else { return [] }
        if ip.proto == 17, let u = UDP.parse(ip.payload), u.dport == 67, let t = Self.clientMessageType(u.payload) {
            lock.lock(); _dhcp.append((t, u.payload)); lock.unlock()
            return silent ? [] : dhcpReply(to: u.payload, t)
        }
        lock.lock(); _ipv4.append(payload); lock.unlock()
        return []
    }

    /// Message type of a client→server BOOTP packet (op 1), from option 53.
    static func clientMessageType(_ p: [UInt8]) -> DHCPType? {
        guard p.count >= 241, p[0] == 1, rd32(p, 236) == 0x63825363 else { return nil }
        var i = 240
        while i + 1 < p.count, p[i] != 255 {
            if p[i] == 0 { i += 1; continue }
            if p[i] == 53, p[i + 1] == 1, i + 2 < p.count { return DHCPType(rawValue: p[i + 2]) }
            i += 2 + Int(p[i + 1])
        }
        return nil
    }

    private func dhcpReply(to req: [UInt8], _ mtype: DHCPType) -> [[UInt8]] {
        var rtype: DHCPType
        var yi = offeredIP
        switch mtype {
        case .discover: rtype = .offer
        case .request:
            lock.lock(); let nak = nakCount > 0; if nak { nakCount -= 1 }; lock.unlock()
            rtype = nak ? .nak : .ack
            if rtype == .ack, rd32(req, 12) != 0, let r = renewIP { yi = r }
        default: return []
        }
        var b = Array(req[0..<236])
        b[0] = 2
        b.replaceSubrange(16..<20, with: be32(rtype == .nak ? 0 : yi))
        b += [99, 130, 83, 99, 53, 1, rtype.rawValue, 54, 4] + be32(serverID)
        if rtype != .nak {
            b += [1, 4] + be32(mask) + [3, 4] + be32(router)
            b += [6, UInt8(dns.count * 4)] + dns.flatMap { be32($0) }
            b += [51, 4] + be32(leaseSeconds)
        }
        b += [255]
        let udp = UDP.datagram(src: router, dst: 0xFFFFFFFF, sport: 67, dport: 68, payload: b)
        let ip = IPv4.packet(proto: 17, src: router, dst: 0xFFFFFFFF, payload: udp)
        return [Ethernet.frame(dst: broadcastMAC, src: gatewayMAC, type: 0x0800, payload: ip)]
    }
}

/// Builds an Ethernet/IPv4 UDP frame addressed to `dstMAC` (for feeding the bridge).
func ipv4Frame(
    dstMAC: MAC, srcMAC: MAC = [0, 1, 2, 3, 4, 5], src: UInt32, dst: UInt32, proto: UInt8 = 6,
    payload: [UInt8] = [1, 2, 3, 4]
) -> [UInt8] {
    Ethernet.frame(dst: dstMAC, src: srcMAC, type: 0x0800, payload: IPv4.packet(proto: proto, src: src, dst: dst, payload: payload))
}

/// A minimal IPv4 packet as produced by the host stack (for `fromHost`).
func hostPacket(to dst: UInt32, from src: UInt32 = 0x0AE991B6, payload: [UInt8] = [9, 9, 9, 9]) -> [UInt8] {
    IPv4.packet(proto: 6, src: src, dst: dst, payload: payload)
}
