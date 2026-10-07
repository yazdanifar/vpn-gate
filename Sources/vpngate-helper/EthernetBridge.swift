import Foundation
import VPNGateCore

struct Lease: Equatable {
    var ip: UInt32
    var mask: UInt32
    var router: UInt32
    var dns: [UInt32]
    var seconds: UInt32
    var serverID: UInt32
}

struct BridgeTiming {
    var dhcpTimeout: Double = 4
    var dhcpRetries = 6
    /// ARP cache entries older than this are re-resolved.
    var arpTTL: Double = 60
    /// Minimum spacing between ARP requests for the same next hop.
    var arpRetryInterval: Double = 1
    /// Packets waiting for ARP longer than this are dropped instead of being sent late.
    var arpQueueMaxAge: Double = 3
    var arpMaxQueued = 64
}

/// Userspace L2 stack: lets an L3 utun device talk to SoftEther's L2 virtual hub.
/// Implements a DHCP client, ARP responder/resolver, and IPv4 framing.
final class EthernetBridge {
    private struct ARPEntry { var mac: MAC; var at: Date }
    private struct Pending { var packets: [(pkt: [UInt8], at: Date)] = []; var lastRequest: Date? }

    let mac: MAC
    private let lock = NSLock()
    private(set) var lease: Lease?
    private var arpCache: [UInt32: ARPEntry] = [:]
    private var waiting: [UInt32: Pending] = [:]
    private var lastDHCP: DHCPMessage?
    private var xid = UInt32.random(in: 1...UInt32.max)

    var sendFrame: (([UInt8]) -> Void)?       // to hub
    var deliverIPv4: (([UInt8]) -> Void)?     // to utun
    var onLeaseChanged: ((Lease) -> Void)?    // renew returned a different address/router
    var onLeaseLost: (() -> Void)?            // renew got no answer or a NAK
    var now: () -> Date = Date.init
    private let timing: BridgeTiming

    init(timing: BridgeTiming = BridgeTiming()) {
        self.timing = timing
        var m = (0..<6).map { _ in UInt8.random(in: 0...255) }
        m[0] = 0x5E; m[1] = 0x00 | (m[1] & 0xFE)    // locally administered-style prefix like SoftEther (5E:xx), unicast
        mac = m
    }

    // MARK: DHCP

    private func newXid() -> UInt32 {
        lock.lock(); defer { lock.unlock() }
        xid = UInt32.random(in: 1...UInt32.max)
        lastDHCP = nil
        return xid
    }

    func acquireLease() async throws -> Lease {
        for _ in 0..<timing.dhcpRetries {
            let x = newXid()
            sendDHCP(DHCPMessage(type: .discover, xid: x, mac: mac))
            guard let offer = await waitDHCP([.offer], seconds: timing.dhcpTimeout) else { continue }
            var req = DHCPMessage(type: .request, xid: x, mac: mac)
            req.requestedIP = offer.yiaddr
            req.serverID = offer.serverID
            clearLast()
            sendDHCP(req)
            guard let reply = await waitDHCP([.ack, .nak], seconds: timing.dhcpTimeout) else { continue }
            if reply.type == .nak { continue }                       // start over immediately
            let l = Lease(ip: reply.yiaddr, mask: reply.subnetMask ?? 0xffffff00,
                          router: reply.router ?? offer.router ?? 0,
                          dns: reply.dns.isEmpty ? offer.dns : reply.dns,
                          seconds: reply.leaseSeconds ?? 3600,
                          serverID: reply.serverID ?? offer.serverID ?? 0)
            setLease(l)
            return l
        }
        throw StreamError.protocolError("DHCP failed: no lease from the VPN server")
    }

    /// Renews the current lease (RFC 2131 §4.3.2 RENEWING: ciaddr set, no requested-ip/server-id options).
    /// Reports `onLeaseChanged` if the server hands out different parameters, `onLeaseLost` on NAK/silence.
    func renew() async {
        guard let l = currentLease() else { return }
        let x = newXid()
        var req = DHCPMessage(type: .request, xid: x, mac: mac)
        req.ciaddr = l.ip
        sendDHCP(req)
        guard let reply = await waitDHCP([.ack, .nak], seconds: timing.dhcpTimeout), reply.type == .ack else {
            onLeaseLost?(); return
        }
        var n = l
        n.ip = reply.yiaddr
        n.mask = reply.subnetMask ?? l.mask
        n.router = reply.router ?? l.router
        n.seconds = reply.leaseSeconds ?? l.seconds
        if !reply.dns.isEmpty { n.dns = reply.dns }
        let changed = n.ip != l.ip || n.router != l.router || n.mask != l.mask
        setLease(n)
        if changed { onLeaseChanged?(n) }
    }

    private func currentLease() -> Lease? { lock.lock(); defer { lock.unlock() }; return lease }
    private func setLease(_ l: Lease) { lock.lock(); lease = l; lock.unlock() }
    private func clearLast() { lock.lock(); lastDHCP = nil; lock.unlock() }
    private func lastMessage() -> DHCPMessage? { lock.lock(); defer { lock.unlock() }; return lastDHCP }

    private func waitDHCP(_ types: [DHCPType], seconds: Double) async -> DHCPMessage? {
        let end = Date().addingTimeInterval(seconds)
        while Date() < end {
            if let m = lastMessage(), types.contains(m.type) { return m }
            try? await Task.sleep(nanoseconds: 10_000_000)
        }
        return nil
    }

    private func sendDHCP(_ m: DHCPMessage) {
        let udp = UDP.datagram(src: m.ciaddr, dst: 0xffffffff, sport: 68, dport: 67, payload: m.encode())
        let ip = IPv4.packet(proto: 17, src: m.ciaddr, dst: 0xffffffff, payload: udp)
        sendFrame?(Ethernet.frame(dst: broadcastMAC, src: mac, type: 0x0800, payload: ip))
    }

    // MARK: hub -> host

    func fromHub(_ f: [UInt8]) {
        guard f.count >= 14 else { return }
        let dst = Array(f[0..<6])
        let type = rd16(f, 12)
        let payload = Array(f[14...])
        let forUs = dst == mac || dst == broadcastMAC || (dst[0] & 1) == 1
        switch type {
        case 0x0806:
            guard let a = ARPPacket(payload) else { return }
            let t = now()
            lock.lock()
            var queued: [(pkt: [UInt8], at: Date)] = []
            if a.senderIP != 0 {
                arpCache[a.senderIP] = ARPEntry(mac: a.senderMAC, at: t)
                queued = waiting.removeValue(forKey: a.senderIP)?.packets ?? []
            }
            let myIP = lease?.ip
            lock.unlock()
            if a.op == 1, let myIP = myIP, a.targetIP == myIP {
                let r = ARPPacket(op: 2, senderMAC: mac, senderIP: myIP, targetMAC: a.senderMAC, targetIP: a.senderIP)
                sendFrame?(Ethernet.frame(dst: a.senderMAC, src: mac, type: 0x0806, payload: r.encode()))
            }
            // Flush in order, but never send packets that have been waiting too long.
            for q in queued where t.timeIntervalSince(q.at) <= timing.arpQueueMaxAge { fromHost(q.pkt) }
        case 0x0800:
            guard forUs, let ip = IPv4.parse(payload) else { return }
            if ip.proto == 17, let u = UDP.parse(ip.payload), u.dport == 68, let m = DHCPMessage(u.payload) {
                lock.lock()
                if m.xid == xid { lastDHCP = m }
                lock.unlock()
                return
            }
            lock.lock(); let have = lease != nil; lock.unlock()
            if have { deliverIPv4?(payload) }
        default:
            break   // IPv6 and others are dropped to avoid leaks around the tunnel
        }
    }

    // MARK: host -> hub

    func fromHost(_ pkt: [UInt8]) {
        guard pkt.count >= 20 else { return }
        let t = now()
        lock.lock()
        guard let l = lease else { lock.unlock(); return }
        let dst = rd32(pkt, 16)
        var nextHop = dst
        let onLink = (dst & l.mask) == (l.ip & l.mask)
        if !onLink { nextHop = l.router }
        let isBroadcast = dst == 0xffffffff || (onLink && (dst | ~l.mask) == dst) || (dst >> 28) == 0xE
        var target: MAC?
        if isBroadcast { target = broadcastMAC }
        else if let e = arpCache[nextHop] {
            if t.timeIntervalSince(e.at) <= timing.arpTTL { target = e.mac } else { arpCache[nextHop] = nil }
        }
        var sendRequest = false
        if target == nil {
            var p = waiting[nextHop] ?? Pending()
            p.packets.removeAll { t.timeIntervalSince($0.at) > timing.arpQueueMaxAge }
            if p.packets.count < timing.arpMaxQueued { p.packets.append((pkt, t)) }
            if p.lastRequest == nil || t.timeIntervalSince(p.lastRequest!) >= timing.arpRetryInterval {
                p.lastRequest = t; sendRequest = true
            }
            waiting[nextHop] = p
        }
        let myIP = l.ip
        lock.unlock()

        if let tm = target {
            sendFrame?(Ethernet.frame(dst: tm, src: mac, type: 0x0800, payload: pkt))
        } else if sendRequest {
            let req = ARPPacket(op: 1, senderMAC: mac, senderIP: myIP, targetMAC: [0,0,0,0,0,0], targetIP: nextHop)
            sendFrame?(Ethernet.frame(dst: broadcastMAC, src: mac, type: 0x0806, payload: req.encode()))
        }
    }

    /// Announce ourselves so the hub learns our MAC/IP.
    func gratuitousARP() {
        guard let l = currentLease() else { return }
        let a = ARPPacket(op: 1, senderMAC: mac, senderIP: l.ip, targetMAC: [0,0,0,0,0,0], targetIP: l.ip)
        sendFrame?(Ethernet.frame(dst: broadcastMAC, src: mac, type: 0x0806, payload: a.encode()))
    }
}
