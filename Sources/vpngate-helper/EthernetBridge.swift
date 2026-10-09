import Foundation
import VPNGateCore

struct Lease: Equatable {
    var ip: UInt32
    var mask: UInt32
    var router: UInt32
    var dns: [UInt32]
    var seconds: UInt32
    var serverID: UInt32
    var mtu: UInt16?
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
    /// Router Solicitations are repeated (interval doubling up to `rsMaxInterval`) until a Router Advertisement arrives.
    var rsInterval: Double = 4
    var rsMaxInterval: Double = 64
    var rsRetries = 8
}

/// Userspace L2 stack: lets an L3 utun device talk to SoftEther's L2 virtual hub.
/// Implements a DHCP client, ARP responder/resolver, and IPv4 framing.
final class EthernetBridge {
    private struct ARPEntry { var mac: MAC; var at: Date }
    private struct V6Prefix { var prefix: [UInt8]; var onLink: Bool; var autonomous: Bool; var validUntil: Date }
    private struct V6Router { var address: [UInt8]; var until: Date }
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
    var deliverIPv6: (([UInt8]) -> Void)?     // to utun
    var onLeaseChanged: ((Lease) -> Void)?    // renew returned a different address/router
    var onLeaseLost: (() -> Void)?            // renew got no answer or a NAK
    var now: () -> Date = Date.init
    private let timing: BridgeTiming
    var handleIPv6: Bool = true
    private var v6Prefix: V6Prefix?
    private var v6Router: V6Router?
    private var raSeen = false
    private var announcedV6: [UInt8]?
    private var onIPv6Address: ((_ address: [UInt8], _ prefixLength: Int) -> Void)?
    private var nd6Cache: [[UInt8]: ARPEntry] = [:]
    private var waiting6: [[UInt8]: Pending] = [:]
    /// The /64 learned from a Router Advertisement (valid lifetime not yet checked).
    var ipv6Prefix: [UInt8]? { lock.lock(); defer { lock.unlock() }; return v6Prefix?.prefix }
    var routerIPv6: [UInt8]? { lock.lock(); defer { lock.unlock() }; return v6Router?.address }
    /// Our SLAAC address while its valid lifetime has not run out.
    var ipv6Address: [UInt8]? { lock.lock(); defer { lock.unlock() }; return slaacAddress(at: now()) }

    init(timing: BridgeTiming = BridgeTiming(), mac fixedMAC: MAC? = nil) {
        self.timing = timing
        var m = (0..<6).map { _ in UInt8.random(in: 0...255) }
        m[0] = 0x5E; m[1] = 0x00 | (m[1] & 0xFE)    // locally administered-style prefix like SoftEther (5E:xx), unicast
        mac = fixedMAC ?? m
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
                          serverID: reply.serverID ?? offer.serverID ?? 0,
                          mtu: reply.mtu ?? offer.mtu)
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
        case 0x86DD:
            guard handleIPv6, forUs else { return }
            guard let v6 = IPv6.parse(payload) else { return }
            if v6.nextHeader == 58, v6.payload.count >= 4, (133...137).contains(v6.payload[0]) {
                // Neighbour Discovery is answered here, never handed to the kernel (which would otherwise
                // act on RAs and configure the utun a second time).
                handleNDP(v6, hopLimit: payload[7], srcMAC: Array(f[6..<12]))
                return
            }
            deliverIPv6?(payload)
        default:
            break
        }
    }

    // MARK: host -> hub

    func fromHost(_ pkt: [UInt8]) {
        guard !pkt.isEmpty else { return }
        let version = pkt[0] >> 4
        if version == 6 {
            fromHostIPv6(pkt)
            return
        }
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

    private func fromHostIPv6(_ pkt: [UInt8]) {
        guard handleIPv6, pkt.count >= 40 else { return }
        guard let v6 = IPv6.parse(pkt) else { return }
        if v6.dst[0] == 0xff {      // multicast
            sendFrame?(Ethernet.frame(dst: IPv6.multicastMAC(ip: v6.dst), src: mac, type: 0x86DD, payload: pkt))
            return
        }
        let t = now()
        lock.lock()
        // Link-local and on-link destinations are resolved directly; everything else goes to the router.
        var nextHop = v6.dst
        let onLink = IPv6.isLinkLocal(v6.dst)
            || (v6Prefix.map { $0.onLink && t < $0.validUntil && Array(v6.dst[0..<8]) == Array($0.prefix[0..<8]) } ?? false)
        if !onLink {
            guard let r = v6Router, t < r.until else { lock.unlock(); return }      // no IPv6 router: nothing to send to
            nextHop = r.address
        }
        var target: MAC?
        if let e = nd6Cache[nextHop] {
            if t.timeIntervalSince(e.at) <= timing.arpTTL { target = e.mac } else { nd6Cache[nextHop] = nil }
        }
        var sendRequest = false
        if target == nil {
            if waiting6[nextHop] == nil && waiting6.count >= timing.arpMaxQueued { lock.unlock(); return }
            var p = waiting6[nextHop] ?? Pending()
            p.packets.removeAll { t.timeIntervalSince($0.at) > timing.arpQueueMaxAge }
            if p.packets.count < timing.arpMaxQueued { p.packets.append((pkt, t)) }
            if p.lastRequest == nil || t.timeIntervalSince(p.lastRequest!) >= timing.arpRetryInterval {
                p.lastRequest = t; sendRequest = true
            }
            waiting6[nextHop] = p
        }
        lock.unlock()

        if let tm = target {
            sendFrame?(Ethernet.frame(dst: tm, src: mac, type: 0x86DD, payload: pkt))
        } else if sendRequest {
            let src = IPv6.linkLocal(mac: mac), dst = IPv6.solicitedNodeMulticast(ip: nextHop)
            let ns = ICMPv6.neighborSolicitation(targetIP: nextHop, srcMAC: mac, srcIP: src, dstIP: dst)
            sendFrame?(Ethernet.frame(dst: IPv6.multicastMAC(ip: dst), src: mac, type: 0x86DD,
                                      payload: IPv6.ndpPacket(src: src, dst: dst, icmp: ns)))
        }
    }

    // MARK: IPv6 neighbour discovery

    /// Starts IPv6 on the link: reports the SLAAC address (once, as soon as a Router Advertisement provides a
    /// usable prefix) and sends Router Solicitations with backoff until some router answers.
    func startIPv6(onAddress: @escaping (_ address: [UInt8], _ prefixLength: Int) -> Void) {
        guard handleIPv6 else { return }
        lock.lock()
        onIPv6Address = onAddress
        let known = announcedV6
        lock.unlock()
        if let a = known { onAddress(a, 64) }
        let first = timing.rsInterval, cap = timing.rsMaxInterval, tries = timing.rsRetries
        Task.detached { [weak self] in
            var wait = first
            for _ in 0..<tries {
                guard self?.solicitRouterIfNeeded() == true else { return }
                try? await Task.sleep(nanoseconds: UInt64(wait * 1_000_000_000))
                wait = min(wait * 2, cap)
            }
        }
    }

    private func solicitRouterIfNeeded() -> Bool {
        lock.lock(); let seen = raSeen; lock.unlock()
        if seen || !handleIPv6 { return false }
        let src = IPv6.linkLocal(mac: mac)
        let allRouters: [UInt8] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]
        let rs = ICMPv6.routerSolicitation(srcMAC: mac, srcIP: src)
        sendFrame?(Ethernet.frame(dst: IPv6.multicastMAC(ip: allRouters), src: mac, type: 0x86DD,
                                  payload: IPv6.ndpPacket(src: src, dst: allRouters, icmp: rs)))
        return true
    }

    /// Lock must be held.
    private func slaacAddress(at t: Date) -> [UInt8]? {
        guard let p = v6Prefix, p.autonomous, t < p.validUntil else { return nil }
        return IPv6.slaac(prefix: p.prefix, mac: mac)
    }

    /// Lock must be held. Returns the packets that were waiting for `ip`.
    private func learn6(_ ip: [UInt8], _ m: MAC, _ t: Date) -> [(pkt: [UInt8], at: Date)] {
        nd6Cache[ip] = ARPEntry(mac: m, at: t)
        return waiting6.removeValue(forKey: ip)?.packets ?? []
    }

    private func flush6(_ queued: [(pkt: [UInt8], at: Date)], _ t: Date) {
        for q in queued where t.timeIntervalSince(q.at) <= timing.arpQueueMaxAge { fromHostIPv6(q.pkt) }
    }

    /// Option of `type` (RFC 4861 §4.6) in an ICMPv6 NDP message whose options start at `from`; nil if absent or malformed.
    private func ndpOption(_ icmp: [UInt8], from: Int, type: UInt8) -> [UInt8]? {
        var i = from
        while i + 8 <= icmp.count {
            let len = Int(icmp[i + 1]) * 8
            guard len > 0, i + len <= icmp.count else { return nil }
            if icmp[i] == type { return Array(icmp[i + 2..<i + len]) }
            i += len
        }
        return nil
    }

    private func handleNDP(_ v6: (nextHeader: UInt8, src: [UInt8], dst: [UInt8], payload: [UInt8]), hopLimit: UInt8, srcMAC: MAC) {
        let icmp = v6.payload
        // RFC 4861 §7.1/§6.1: hop limit 255 (never forwarded by a router), code 0, valid checksum.
        guard hopLimit == 255, icmp[1] == 0, ICMPv6.isChecksumValid(src: v6.src, dst: v6.dst, icmp: icmp) else { return }
        let t = now()
        switch icmp[0] {
        case 135 where icmp.count >= 24:                                 // Neighbor Solicitation
            let target = Array(icmp[8..<24])
            guard target[0] != 0xff else { return }
            let probe = v6.src.allSatisfy { $0 == 0 }                    // DAD probe from ::
            guard v6.dst == IPv6.solicitedNodeMulticast(ip: target) || (!probe && v6.dst == target) else { return }
            let slla = probe ? nil : ndpOption(icmp, from: 24, type: 1)
            lock.lock()
            let queued = slla.flatMap { $0.count == 6 ? learn6(v6.src, $0, t) : nil } ?? []
            let own = [IPv6.linkLocal(mac: mac)] + (slaacAddress(at: t).map { [$0] } ?? [])
            lock.unlock()
            flush6(queued, t)
            guard own.contains(target) else { return }
            // Answer from the solicited address to the asker's own MAC (not to the multicast MAC it was sent to);
            // a DAD probe has no one to unicast to, so the answer goes to all nodes with S clear.
            let allNodes: [UInt8] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
            let dstIP = probe ? allNodes : v6.src
            let na = ICMPv6.neighborAdvertisement(targetIP: target, targetMAC: mac, srcIP: target, dstIP: dstIP, solicited: !probe)
            sendFrame?(Ethernet.frame(dst: probe ? IPv6.multicastMAC(ip: allNodes) : srcMAC, src: mac, type: 0x86DD,
                                      payload: IPv6.ndpPacket(src: target, dst: dstIP, icmp: na)))
        case 136 where icmp.count >= 24:                                 // Neighbor Advertisement
            let target = Array(icmp[8..<24])
            guard target[0] != 0xff else { return }
            let tlla = ndpOption(icmp, from: 24, type: 2)
            let m = (tlla?.count == 6 ? tlla : nil) ?? srcMAC
            lock.lock()
            // Only resolutions we asked for (or refreshes of known entries) are accepted.
            let queued = (waiting6[target] != nil || nd6Cache[target] != nil) ? learn6(target, m, t) : []
            lock.unlock()
            flush6(queued, t)
        case 134 where icmp.count >= 16:                                 // Router Advertisement
            guard IPv6.isLinkLocal(v6.src) else { return }
            handleRouterAdvertisement(v6.src, icmp, srcMAC: srcMAC, t)
        default:
            break                                                        // RS (we are not a router) and Redirect
        }
    }

    private func handleRouterAdvertisement(_ router: [UInt8], _ icmp: [UInt8], srcMAC: MAC, _ t: Date) {
        func until(_ seconds: UInt32) -> Date { seconds == 0xffffffff ? .distantFuture : t.addingTimeInterval(Double(seconds)) }
        let routerLifetime = UInt32(rd16(icmp, 6))
        let slla = ndpOption(icmp, from: 16, type: 1)
        var candidate: V6Prefix?
        var i = 16
        while i + 8 <= icmp.count {
            let len = Int(icmp[i + 1]) * 8
            guard len > 0, i + len <= icmp.count else { break }
            if icmp[i] == 3, len >= 32, candidate == nil, icmp[i + 2] == 64 {          // Prefix Information, /64 only
                let flags = icmp[i + 3], valid = rd32(icmp, i + 4), preferred = rd32(icmp, i + 8)
                let prefix = Array(icmp[i + 16..<i + 32])
                // RFC 4862 §5.5.3: preferred must not exceed valid; link-local prefixes are ignored.
                if valid > 0, preferred <= valid, !IPv6.isLinkLocal(prefix), prefix[0] != 0xff, flags & 0xc0 != 0 {
                    candidate = V6Prefix(prefix: prefix, onLink: flags & 0x80 != 0, autonomous: flags & 0x40 != 0, validUntil: until(valid))
                }
            }
            i += len
        }
        lock.lock()
        raSeen = true
        var queued: [(pkt: [UInt8], at: Date)] = []
        if routerLifetime == 0 {
            if v6Router?.address == router { v6Router = nil }
        } else {
            v6Router = V6Router(address: router, until: until(routerLifetime))
            queued = learn6(router, (slla?.count == 6 ? slla : nil) ?? srcMAC, t)
        }
        // One prefix per link: later RAs refresh it; a different prefix replaces it only after it has expired.
        if let c = candidate, v6Prefix == nil || v6Prefix!.prefix[0..<8] == c.prefix[0..<8] || t >= v6Prefix!.validUntil {
            v6Prefix = c
        }
        var announce: (address: [UInt8], handler: (([UInt8], Int) -> Void)?)?
        if let a = slaacAddress(at: t), announcedV6 != a {
            announcedV6 = a
            announce = (a, onIPv6Address)
        }
        lock.unlock()
        flush6(queued, t)
        if let a = announce { a.handler?(a.address, 64) }
    }

    /// Announce ourselves so the hub learns our MAC/IP.
    func gratuitousARP() {
        guard let l = currentLease() else { return }
        let a = ARPPacket(op: 1, senderMAC: mac, senderIP: l.ip, targetMAC: [0,0,0,0,0,0], targetIP: l.ip)
        sendFrame?(Ethernet.frame(dst: broadcastMAC, src: mac, type: 0x0806, payload: a.encode()))
    }
}
