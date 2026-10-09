import Foundation
import VPNGateCore

private func dhcpOptions(_ p: [UInt8]) -> [UInt8: [UInt8]] {
    var out: [UInt8: [UInt8]] = [:]
    var i = 240
    while i < p.count, p[i] != 255 {
        if p[i] == 0 { i += 1; continue }
        let l = Int(p[i + 1]); out[p[i]] = Array(p[(i + 2)..<(i + 2 + l)]); i += 2 + l
    }
    return out
}

private func makeBridge(_ net: FakeNetworkServer, timeout: Double = 0.5, retries: Int = 3) -> EthernetBridge {
    let b = EthernetBridge(timing: BridgeTiming(dhcpTimeout: timeout, dhcpRetries: retries))
    wire(b, to: net)
    return b
}

private let gw: UInt32 = 0x0AE9FEFE
private let myIP: UInt32 = 0x0AE991B6

// MARK: IPv6 fixtures

private let v6MAC: MAC = [0x5E, 0x00, 0x11, 0x22, 0x33, 0x44]
private let v6Local = hex6("fe80::5c00:11ff:fe22:3344")           // EUI-64 link-local of v6MAC
private let peerMAC: MAC = [0x02, 0, 0, 0, 0, 0x01]
private let peerLL = hex6("fe80::1")
private let allNodes = hex6("ff02::1")

private func v6Bridge(timing: BridgeTiming = BridgeTiming()) -> (EthernetBridge, Locked<[[UInt8]]>) {
    let b = EthernetBridge(timing: timing, mac: v6MAC)
    let out = Locked([[UInt8]]())
    b.sendFrame = { f in out.update { $0.append(f) } }
    return (b, out)
}

/// Ethernet frame carrying an ICMPv6 message; the checksum is filled in unless `corrupt` flips it afterwards.
private func icmp6Frame(dstMAC: MAC, srcMAC: MAC = peerMAC, src: [UInt8], dst: [UInt8], icmp: [UInt8],
                        hop: UInt8 = 255, corrupt: Bool = false) -> [UInt8] {
    var m = icmp; m[2] = 0; m[3] = 0
    let c = ICMPv6.checksum(src: src, dst: dst, icmpPayload: m)
    m[2] = UInt8(c >> 8); m[3] = UInt8(c & 0xff) ^ (corrupt ? 1 : 0)
    let ip = IPv6.header(src: src, dst: dst, nextHeader: 58, payloadLen: m.count, hopLimit: hop) + m
    return Ethernet.frame(dst: dstMAC, src: srcMAC, type: 0x86DD, payload: ip)
}

private func nsFrame(target: [UInt8], src: [UInt8] = peerLL, dst: [UInt8]? = nil, dstMAC: MAC? = nil, hop: UInt8 = 255,
                     corrupt: Bool = false) -> [UInt8] {
    let d = dst ?? IPv6.solicitedNodeMulticast(ip: target)
    let icmp = ICMPv6.neighborSolicitation(targetIP: target, srcMAC: peerMAC, srcIP: src, dstIP: d)
    return icmp6Frame(dstMAC: dstMAC ?? IPv6.multicastMAC(ip: d), src: src, dst: d, icmp: icmp, hop: hop, corrupt: corrupt)
}

/// Router Advertisement from `peerLL` with an SLLA option and one prefix option.
private func raFrame(prefix: String = "2001:db8:1:2::", flags: UInt8 = 0xC0, valid: UInt32 = 86400, preferred: UInt32 = 14400,
                     routerLifetime: Int = 1800, src: [UInt8] = peerLL, hop: UInt8 = 255, prefixLen: UInt8 = 64) -> [UInt8] {
    var icmp: [UInt8] = [134, 0, 0, 0, 64, 0] + be16(routerLifetime) + [0, 0, 0, 0, 0, 0, 0, 0]
    icmp += [1, 1] + peerMAC
    icmp += [3, 4, prefixLen, flags] + be32(valid) + be32(preferred) + [0, 0, 0, 0] + hex6(prefix)
    return icmp6Frame(dstMAC: IPv6.multicastMAC(ip: allNodes), src: src, dst: allNodes, icmp: icmp, hop: hop)
}

private func icmpType(_ frame: [UInt8]) -> UInt8 { frame[14 + 40] }
private func v6DataPacket(to dst: String, from src: [UInt8] = hex6("2001:db8:1:2:5c00:11ff:fe22:3344")) -> [UInt8] {
    IPv6.header(src: src, dst: hex6(dst), nextHeader: 17, payloadLen: 4) + [1, 2, 3, 4]
}

func registerBridgeIPv6Tests() {
    test("bridge6/neighbor-solicitation-is-answered-to-the-askers-mac-with-hop-limit-255") {       // review 5, 6
        let (b, out) = v6Bridge()
        // The NS frame goes to our solicited-node multicast MAC; the NA must NOT be sent there.
        b.fromHub(nsFrame(target: v6Local))
        expectEqual(out.value.count, 1)
        // Exact frame from an independent encoder: dst = asker's MAC, hop limit ff, S+O flags, TLLA = our MAC.
        expectEqual(out.value.first, bytes("0200000000015e001122334486dd6000000000203afffe800000000000005c0011fffe223344"
            + "fe800000000000000000000000000001880038ec60000000fe800000000000005c0011fffe22334402015e0011223344"))
    }
    test("bridge6/dad-probe-is-answered-to-all-nodes-with-solicited-clear") {                       // review 6
        let (b, out) = v6Bridge()
        b.fromHub(nsFrame(target: v6Local, src: hex6("::")))
        expectEqual(out.value.first, bytes("3333000000015e001122334486dd6000000000203afffe800000000000005c0011fffe223344"
            + "ff0200000000000000000000000000018800786a20000000fe800000000000005c0011fffe22334402015e0011223344"))
    }
    test("bridge6/invalid-or-foreign-solicitations-are-ignored") {                                  // review 5
        let (b, out) = v6Bridge()
        b.fromHub(nsFrame(target: hex6("fe80::9")))                                    // not our address
        b.fromHub(nsFrame(target: v6Local, hop: 64))                                   // crossed a router
        b.fromHub(nsFrame(target: v6Local, corrupt: true))                             // bad checksum
        b.fromHub(nsFrame(target: v6Local, dst: hex6("ff02::1:ff00:7")))               // not the solicited-node group of the target
        expectEqual(out.value.count, 0)
        b.handleIPv6 = false
        b.fromHub(nsFrame(target: v6Local))
        expectEqual(out.value.count, 0, "IPv6 disabled")
    }
    test("bridge6/router-advertisement-yields-a-slaac-address-and-is-not-passed-to-the-kernel") {   // review 7
        let (b, out) = v6Bridge()
        let addr = Locked([([UInt8], Int)]()); let delivered = Locked(0)
        b.deliverIPv6 = { _ in delivered.update { $0 += 1 } }
        b.startIPv6 { a, l in addr.update { $0.append((a, l)) } }
        b.fromHub(raFrame())
        b.fromHub(raFrame())                                                           // refresh: reported only once
        expectEqual(addr.value.count, 1)
        expectEqual(addr.value.first?.0, bytes("20010db8000100025c0011fffe223344"))     // prefix + EUI-64 of 5E:00:11:22:33:44
        expectEqual(addr.value.first?.1, 64)
        expectEqual(b.routerIPv6, peerLL); expectEqual(b.ipv6Address, bytes("20010db8000100025c0011fffe223344"))
        expectEqual(delivered.value, 0, "NDP is consumed by the bridge")
        // we now own the SLAAC address and answer for it
        out.update { $0.removeAll() }
        b.fromHub(nsFrame(target: bytes("20010db8000100025c0011fffe223344")))
        expectEqual(out.value.filter { icmpType($0) == 136 }.count, 1, "NA for the SLAAC address")
    }
    test("bridge6/address-reported-to-a-late-observer") {
        let (b, _) = v6Bridge()
        b.fromHub(raFrame())                                                           // RA arrives before the netconfig exists
        let addr = Locked(0)
        b.startIPv6 { _, _ in addr.update { $0 += 1 } }
        expectEqual(addr.value, 1)
    }
    test("bridge6/prefix-rules-A-flag-lifetimes-length-and-source") {                               // review 5, 7
        func address(_ f: [UInt8]) -> [UInt8]? {
            let (b, _) = v6Bridge(); b.fromHub(f); return b.ipv6Address
        }
        expect(address(raFrame()) != nil)
        expect(address(raFrame(flags: 0x80)) == nil, "no A flag: on-link only, no SLAAC address")
        expect(address(raFrame(valid: 0, preferred: 0)) == nil, "valid lifetime 0")
        expect(address(raFrame(valid: 100, preferred: 200)) == nil, "preferred > valid")
        expect(address(raFrame(prefixLen: 48)) == nil, "only /64 prefixes")
        expect(address(raFrame(prefix: "fe80::")) == nil, "link-local prefix")
        expect(address(raFrame(src: hex6("2001:db8::1"))) == nil, "RA must come from a link-local address")
        expect(address(raFrame(hop: 64)) == nil, "RA that crossed a router")
        expect(address(raFrame(valid: 0xffffffff, preferred: 0xffffffff)) != nil, "infinite lifetimes")
    }
    test("bridge6/valid-lifetime-expiry-stops-the-address-and-router") {                            // review 7
        let (b, out) = v6Bridge()
        let t = Locked(Date(timeIntervalSince1970: 1000)); b.now = { t.value }
        b.fromHub(raFrame(valid: 100, preferred: 50, routerLifetime: 30))
        expect(b.ipv6Address != nil)
        t.update { $0 = $0.addingTimeInterval(101) }
        expect(b.ipv6Address == nil, "expired")
        out.update { $0.removeAll() }
        b.fromHub(nsFrame(target: bytes("20010db8000100025c0011fffe223344")))
        expectEqual(out.value.count, 0, "no NA for an expired address")
        b.fromHost(v6DataPacket(to: "2001:db8:ffff::1"))
        expectEqual(out.value.count, 0, "router lifetime ran out: nothing to forward to")
    }
    test("bridge6/router-solicitations-repeat-with-backoff-until-an-advertisement-arrives") {         // review 7
        let (b, out) = v6Bridge(timing: BridgeTiming(rsInterval: 0.05, rsMaxInterval: 1, rsRetries: 4))
        let stamps = Locked([Date]())
        b.sendFrame = { f in if icmpType(f) == 133 { out.update { $0.append(f) }; stamps.update { $0.append(Date()) } } }
        b.startIPv6 { _, _ in }
        await expectA(await eventually(3) { out.value.count == 4 })
        // 0.05 + 0.10 + 0.20 s between the four attempts
        expect(stamps.value.last!.timeIntervalSince(stamps.value.first!) >= 0.3, "no backoff: \(stamps.value.map { $0.timeIntervalSince1970 })")
        let rs = out.value[0]
        expectEqual(Array(rs[0..<6]), [0x33, 0x33, 0, 0, 0, 2]); expectEqual(rs[14 + 7], 255, "hop limit")
        expectEqual(Array(rs[14 + 8..<14 + 24]), v6Local)
        try await Task.sleep(nanoseconds: 600_000_000)
        expectEqual(out.value.count, 4, "stops after the retry budget")

        let (b2, out2) = v6Bridge(timing: BridgeTiming(rsInterval: 0.2, rsMaxInterval: 1, rsRetries: 5))
        b2.sendFrame = { f in if icmpType(f) == 133 { out2.update { $0.append(f) } } }
        b2.startIPv6 { _, _ in }
        b2.fromHub(raFrame())
        try await Task.sleep(nanoseconds: 700_000_000)
        expectEqual(out2.value.count, 1, "no more solicitations once a router answered")
    }
    test("bridge6/outbound-packets-are-resolved-with-neighbor-discovery-not-broadcast") {            // review 7
        let (b, out) = v6Bridge()
        let t = Locked(Date(timeIntervalSince1970: 1000)); b.now = { t.value }
        b.fromHub(raFrame())
        t.update { $0 = $0.addingTimeInterval(61) }                                     // the RA's neighbour entry aged out
        let pkt = v6DataPacket(to: "2606:4700::1111")                                  // off-link: next hop is the router
        b.fromHost(pkt)
        // exact NS to the router's solicited-node group (independent encoder)
        expectEqual(out.value.last, bytes("3333ff0000015e001122334486dd6000000000203afffe800000000000005c0011fffe223344"
            + "ff0200000000000000000001ff00000187003ace00000000fe80000000000000000000000000000101015e0011223344"))
        b.fromHub(raFrame())                                                           // the RA's SLLA resolves the router again
        out.update { $0.removeAll() }
        b.fromHost(pkt)
        expectEqual(out.value, [Ethernet.frame(dst: peerMAC, src: v6MAC, type: 0x86DD, payload: pkt)])
    }
    test("bridge6/queued-packets-flush-after-the-advertisement-and-are-not-flooded") {
        let (b, out) = v6Bridge()
        let t = Locked(Date(timeIntervalSince1970: 1000)); b.now = { t.value }
        b.fromHub(raFrame())
        t.update { $0 = $0.addingTimeInterval(61) }                                     // neighbour entry aged out
        out.update { $0.removeAll() }
        let pkts = (1...3).map { v6DataPacket(to: "2606:4700::\($0)") }
        pkts.forEach { b.fromHost($0) }
        expectEqual(out.value.filter { icmpType($0) == 135 }.count, 1, "one NS, rate limited")
        expectEqual(out.value.filter { Array($0[0..<6]) == broadcastMAC }.count, 0, "IPv6 is never flooded to the broadcast MAC")
        // the router answers from a different MAC than the RA claimed
        let newMAC: MAC = [0x02, 0, 0, 0, 0, 0x77]
        let na = ICMPv6.neighborAdvertisement(targetIP: peerLL, targetMAC: newMAC, srcIP: peerLL, dstIP: v6Local)
        out.update { $0.removeAll() }
        b.fromHub(icmp6Frame(dstMAC: v6MAC, srcMAC: newMAC, src: peerLL, dst: v6Local, icmp: na))
        expectEqual(out.value, pkts.map { Ethernet.frame(dst: newMAC, src: v6MAC, type: 0x86DD, payload: $0) })
        // unsolicited advertisements for strangers do not create entries
        let evil = ICMPv6.neighborAdvertisement(targetIP: hex6("fe80::66"), targetMAC: newMAC, srcIP: hex6("fe80::66"), dstIP: v6Local)
        b.fromHub(icmp6Frame(dstMAC: v6MAC, src: hex6("fe80::66"), dst: v6Local, icmp: evil))
        out.update { $0.removeAll() }
        b.fromHost(v6DataPacket(to: "fe80::66"))
        expectEqual(out.value.filter { icmpType($0) == 135 }.count, 1, "stranger still has to be resolved")
    }
    test("bridge6/on-link-destinations-are-resolved-directly-and-unrouted-ones-dropped") {
        let (b, out) = v6Bridge()
        b.fromHost(v6DataPacket(to: "2606:4700::1")); expectEqual(out.value.count, 0, "no router yet")
        b.fromHub(raFrame())                                                           // L flag set: 2001:db8:1:2::/64 is on-link
        out.update { $0.removeAll() }
        b.fromHost(v6DataPacket(to: "2001:db8:1:2::99"))
        let ns = out.value.last!
        expectEqual(icmpType(ns), 135); expectEqual(Array(ns[14 + 48..<14 + 64]), hex6("2001:db8:1:2::99"), "target is the destination itself")
        out.update { $0.removeAll() }
        b.fromHost(IPv6.header(src: v6Local, dst: hex6("ff02::2"), nextHeader: 58, payloadLen: 0))
        expectEqual(out.value.first.map { Array($0[0..<6]) }, [0x33, 0x33, 0, 0, 0, 2], "multicast keeps its group MAC")
    }
    test("bridge6/blocked-bridge-sends-and-delivers-nothing") {
        let (b, out) = v6Bridge(); b.handleIPv6 = false
        let got = Locked(0); b.deliverIPv6 = { _ in got.update { $0 += 1 } }
        b.startIPv6 { _, _ in got.update { $0 += 100 } }
        b.fromHub(raFrame()); b.fromHost(v6DataPacket(to: "2606:4700::1"))
        try await Task.sleep(nanoseconds: 100_000_000)
        expectEqual(out.value.count, 0); expectEqual(got.value, 0)
    }
    test("bridge6/non-ndp-ipv6-from-the-hub-reaches-the-tun") {
        let (b, _) = v6Bridge()
        let got = Locked([[UInt8]]()); b.deliverIPv6 = { p in got.update { $0.append(p) } }
        let pkt = IPv6.header(src: hex6("2606:4700::1"), dst: hex6("2001:db8:1:2:5c00:11ff:fe22:3344"), nextHeader: 17, payloadLen: 4) + [1, 2, 3, 4]
        b.fromHub(Ethernet.frame(dst: v6MAC, src: peerMAC, type: 0x86DD, payload: pkt))
        expectEqual(got.value, [pkt])
    }
}

func registerBridgeTests() {
    test("bridge/dhcp-discover-offer-request-ack") {
        let net = FakeNetworkServer(); let b = makeBridge(net)
        let l = try await b.acquireLease()
        expectEqual(l.ip, myIP); expectEqual(l.router, gw); expectEqual(l.mask, 0xFFFF0000)
        expectEqual(l.dns, [gw, 0x08080808]); expectEqual(l.seconds, 3600); expectEqual(l.serverID, gw)
        expectEqual(net.count(.discover), 1); expectEqual(net.count(.request), 1)
        // REQUEST selects the offered address from the offering server
        let req = net.dhcpMessages.first { $0.type == .request }!.payload
        expectEqual(dhcpOptions(req)[50], be32(myIP)); expectEqual(dhcpOptions(req)[54], be32(gw))
    }
    test("bridge/dhcp-fails-when-nobody-answers") {
        let net = FakeNetworkServer(); net.silent = true
        let b = makeBridge(net, timeout: 0.1, retries: 2)
        do { _ = try await b.acquireLease(); fail("expected failure") } catch {}
        expectEqual(net.count(.discover), 2)
    }
    test("bridge/dhcp-ignores-replies-with-foreign-xid") {
        let net = FakeNetworkServer(); net.silent = true
        let b = EthernetBridge(timing: BridgeTiming(dhcpTimeout: 0.3, dhcpRetries: 1))
        b.sendFrame = { f in
            // answer with a different transaction id
            let real = FakeNetworkServer(); real.offeredIP = myIP
            for r in real.handle(f) {
                var r = r; r[14 + 20 + 8 + 4] ^= 0xFF           // corrupt xid inside the BOOTP header
                b.fromHub(r)
            }
        }
        do { _ = try await b.acquireLease(); fail("accepted foreign xid") } catch {}
    }
    test("bridge/dhcp-nak-restarts-immediately") {                       // B11
        let net = FakeNetworkServer(); net.nakCount = 1
        let b = makeBridge(net, timeout: 2, retries: 3)
        let start = Date()
        let l = try await b.acquireLease()
        expectEqual(l.ip, myIP)
        expect(Date().timeIntervalSince(start) < 1.0, "NAK should trigger an immediate new DISCOVER (took \(Date().timeIntervalSince(start))s)")
        expectEqual(net.count(.discover), 2)
    }
    test("bridge/renew-uses-ciaddr-not-selecting-options") {              // B11
        let net = FakeNetworkServer(); let b = makeBridge(net)
        _ = try await b.acquireLease()
        await b.renew()
        let renew = net.dhcpMessages.filter { $0.type == .request }.last!.payload
        expectEqual(Array(renew[12..<16]), be32(myIP), "ciaddr")
        let o = dhcpOptions(renew)
        expect(o[50] == nil && o[54] == nil, "renewing requests must not carry requested-ip/server-id options")
    }
    test("bridge/renew-with-new-address-reports-change") {               // B11
        let net = FakeNetworkServer(); let b = makeBridge(net)
        _ = try await b.acquireLease()
        let changed = Locked<Lease?>(nil)
        b.onLeaseChanged = { l in changed.update { $0 = l } }
        net.renewIP = 0x0AE99999
        await b.renew()
        expectEqual(changed.value?.ip, 0x0AE99999, "onLeaseChanged")
    }
    test("bridge/renew-silence-or-nak-reports-lease-lost") {              // B11
        let net = FakeNetworkServer(); let b = makeBridge(net, timeout: 0.2)
        _ = try await b.acquireLease()
        let lost = Locked(0)
        b.onLeaseLost = { lost.update { $0 += 1 } }
        net.nakCount = 1
        await b.renew()
        expectEqual(lost.value, 1, "NAK on renew")
        net.silent = true
        await b.renew()
        expectEqual(lost.value, 2, "no answer to renew")
    }
    test("bridge/arp-for-unresolved-next-hop-is-rate-limited") {         // B10
        let net = FakeNetworkServer(); net.answerARP = false
        let b = makeBridge(net); _ = try await b.acquireLease()
        let t = Locked(Date(timeIntervalSince1970: 1000)); b.now = { t.value }
        for _ in 0..<50 { b.fromHost(hostPacket(to: 0x08080808)) }
        expectEqual(net.arpRequestTargets.filter { $0 == gw }.count, 1, "ARP requests for the gateway within one second")
        t.update { $0 = $0.addingTimeInterval(1.1) }
        b.fromHost(hostPacket(to: 0x08080808))
        expectEqual(net.arpRequestTargets.filter { $0 == gw }.count, 2, "retry after the interval")
    }
    test("bridge/queued-packets-flush-in-order-after-arp-reply") {
        let net = FakeNetworkServer(); net.answerARP = false
        let b = makeBridge(net); _ = try await b.acquireLease()
        let pkts = (1...3).map { hostPacket(to: 0x08080808, payload: [UInt8($0), 0, 0, 0]) }
        pkts.forEach { b.fromHost($0) }
        expectEqual(net.ipv4Packets.count, 0)
        let reply = ARPPacket(op: 2, senderMAC: net.gatewayMAC, senderIP: gw, targetMAC: b.mac, targetIP: myIP)
        b.fromHub(Ethernet.frame(dst: b.mac, src: net.gatewayMAC, type: 0x0806, payload: reply.encode()))
        expectEqual(net.ipv4Packets, pkts)
    }
    test("bridge/stale-queued-packets-are-dropped") {                    // B10
        let net = FakeNetworkServer(); net.answerARP = false
        let b = makeBridge(net); _ = try await b.acquireLease()
        let t = Locked(Date(timeIntervalSince1970: 1000)); b.now = { t.value }
        b.fromHost(hostPacket(to: 0x08080808)); b.fromHost(hostPacket(to: 0x08080808))
        t.update { $0 = $0.addingTimeInterval(4) }
        let reply = ARPPacket(op: 2, senderMAC: net.gatewayMAC, senderIP: gw, targetMAC: b.mac, targetIP: myIP)
        b.fromHub(Ethernet.frame(dst: b.mac, src: net.gatewayMAC, type: 0x0806, payload: reply.encode()))
        expectEqual(net.ipv4Packets.count, 0, "packets queued 4s ago must not be sent late")
    }
    test("bridge/arp-cache-entries-expire") {                            // B10
        let net = FakeNetworkServer()
        let b = makeBridge(net); _ = try await b.acquireLease()
        let t = Locked(Date(timeIntervalSince1970: 1000)); b.now = { t.value }
        b.fromHost(hostPacket(to: 0x08080808))
        expectEqual(net.arpRequestTargets.filter { $0 == gw }.count, 1)
        b.fromHost(hostPacket(to: 0x08080808))
        expectEqual(net.arpRequestTargets.filter { $0 == gw }.count, 1, "cached")
        t.update { $0 = $0.addingTimeInterval(61) }
        b.fromHost(hostPacket(to: 0x08080808))
        expectEqual(net.arpRequestTargets.filter { $0 == gw }.count, 2, "re-resolved after the entry aged out")
        expectEqual(net.ipv4Packets.count, 3, "no packet lost while re-resolving")
    }
    test("bridge/answers-arp-only-for-own-address") {
        let net = FakeNetworkServer(); let b = makeBridge(net); _ = try await b.acquireLease()
        let out = Locked([[UInt8]]()); b.sendFrame = { f in out.update { $0.append(f) } }
        func ask(_ target: UInt32) {
            let a = ARPPacket(op: 1, senderMAC: net.gatewayMAC, senderIP: gw, targetMAC: [0,0,0,0,0,0], targetIP: target)
            b.fromHub(Ethernet.frame(dst: broadcastMAC, src: net.gatewayMAC, type: 0x0806, payload: a.encode()))
        }
        ask(0x0A0A0A0A); expectEqual(out.value.count, 0)
        ask(myIP)
        expectEqual(out.value.count, 1)
        let r = ARPPacket(Array(out.value[0][14...]))
        expectEqual(r?.op, 2); expectEqual(r?.senderIP, myIP); expectEqual(r?.senderMAC, b.mac)
    }
    test("bridge/delivers-ipv4-for-us-and-drops-the-rest") {
        let net = FakeNetworkServer(); let b = makeBridge(net); _ = try await b.acquireLease()
        let got = Locked(0); b.deliverIPv4 = { _ in got.update { $0 += 1 } }
        b.fromHub(ipv4Frame(dstMAC: b.mac, src: 1, dst: myIP)); expectEqual(got.value, 1, "unicast to us")
        b.fromHub(ipv4Frame(dstMAC: broadcastMAC, src: 1, dst: 0xFFFFFFFF)); expectEqual(got.value, 2, "broadcast")
        b.fromHub(ipv4Frame(dstMAC: [0x02, 9, 9, 9, 9, 9], src: 1, dst: myIP)); expectEqual(got.value, 2, "foreign unicast")
        b.fromHub(Ethernet.frame(dst: b.mac, src: [1,2,3,4,5,6], type: 0x86DD, payload: [UInt8](repeating: 0, count: 40)))
        expectEqual(got.value, 2, "IPv6 must be dropped")
        b.fromHub([1, 2, 3])                                           // runt frame
    }
    test("bridge/nothing-is-delivered-before-a-lease") {
        let b = EthernetBridge()
        let got = Locked(0); b.deliverIPv4 = { _ in got.update { $0 += 1 } }
        let sent = Locked(0); b.sendFrame = { _ in sent.update { $0 += 1 } }
        b.fromHub(ipv4Frame(dstMAC: b.mac, src: 1, dst: 2)); b.fromHost(hostPacket(to: 5))
        expectEqual(got.value, 0); expectEqual(sent.value, 0)
    }
    test("bridge/host-packets-on-link-broadcast-and-offlink") {
        let net = FakeNetworkServer(); let b = makeBridge(net); _ = try await b.acquireLease()
        b.fromHost(hostPacket(to: 0x0AE90101))                          // on-link peer → ARP for the peer itself
        expect(net.arpRequestTargets.contains(0x0AE90101), "on-link destination is resolved directly")
        let before = net.arpRequestTargets.count
        b.fromHost(hostPacket(to: 0xFFFFFFFF))
        expectEqual(net.arpRequestTargets.count, before, "broadcast needs no ARP")
        b.fromHost(hostPacket(to: 0x01010101))
        expect(net.arpRequestTargets.contains(gw), "off-link destination goes via the router")
    }
    test("bridge/gratuitous-arp-announces-our-address") {
        let net = FakeNetworkServer(); let b = makeBridge(net); _ = try await b.acquireLease()
        b.gratuitousARP()
        expect(net.arpRequestTargets.contains(myIP))
    }
    test("bridge/mac-is-unicast-and-prefixed") {
        for _ in 0..<50 { let m = EthernetBridge().mac; expectEqual(m[0], 0x5E); expect(m[0] & 1 == 0, "unicast"); expectEqual(m.count, 6) }
    }
}
