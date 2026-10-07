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
