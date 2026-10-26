import CryptoKit
import Foundation
import VPNGateCore

// Golden transcripts: whole protocol exchanges recorded against the in-memory fakes with every random value injected.
// A port replays the `entropy` draws in order (asserting the same call sequence) and must then produce the same
// client->server bytes; the server->client bytes are what the fake answered. `scripts/gen-golden.sh` writes them to
// Tests/Fixtures/golden/transcripts/*.json and `Tests/Unit/GoldenTests.swift` fails when they go stale.

private func tHex(_ b: [UInt8]) -> String { b.map { String(format: "%02x", $0) }.joined() }
private func tHex(_ d: Data) -> String { tHex([UInt8](d)) }

/// Deterministic randomness (SplitMix64) that records every draw. Ports feed the recorded values back instead of
/// reimplementing the generator.
final class RecordingEntropy {
    private let lock = NSLock()
    private var state: UInt64
    private var _log: [GJ] = []
    init(seed: UInt64) { state = seed }
    var log: [GJ] { lock.lock(); defer { lock.unlock() }; return _log }

    private func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }

    var entropy: Entropy {
        Entropy(
            bytes: { [self] n in
                lock.lock(); defer { lock.unlock() }
                var out = [UInt8]()
                while out.count < n { var v = next(); for _ in 0..<8 where out.count < n { out.append(UInt8(v & 0xff)); v >>= 8 } }
                _log.append(["op": "bytes", "n": n, "hex": tHex(out)])
                return Data(out)
            },
            below: { [self] n in
                lock.lock(); defer { lock.unlock() }
                let v = Int(next() % UInt64(n))
                _log.append(["op": "below", "n": n, "value": v])
                return v
            })
    }
}

/// Wraps a stream and records both directions as ordered events shared by every connection of one transcript.
private final class Tape {
    private let lock = NSLock()
    private(set) var events: [GJ] = []
    private(set) var streams = 0
    func nextIndex() -> Int { lock.lock(); defer { lock.unlock() }; streams += 1; return streams - 1 }
    func add(_ e: GJ) { lock.lock(); events.append(e); lock.unlock() }
}

private final class TapStream: ByteStream {
    var buffer: ByteBuffer {
        get { inner.buffer }
        set { inner.buffer = newValue }
    }
    let inner: ByteStream
    let tape: Tape
    let index: Int
    init(_ inner: ByteStream, tape: Tape) { self.inner = inner; self.tape = tape; index = tape.nextIndex() }
    var remoteIPv4: String? { inner.remoteIPv4 }
    func start() async throws { try await inner.start() }
    func cancel() { inner.cancel() }
    func send(_ data: Data) async throws {
        tape.add(Self.clientEvent(conn: index, [UInt8](data)))
        try await inner.send(data)
    }
    func readChunk() async throws -> Data {
        let d = try await inner.readChunk()
        tape.add(["conn": index, "dir": "s2c", "hex": tHex(d)])
        return d
    }

    /// An HTTP request is split into head and body; the watermark upload (a ~8 KB constant image) is recorded as a flag
    /// plus the random padding behind it, so the file stays readable.
    static func clientEvent(conn: Int, _ b: [UInt8]) -> GJ {
        guard let end = (0..<max(0, b.count - 3)).first(where: { b[$0] == 13 && b[$0 + 1] == 10 && b[$0 + 2] == 13 && b[$0 + 3] == 10 })
        else { return ["conn": conn, "dir": "c2s", "kind": "data", "hex": tHex(b)] }
        let head = String(decoding: b[0..<end], as: UTF8.self)
        let body = Array(b[(end + 4)...])
        let mark = [UInt8](softEtherWaterMark)
        var e: GJ = ["conn": conn, "dir": "c2s", "kind": "http", "head": head]
        if body.starts(with: mark) {
            e["body"] = ["watermark": true, "paddingHex": tHex(Array(body[mark.count...]))] as GJ
        } else {
            e["bodyHex"] = tHex(body)
        }
        return e
    }
}

// MARK: - login transcripts

private let tHostKey = Data((0..<32).map { UInt8(0xA0 &+ $0) })
private let tEnvironment = ClientEnvironment(osName: "macOS", osVersion: "14.5.0", hostname: "golden-host")
private func gPemDER(_ pem: String) -> Data {
    Data(base64Encoded: pem.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined().filter { !$0.isWhitespace })!
}

private func welcomeJSON(_ w: Welcome) -> GJ {
    var o: GJ = [
        "sessionName": w.sessionName, "connectionName": w.connectionName, "timeoutMs": w.timeoutMs,
        "sessionKey": w.sessionKey.map(tHex) ?? NSNull(), "maxConnection": w.maxConnection, "useCompress": w.useCompress,
        "useEncrypt": w.useEncrypt, "halfConnection": w.halfConnection, "qos": w.qos,
        "enableUdpRecovery": w.enableUdpRecovery, "useUdpAcceleration": w.useUdpAcceleration,
        "udpAccelVersion": w.udpAccelVersion, "udpFastDisconnect": w.udpFastDisconnect,
    ]
    o["message"] = w.message ?? NSNull()
    o["udpServerIp"] = w.udpServerIp ?? NSNull()
    o["udpServerPort"] = w.udpServerPort.map { Int($0) } ?? NSNull()
    o["udpServerCookie"] = w.udpServerCookie.map { Int($0) } ?? NSNull()
    o["udpClientCookie"] = w.udpClientCookie.map { Int($0) } ?? NSNull()
    o["udpServerKey"] = w.udpServerKey.map(tHex) ?? NSNull()
    return o
}

private struct LoginScenario {
    var name: String
    var note: String
    var host = "203.0.113.7"
    var port: UInt16 = 443
    var hub = "VPNGATE"
    var user = "vpn"
    var auth: ClientAuth = .anonymous
    var authJSON: GJ = ["type": "anonymous"]
    var maxConnections = 1
    var useCompress = false
    var halfConnection = false
    var seed: UInt64 = 1
    var sendFrame: [UInt8]?
    var configure: (FakeSoftEtherServer) -> Void = { _ in }
    /// Runs when the n-th stream is created (0-based), before it is used.
    var onStream: (FakeSoftEtherServer, Int) -> Void = { _, _ in }
}

private func runLogin(_ sc: LoginScenario) async throws -> GJ {
    let server = FakeSoftEtherServer()
    sc.configure(server)
    let tape = Tape()
    let rec = RecordingEntropy(seed: sc.seed)
    let inner = server.factory
    let client = SoftEtherClient(
        host: sc.host, port: sc.port, hubName: sc.hub, userName: sc.user, auth: sc.auth, proxy: ProxySettings(),
        maxConnections: sc.maxConnections, useCompress: sc.useCompress, useUdpAccel: false, halfConnection: sc.halfConnection,
        uniqueId: HostUniqueId(key: tHostKey),
        makeStream: { h, p, px in
            let n = tape.streams
            sc.onStream(server, n)
            return TapStream(inner(h, p, px), tape: tape)
        },
        entropy: rec.entropy, environment: tEnvironment)
    var result: GJ
    do {
        let w = try await client.connect { _ in }
        result = ["ok": true, "welcome": welcomeJSON(w)]
        if let f = sc.sendFrame {
            client.sendFrame(f)
            let delivered = await eventuallyA(5) { server.framesReceived.count == 1 }
            precondition(delivered, "\(sc.name): the frame never reached the fake server")
        }
    } catch {
        result = ["ok": false, "error": error.localizedDescription]
    }
    client.close(nil)
    var out: GJ = [
        "name": sc.name, "note": sc.note,
        "config": [
            "host": sc.host, "port": Int(sc.port), "hub": sc.hub, "user": sc.user, "auth": sc.authJSON,
            "maxConnections": sc.maxConnections, "useCompress": sc.useCompress, "halfConnection": sc.halfConnection,
            "useUdpAccel": false, "hostUniqueIdKey": tHex(tHostKey),
            "environment": ["osName": tEnvironment.osName, "osVersion": tEnvironment.osVersion, "hostname": tEnvironment.hostname],
        ] as GJ,
        "entropy": rec.log, "events": tape.events, "result": result,
    ]
    if let f = sc.sendFrame { out["sentFrameHex"] = tHex(f) }
    return out
}

private func loginScenarios() -> [LoginScenario] {
    let cert = gPemDER(CertFixtures.certPEM)
    let key = gPemDER(CertFixtures.rsaPKCS8PEM)
    var all: [LoginScenario] = []

    var s = LoginScenario(name: "anonymous-welcome-and-frame", note: "Default VPN Gate login (authtype 0), then one Ethernet frame in the data phase.")
    s.sendFrame = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x5e, 0, 0, 0, 0, 1, 0x08, 0x06, 1, 2, 3, 4]
    all.append(s)

    s = LoginScenario(name: "password-hashed", note: "authtype 1: SHA-0 of password+UPPER(user), then SHA-0 with the server's 20-byte random.")
    s.user = "Alice"; s.auth = .hashedPassword("p@ss wörd"); s.authJSON = ["type": "hashedPassword", "password": "p@ss wörd"]
    s.seed = 2
    all.append(s)

    s = LoginScenario(name: "password-plain", note: "authtype 2: plain_password element.")
    s.auth = .plainPassword("hunter2"); s.authJSON = ["type": "plainPassword", "password": "hunter2"]; s.seed = 3
    all.append(s)

    s = LoginScenario(
        name: "certificate", note: "authtype 3: cert DER plus RSA PKCS#1 v1.5 SHA-1 signature (PKCS#8 key) over the server random.")
    s.auth = .certificate(certDer: cert, sign: CertAuth.signer(privateKeyDer: key))
    s.authJSON = ["type": "certificate", "certDerHex": tHex(cert), "privateKeyPKCS8Hex": tHex(key)]; s.seed = 4
    all.append(s)

    s = LoginScenario(name: "ticket", note: "authtype 99: ticket element (what a redirect hands to the second login).")
    s.auth = .ticket(Data(repeating: 0x5a, count: 20)); s.authJSON = ["type": "ticket", "ticketHex": tHex(Data(repeating: 0x5a, count: 20))]
    s.seed = 5
    all.append(s)

    s = LoginScenario(
        name: "cluster-redirect", note: "First login answers Redirect (new host, port list, ticket); the second connection logs in with that ticket.")
    s.seed = 6
    s.configure = {
        $0.redirect = true; $0.redirectHost = "198.51.100.9"; $0.redirectPorts = [992, 443]; $0.redirectTicket = Data((0..<20).map { UInt8($0 + 1) })
    }
    s.onStream = { server, n in if n == 1 { server.redirect = false } }
    all.append(s)

    s = LoginScenario(name: "watermark-rejected-plain-retry", note: "The server refuses the watermark (403); the client reconnects and uploads VPNCONNECT.")
    s.seed = 7
    s.configure = { $0.rejectWatermark = true }
    all.append(s)

    s = LoginScenario(name: "login-refused", note: "Welcome carries error 9 (user not found / auth failed).")
    s.seed = 8
    s.configure = { $0.loginError = 9 }
    all.append(s)

    s = LoginScenario(name: "welcome-missing-session-key", note: "A welcome without session_key is a protocol error.")
    s.seed = 9
    s.configure = {
        var p = Pack(); p.addStr("session_name", "SID-X"); p.addStr("connection_name", "CID-1")
        $0.welcomeOverride = p
    }
    all.append(s)

    s = LoginScenario(
        name: "welcome-full-fields", note: "Compression, QoS, UDP acceleration fields and a message in the welcome (client has UDP off, so only parsing).")
    s.seed = 10; s.maxConnections = 8; s.useCompress = true
    s.configure = {
        var p = Pack()
        p.addStr("session_name", "SID-VPN-FULL"); p.addStr("connection_name", "CID-7"); p.addInt("timeout", 12000)
        p.addData("session_key", Data((0..<20).map { UInt8(0x30 + $0) })); p.addInt("max_connection", 4)
        p.addBool("use_compress", true); p.addBool("use_encrypt", true); p.addBool("qos", true); p.addBool("enable_udp_recovery", false)
        p.addData("Msg", Data("Welcome to the test relay".utf8))
        p.addBool("use_udp_acceleration", true); p.addInt("udp_acceleration_version", 2)
        p.addStr("udp_acceleration_server_ip", "192.0.2.55"); p.addInt("udp_acceleration_server_port", 40001)
        p.addInt("udp_acceleration_server_cookie", 0x12345678); p.addInt("udp_acceleration_client_cookie", 0x87654321)
        p.addData("udp_acceleration_server_key_v2", Data(repeating: 0x99, count: 128))
        p.addBool("udp_accel_fast_disconnect_detect", true)
        $0.welcomeOverride = p; $0.useCompress = true
    }
    all.append(s)
    return all
}

private func hostIdCases() -> [GJ] {
    [Data((0..<32).map { UInt8($0) }), tHostKey, Data(repeating: 0, count: 32)].map { k in
        let id = HostUniqueId(key: k)
        return ["keyHex": tHex(k), "loginIdHex": tHex(id.loginId), "nodeIdHex": tHex(id.nodeId)]
    }
}

// MARK: - bridge transcripts

private let bMAC: MAC = [0x5E, 0x00, 0x11, 0x22, 0x33, 0x44]
private let bPeerMAC: MAC = [0x02, 0, 0, 0, 0, 0x01]
private let bFixedNow = Date(timeIntervalSince1970: 1_700_000_000)

/// Records every frame between the bridge and a hub, plus what it hands the host.
private final class BridgeTape {
    private let lock = NSLock()
    private(set) var events: [GJ] = []
    func add(_ dir: String, _ b: [UInt8]) { lock.lock(); events.append(["dir": dir, "hex": tHex(b)]); lock.unlock() }
    func note(_ k: String, _ v: Any) { lock.lock(); events.append(["dir": "note", k: v]); lock.unlock() }
}

private func ip4(_ v: UInt32) -> String { "\(v >> 24).\(v >> 16 & 255).\(v >> 8 & 255).\(v & 255)" }
private func leaseJSON(_ l: Lease) -> GJ {
    [
        "ip": ip4(l.ip), "mask": ip4(l.mask), "router": ip4(l.router), "dns": l.dns.map(ip4), "seconds": Int(l.seconds),
        "serverId": ip4(l.serverID), "mtu": l.mtu.map { Int($0) } ?? NSNull(),
    ]
}

/// A bridge on a fake L2 hub. `c2h` = bridge to hub, `h2c` = hub to bridge, `host` = IPv4/IPv6 delivered to the tun.
private func makeBridge(seed: UInt64, timing: BridgeTiming, net: FakeNetworkServer?, tape: BridgeTape, fixedMAC: MAC? = nil)
    -> (EthernetBridge, RecordingEntropy)
{
    let rec = RecordingEntropy(seed: seed)
    let b = EthernetBridge(timing: timing, mac: fixedMAC, entropy: rec.entropy)
    b.now = { bFixedNow }
    b.sendFrame = { [weak b] f in
        tape.add("c2h", f)
        guard let net else { return }
        for r in net.handle(f) { tape.add("h2c", r); b?.fromHub(r) }
    }
    b.deliverIPv4 = { tape.add("host4", $0) }
    b.deliverIPv6 = { tape.add("host6", $0) }
    return (b, rec)
}

private func bridgeDoc(_ name: String, _ note: String, _ b: EthernetBridge, _ rec: RecordingEntropy, _ tape: BridgeTape, config: GJ, result: GJ = [:])
    -> GJ
{
    ["name": name, "note": note, "mac": tHex(b.mac), "config": config, "entropy": rec.log, "events": tape.events, "result": result]
}

private func icmp6Frame(dstMAC: MAC, srcMAC: MAC = bPeerMAC, src: [UInt8], dst: [UInt8], icmp: [UInt8]) -> [UInt8] {
    var m = icmp; m[2] = 0; m[3] = 0
    let c = ICMPv6.checksum(src: src, dst: dst, icmpPayload: m)
    m[2] = UInt8(c >> 8); m[3] = UInt8(c & 0xff)
    let ip = IPv6.header(src: src, dst: dst, nextHeader: 58, payloadLen: m.count, hopLimit: 255) + m
    return Ethernet.frame(dst: dstMAC, src: srcMAC, type: 0x86DD, payload: ip)
}

private func v6(_ s: String) -> [UInt8] {
    var a = in6_addr(); precondition(inet_pton(AF_INET6, s, &a) == 1)
    return withUnsafeBytes(of: &a) { Array($0) }
}

private func bridgeCases() async -> [GJ] {
    var out: [GJ] = []

    // DHCP: discover -> offer -> request -> ack, then a gratuitous ARP.
    do {
        let tape = BridgeTape(), net = FakeNetworkServer()
        let (b, rec) = makeBridge(seed: 11, timing: BridgeTiming(dhcpTimeout: 2, dhcpRetries: 2), net: net, tape: tape)
        let lease = try? await b.acquireLease()
        b.gratuitousARP()
        out.append(
            bridgeDoc(
                "dhcp-lease-and-gratuitous-arp", "Random MAC and xid come from the entropy log; the hub is the FakeNetworkServer defaults.",
                b, rec, tape, config: ["fixedMac": NSNull(), "hub": hubJSON(net)],
                result: ["lease": lease.map(leaseJSON) ?? NSNull()]))
    }

    // DHCP: NAK to the first REQUEST, then a fresh discover cycle with a new xid.
    do {
        let tape = BridgeTape(), net = FakeNetworkServer(); net.nakCount = 1
        let (b, rec) = makeBridge(seed: 12, timing: BridgeTiming(dhcpTimeout: 2, dhcpRetries: 3), net: net, tape: tape)
        let lease = try? await b.acquireLease()
        out.append(
            bridgeDoc(
                "dhcp-nak-restarts", "The first REQUEST is answered with a NAK; the client starts over with a new xid.", b, rec, tape,
                config: ["fixedMac": NSNull(), "hub": hubJSON(net), "nakCount": 1], result: ["lease": lease.map(leaseJSON) ?? NSNull()]))
    }

    // DHCP renew with a different address.
    do {
        let tape = BridgeTape(), net = FakeNetworkServer()
        let (b, rec) = makeBridge(seed: 13, timing: BridgeTiming(dhcpTimeout: 2, dhcpRetries: 2), net: net, tape: tape)
        _ = try? await b.acquireLease()
        net.renewIP = 0x0AE991B7
        let changed = Locked<Lease?>(nil)
        b.onLeaseChanged = { l in changed.update { $0 = l } }
        tape.note("step", "renew")
        await b.renew()
        out.append(
            bridgeDoc(
                "dhcp-renew-new-address", "RENEWING request (ciaddr set, no requested-ip/server-id); the ACK carries another address.",
                b, rec, tape, config: ["fixedMac": NSNull(), "hub": hubJSON(net), "renewIp": ip4(0x0AE991B7)],
                result: ["leaseChanged": changed.value.map(leaseJSON) ?? NSNull(), "lease": b.lease.map(leaseJSON) ?? NSNull()]))
    }

    // ARP resolve of the router for host traffic, queued packets flushed after the reply, then inbound IPv4.
    do {
        let tape = BridgeTape(), net = FakeNetworkServer()
        let (b, rec) = makeBridge(seed: 14, timing: BridgeTiming(dhcpTimeout: 2, dhcpRetries: 2), net: net, tape: tape)
        _ = try? await b.acquireLease()
        tape.note("step", "host sends to 93.184.216.34 (needs ARP for the router)")
        let pkt = IPv4.packet(proto: 6, src: 0x0AE991B6, dst: 0x5DB8D822, payload: [9, 9, 9, 9])
        b.fromHost(pkt)
        tape.note("step", "hub sends 10.233.145.182 an IPv4 packet")
        let inbound = IPv4.packet(proto: 6, src: 0x5DB8D822, dst: 0x0AE991B6, payload: [1, 2, 3, 4])
        b.fromHub(Ethernet.frame(dst: b.mac, src: net.gatewayMAC, type: 0x0800, payload: inbound))
        tape.note("step", "ARP request for our address from a neighbour")
        let who = ARPPacket(op: 1, senderMAC: bPeerMAC, senderIP: 0x0AE90001, targetMAC: [0, 0, 0, 0, 0, 0], targetIP: 0x0AE991B6)
        b.fromHub(Ethernet.frame(dst: broadcastMAC, src: bPeerMAC, type: 0x0806, payload: who.encode()))
        out.append(
            bridgeDoc(
                "arp-resolve-and-inbound",
                "Outbound packet waits for ARP, is sent to the router MAC; inbound IPv4 goes to the host; an ARP request is answered.",
                b, rec, tape, config: ["fixedMac": NSNull(), "hub": hubJSON(net)], result: ["hostPacketHex": tHex(pkt)]))
    }

    // IPv6: RS out, RA in (SLAAC), NS in -> NA out, host packet via the learned router.
    do {
        let tape = BridgeTape()
        let (b, rec) = makeBridge(seed: 15, timing: BridgeTiming(rsRetries: 1), net: nil, tape: tape, fixedMAC: bMAC)
        let announced = Locked([GJ]())
        b.startIPv6 { addr, len in announced.update { $0.append(["addressHex": tHex(addr), "prefixLength": len]) } }
        let routerLL = v6("fe80::1"), allNodes = v6("ff02::1")
        var ra: [UInt8] = [134, 0, 0, 0, 64, 0] + be16(1800) + [0, 0, 0, 0, 0, 0, 0, 0]
        ra += [1, 1] + bPeerMAC
        ra += [3, 4, 64, 0xC0] + be32(86400) + be32(14400) + [0, 0, 0, 0] + v6("2001:db8:1:2::")
        tape.note("step", "router advertisement")
        b.fromHub(icmp6Frame(dstMAC: IPv6.multicastMAC(ip: allNodes), src: routerLL, dst: allNodes, icmp: ra))
        let mine = IPv6.linkLocal(mac: b.mac)
        let ns = ICMPv6.neighborSolicitation(targetIP: mine, srcMAC: bPeerMAC, srcIP: routerLL, dstIP: IPv6.solicitedNodeMulticast(ip: mine))
        tape.note("step", "neighbour solicitation for our link-local address")
        b.fromHub(
            icmp6Frame(
                dstMAC: IPv6.multicastMAC(ip: IPv6.solicitedNodeMulticast(ip: mine)), src: routerLL,
                dst: IPv6.solicitedNodeMulticast(ip: mine), icmp: ns))
        tape.note("step", "host sends to 2001:db8:ffff::1")
        let hostPkt = IPv6.header(src: b.ipv6Address ?? [], dst: v6("2001:db8:ffff::1"), nextHeader: 17, payloadLen: 4) + [1, 2, 3, 4]
        b.fromHost(hostPkt)
        out.append(
            bridgeDoc(
                "ipv6-slaac-nd", "Router Solicitation, Router Advertisement (SLAAC /64), NS answered, host packet sent to the router's MAC.",
                b, rec, tape, config: ["fixedMac": tHex(bMAC), "now": Int(bFixedNow.timeIntervalSince1970)],
                result: [
                    "announced": announced.value, "prefixHex": b.ipv6Prefix.map(tHex) ?? NSNull(),
                    "routerHex": b.routerIPv6.map(tHex) ?? NSNull(), "addressHex": b.ipv6Address.map(tHex) ?? NSNull(),
                    "hostPacketHex": tHex(hostPkt),
                ]))
    }
    return out
}

private func hubJSON(_ n: FakeNetworkServer) -> GJ {
    [
        "offeredIp": ip4(n.offeredIP), "mask": ip4(n.mask), "router": ip4(n.router), "dns": n.dns.map(ip4),
        "leaseSeconds": Int(n.leaseSeconds), "serverId": ip4(n.serverID), "gatewayMac": tHex(n.gatewayMAC),
    ]
}

// MARK: - DNS proxy transcripts

private final class ScriptedUpstream: DNSUpstream {
    var calls: [GJ] = []
    var answers: [String]?  // A records to return; nil = no answer (timeout)
    func query(_ message: [UInt8], server: String, timeoutMs: Int32) -> [UInt8]? {
        var call: GJ = ["server": server, "timeoutMs": Int(timeoutMs), "queryHex": tHex(message)]
        defer { calls.append(call) }
        guard let answers else { call["responseHex"] = NSNull(); return nil }
        var p = message
        p[2] |= 0x80
        p[6] = UInt8(answers.count >> 8); p[7] = UInt8(answers.count & 0xff)
        for a in answers { p += [0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 0x3C, 0, 4] + a.split(separator: ".").compactMap { UInt8($0) } }
        call["responseHex"] = tHex(p)
        return p
    }
}

/// Only `applyDynamicRule` matters to the DNS proxy; the rest of NetConfiguring is inert here.
private final class DynamicRuleRecorder: NetConfiguring {
    private(set) var rules: [(ip: String, action: RoutingAction)] = []
    func apply(
        iface: String, lease: Lease, bypassHost: String, blockIPv6: Bool, mtuOverride: Int?, routing: RoutingConfig?,
        dnsProxyAddress: String?
    ) throws {}
    func applyDynamicRule(ip: String, action: RoutingAction) { rules.append((ip, action)) }
    func directDNSServers() -> [String] { [] }
    func teardown() {}
}

private func dnsCases() -> [GJ] {
    struct Case {
        var name: String; var rules: [RoutingRule] = []; var def: RoutingAction = .proxy; var query: [UInt8]
        var answers: [String]?
    }
    let q = { (n: String) in DNSMessage.aQuery(name: n, id: 0x1234) }
    let cases: [Case] = [
        Case(name: "blocked-domain-nxdomain", rules: [RoutingRule(type: .domainSuffix, value: "ads.example", action: .block)], query: q("tracker.ads.example")),
        Case(
            name: "direct-domain-uses-physical-resolver", rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .direct)],
            query: q("www.example.com"), answers: ["93.184.216.34", "1.2.3.4"]),
        Case(
            name: "proxy-rule-installs-dynamic-route", rules: [RoutingRule(type: .domainSuffix, value: "example.org", action: .proxy)],
            def: .direct, query: q("example.org"), answers: ["5.6.7.8"]),
        Case(name: "unmatched-domain-uses-tunnel-resolver", query: q("unmatched.test"), answers: ["10.9.8.7"]),
        Case(name: "upstream-timeout-servfail", query: q("slow.test")),
        Case(name: "unparsable-query-servfail", query: [0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x00, 0, 1, 0, 1]),
    ]
    return cases.map { c in
        let net = DynamicRuleRecorder(), up = ScriptedUpstream()
        let proxy = DNSProxy(net: net, upstream: up)
        proxy.routing = RoutingConfig(rules: c.rules, defaultAction: c.def)
        proxy.tunnelDNSServers = ["10.0.0.1"]; proxy.directDNSServers = ["9.9.9.9"]
        up.answers = c.answers
        let response = proxy.handle(c.query)
        return [
            "name": c.name,
            "config": [
                "rules": c.rules.map { ["type": $0.type.rawValue, "value": $0.value, "action": $0.action.rawValue] as GJ },
                "defaultAction": c.def.rawValue, "tunnelDns": ["10.0.0.1"], "directDns": ["9.9.9.9"], "timeoutMs": 4000,
            ] as GJ,
            "queryHex": tHex(c.query), "upstreamCalls": up.calls, "responseHex": tHex(response),
            "dynamicRules": net.rules.map { ["ip": $0.ip, "action": $0.action.rawValue] as GJ },
        ]
    }
}

// MARK: - entry point

private func renderT(_ name: String, _ note: String, _ cases: [GJ], extra: GJ = [:]) throws -> (name: String, data: Data) {
    var doc: GJ = ["module": name, "note": note, "cases": cases]
    for (k, v) in extra { doc[k] = v }
    var d = try JSONSerialization.data(withJSONObject: doc, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    d.append(10)
    return ("transcripts/\(name).json", d)
}

func transcriptFiles() async throws -> [(name: String, data: Data)] {
    var logins: [GJ] = []
    for sc in loginScenarios() { logins.append(try await runLogin(sc)) }
    return [
        try renderT(
            "softether_login",
            "SoftEtherClient.connect against FakeSoftEtherServer. events are ordered across connections (conn = stream index). c2s http bodies are hex, except the watermark upload (watermark: true + the random padding behind the constant image). Replay: feed `entropy` draws in order, check the client's bytes equal the c2s events, answer with the s2c events.",
            logins),
        try renderT("host_unique_id", "HostUniqueId.loginId (SHA-1 of \"login\"+key) and nodeId (first 16 bytes of SHA-256 of \"node\"+key).", hostIdCases()),
        try renderT(
            "bridge",
            "EthernetBridge against FakeNetworkServer / scripted frames with injected entropy and clock. Replay frames in event order: c2h = bridge output (must match), h2c = hub input, host4/host6 = delivered to the tun.",
            await bridgeCases()),
        try renderT("dnsproxy", "DNSProxy.handle: routing decision, upstream query, rewritten response and dynamic routes.", dnsCases()),
    ]
}
