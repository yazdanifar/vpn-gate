import Foundation
import VPNGateCore

private let lease = Lease(ip: 0x0AE991B6, mask: 0xFFFF0000, router: 0x0AE9FEFE,
                          dns: [0x0AE9FEFE, 0x08080808], seconds: 3600, serverID: 0x0AE9FEFE)

private func make(_ r: RecordingRunner = RecordingRunner(), _ d: FakeDNS = FakeDNS(), name: String = UUID().uuidString)
    -> (NetConfig, RecordingRunner, FakeDNS, String) {
    let path = tempPath(name + ".state")
    return (NetConfig(runner: r, dns: d, stateFile: path), r, d, path)
}

func registerNetConfigTests() {
    test("netconfig/apply-runs-the-expected-commands-in-order") {
        let (n, r, d, path) = make()
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        let log = r.log
        let expected = [
            "/sbin/route -n get default",
            "/sbin/ifconfig utun7 inet 10.233.145.182 10.233.254.254 netmask 255.255.255.255 mtu 1400 up",
            "/sbin/route -n add -host 5.5.5.5 192.168.1.1",
            "/sbin/route -n add -host 10.233.254.254 -interface utun7",
            "/sbin/route -n add -net 0.0.0.0/1 10.233.254.254",
            "/sbin/route -n add -net 128.0.0.0/1 10.233.254.254",
        ]
        for c in expected { expect(log.contains(c), "missing \(c); log: \(log)") }
        let idx = expected.compactMap { log.firstIndex(of: $0) }
        expectEqual(idx, idx.sorted(), "commands out of order")
        expectEqual(d.setCalls, [["10.233.254.254", "8.8.8.8"]])
        expectEqual(d.setInterfaces, ["utun7"])
        expect(FileManager.default.fileExists(atPath: path), "state file persisted for crash recovery")
    }
    test("netconfig/teardown-removes-what-apply-added") {
        let (n, r, d, path) = make()
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        n.teardown()
        for c in ["/sbin/route -n delete -net 0.0.0.0/1 10.233.254.254", "/sbin/route -n delete -net 128.0.0.0/1 10.233.254.254",
                  "/sbin/route -n delete -host 10.233.254.254", "/sbin/route -n delete -host 5.5.5.5"] {
            expect(r.log.contains(c), "missing \(c)")
        }
        expectEqual(d.removeCalls, 1)
        expect(!FileManager.default.fileExists(atPath: path), "state file removed after a clean teardown")
        n.teardown()                                                   // second teardown is a no-op
        expectEqual(d.removeCalls, 1)
    }
    test("netconfig/no-dns-servers-means-no-dns-changes") {
        let (n, _, d, _) = make()
        var l = lease; l.dns = []
        try n.apply(iface: "utun7", lease: l, bypassHost: "5.5.5.5"); n.teardown()
        expectEqual(d.setCalls.count, 0); expectEqual(d.removeCalls, 0)
    }
    test("netconfig/loopback-proxy-gets-no-bypass-route-and-is-never-deleted") {      // B3
        let (n, r, _, _) = make()
        try n.apply(iface: "utun7", lease: lease, bypassHost: "127.0.0.1")
        n.teardown()
        expect(!r.log.contains { $0.contains("-host 127.0.0.1") }, "touched the loopback host route: \(r.log)")
    }
    test("netconfig/teardown-leaves-routes-it-did-not-create") {                     // B3
        let r = RecordingRunner()
        r.rules.append(.init(contains: "add -host 5.5.5.5", status: 1, out: "route: writing to routing socket: File exists"))
        let (n, _, _, _) = make(r)
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        n.teardown()
        expect(!r.log.contains { $0.contains("delete -host 5.5.5.5") }, "deleted a pre-existing route: \(r.log)")
        expect(r.log.contains { $0.contains("delete -net 0.0.0.0/1") }, "still removes its own routes")
    }
    test("netconfig/failed-default-capture-is-not-deleted-either") {                  // B3
        let r = RecordingRunner()
        r.rules.append(.init(contains: "add -net 128.0.0.0/1", status: 1, out: "route: writing to routing socket: File exists"))
        let (n, _, _, _) = make(r)
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5"); n.teardown()
        expect(!r.log.contains { $0.contains("delete -net 128.0.0.0/1") }, "deleted a route it never added")
    }
    test("netconfig/blocks-ipv6-through-the-tunnel") {                                 // B7
        let (n, r, _, _) = make()
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        expect(r.log.contains("/sbin/route -n add -inet6 ::/1 -interface utun7 -blackhole") ||
               r.log.contains("/sbin/route -n add -inet6 ::/1 ::1 -blackhole") ||
               r.log.contains { $0.contains("-inet6") && $0.contains("::/1") }, "no ::/1 route: \(r.log)")
        expect(r.log.contains { $0.contains("-inet6") && $0.contains("8000::/1") }, "no 8000::/1 route")
        n.teardown()
        expect(r.log.contains { $0.contains("delete -inet6") && $0.contains("::/1") }, "ipv6 routes must be removed on teardown")
    }
    test("netconfig/ipv6-block-can-be-disabled") {
        let (n, r, _, _) = make()
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5", blockIPv6: false)
        expect(!r.log.contains { $0.contains("inet6") }, "\(r.log)")
    }
    test("netconfig/state-file-lists-only-routes-that-were-added") {
        let r = RecordingRunner()
        r.rules.append(.init(contains: "add -host 5.5.5.5", status: 1, out: "File exists"))
        let (n, _, _, path) = make(r)
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        let st = try JSONDecoder().decode(NetConfig.State.self, from: Data(contentsOf: URL(fileURLWithPath: path)))
        expect(st.addedRoutes?.contains(["-host", "5.5.5.5"]) == false, "\(String(describing: st.addedRoutes))")
        expect(st.addedRoutes?.contains(["-net", "0.0.0.0/1", "10.233.254.254"]) == true)
        // a crashed run restarts from that file and must not delete the pre-existing host route either
        let r2 = RecordingRunner()
        NetConfig.cleanupStale(runner: r2, dns: FakeDNS(), stateFile: path)
        expect(!r2.log.contains { $0.contains("delete -host 5.5.5.5") }, "\(r2.log)")
        expect(r2.log.contains { $0.contains("delete -net 0.0.0.0/1") })
    }
    test("dns/tunnel-is-published-as-the-primary-service") {
        // A DNS entity alone is only a supplemental/scoped resolver (E2E showed the LAN resolver still in use);
        // the IPv4 entity with OverridePrimary makes configd rank the tunnel first.
        let e = SystemDNS.entities(servers: ["10.233.254.254", "8.8.8.8"], iface: "utun7",
                                   address: "10.233.145.182", router: "10.233.254.254")
        let v4 = e[SystemDNS.ipv4Key], dns = e[SystemDNS.dnsKey]
        expectEqual(v4?["InterfaceName"] as? String, "utun7")
        expectEqual(v4?["OverridePrimary"] as? Int, 1)
        expectEqual(v4?["Addresses"] as? [String], ["10.233.145.182"])
        expectEqual(v4?["Router"] as? String, "10.233.254.254")
        expectEqual(dns?["ServerAddresses"] as? [String], ["10.233.254.254", "8.8.8.8"])
        expect(dns?["SupplementalMatchDomains"] == nil, "supplemental domains demote the resolver to scoped-only")
        expect(SystemDNS.ipv4Key.hasPrefix("State:/Network/Service/") && SystemDNS.dnsKey.hasSuffix("/DNS"))
    }
    test("netconfig/link-gateway-uses-interface-route-and-no-default-route-skips-bypass") {
        let r = RecordingRunner()
        r.rules = [.init(contains: "get default", status: 0, out: "    gateway: link#14\n  interface: en0\n")]
        let (n, _, _, _) = make(r)
        try n.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        expect(r.log.contains("/sbin/route -n add -host 5.5.5.5 -interface en0"), "\(r.log)")
        let r2 = RecordingRunner(); r2.rules = [.init(contains: "get default", status: 1, out: "route: not in table")]
        let (n2, _, _, _) = make(r2)
        try n2.apply(iface: "utun7", lease: lease, bypassHost: "5.5.5.5")
        expect(!r2.log.contains { $0.contains("add -host 5.5.5.5") }, "no default route → nothing to bypass through")
    }
    test("netconfig/stale-state-from-a-crashed-run-is-cleaned") {
        let path = tempPath("stale.state")
        let st = NetConfig.State(iface: "utun3", bypassHost: "6.6.6.6", gateway: "10.0.0.1", dnsSet: true)
        try JSONEncoder().encode(st).write(to: URL(fileURLWithPath: path))
        let r = RecordingRunner(); let d = FakeDNS()
        NetConfig.cleanupStale(runner: r, dns: d, stateFile: path)
        expect(r.log.contains { $0.contains("delete -net 0.0.0.0/1 10.0.0.1") }, "\(r.log)")
        expectEqual(d.removeCalls, 1)
        expect(!FileManager.default.fileExists(atPath: path))
    }
    test("netconfig/corrupt-or-missing-state-file-is-harmless") {
        let r = RecordingRunner()
        NetConfig.cleanupStale(runner: r, dns: FakeDNS(), stateFile: tempPath("missing.state"))
        let p = tempPath("corrupt.state"); try Data("not json".utf8).write(to: URL(fileURLWithPath: p))
        NetConfig.cleanupStale(runner: r, dns: FakeDNS(), stateFile: p)
        expectEqual(r.log.count, 0)
    }
}
