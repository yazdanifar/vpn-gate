import Foundation
import VPNGateCore

/// Network tests against real VPN Gate relays. Run with `scripts/test.sh --live`.
func registerLiveTests() {
    liveTest("live/server-list-downloads-and-parses") {
        let list = try await ServerList.fetch()
        expect(list.count >= 10, "only \(list.count) servers")
        expectEqual(Set(list.map(\.id)).count, list.count, "ids must be unique")
        expect(list.allSatisfy { InputValidation.isValidHost($0.ip) }, "invalid ip in list")
        expect(list.allSatisfy { $0.connectPort == nil || InputValidation.isValidPort($0.connectPort) })
    }

    liveTest("live/top-servers-handshake-and-dhcp", timeout: 180) {
        let list = try await ServerList.fetch()
        let top = list.filter { $0.connectPort != nil }.sorted { $0.score > $1.score }.prefix(5)
        var okCount = 0
        var report: [String] = []
        for s in top {
            let c = SoftEtherClient(host: s.ip, port: UInt16(s.connectPort ?? 443), proxy: ProxySettings())
            let b = EthernetBridge(timing: BridgeTiming(dhcpTimeout: 4, dhcpRetries: 2))
            b.sendFrame = { c.sendFrame($0) }; c.onFrame = { b.fromHub($0) }
            do {
                _ = try await c.connect { _ in }
                let l = try await b.acquireLease()
                expect(l.ip != 0 && l.router != 0, "empty lease from \(s.ip)")
                okCount += 1; report.append("\(s.ip) ok \(ipString(l.ip))")
            } catch { report.append("\(s.ip) FAILED \(error.localizedDescription)") }
            c.close(nil)
        }
        print("    live report: \(report)")
        expect(okCount >= 3, "only \(okCount)/\(top.count) servers completed handshake + DHCP: \(report)")
    }
}
