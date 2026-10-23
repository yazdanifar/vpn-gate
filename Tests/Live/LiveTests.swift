import Foundation
import VPNGateCore

/// Network tests against real VPN Gate relays. Run with `scripts/test.sh --live live/`.
///
/// They work from the signed list shipped with the app (Tests/Fixtures/VPNGate.dat), not from the CSV API, which
/// is blocked in some countries. Relays come and go, so a single dead relay is not a failure: a test passes when
/// at least one relay completes it. To use specific relays:
///   VPNGATE_LIVE_RELAYS=150.40.105.12:443,219.100.37.59:443 scripts/test.sh --live live/
func registerLiveTests() {
    /// Relays to try: the override from the environment, else the bundled list (port 443 first, best score first).
    func liveRelays(limit: Int) throws -> [(ip: String, port: UInt16)] {
        if let raw = ProcessInfo.processInfo.environment["VPNGATE_LIVE_RELAYS"], !raw.isEmpty {
            return raw.split(separator: ",").compactMap { item in
                let parts = item.split(separator: ":").map(String.init)
                guard let ip = parts.first, InputValidation.isValidHost(ip) else { return nil }
                let port = parts.count > 1 ? UInt16(parts[1]) : 443
                return port.map { (ip, $0) }
            }
        }
        let bundled = try VGDat.parse(data: fixtureData("VPNGate.dat"))
        let usable = bundled.servers.filter { !$0.sslPorts.isEmpty }
        let ranked = usable.sorted { a, b in
            let a443 = a.sslPorts.contains(443), b443 = b.sslPorts.contains(443)
            return a443 != b443 ? a443 : a.score > b.score
        }
        return ranked.prefix(limit).map { ($0.ip, $0.sslPorts.contains(443) ? 443 : $0.sslPorts[0]) }
    }

    liveTest("live/csv-api-reachable-when-the-network-allows") {
        // Informational: the legacy CSV list is the fallback source and is unreachable in some countries.
        do {
            let list = try await ServerList.fetch()
            expect(list.count >= 10, "only \(list.count) servers")
            expectEqual(Set(list.map(\.id)).count, list.count, "ids must be unique")
            expect(list.allSatisfy { InputValidation.isValidHost($0.ip) }, "invalid ip in list")
        } catch {
            print("    SKIPPED: CSV API unreachable from this network (\(error.localizedDescription)); relay tests below do not need it")
        }
    }

    liveTest("live/relay-handshake-and-dhcp", timeout: 240) {
        let relays = try liveRelays(limit: 10)
        expect(!relays.isEmpty, "no relays to try")
        var okCount = 0
        var report: [String] = []
        for (ip, port) in relays {
            let c = SoftEtherClient(host: ip, port: port, proxy: ProxySettings())
            let b = EthernetBridge(timing: BridgeTiming(dhcpTimeout: 4, dhcpRetries: 2))
            b.sendFrame = { c.sendFrame($0) }; c.onFrame = { b.fromHub($0) }
            // One relay must not stall the run: close the client if it takes longer than 20 s.
            let watchdog = Task {
                try? await Task.sleep(nanoseconds: 20_000_000_000); if !Task.isCancelled { c.close(nil) }
            }
            do {
                _ = try await c.connect { _ in }
                let l = try await b.acquireLease()
                expect(l.ip != 0 && l.router != 0, "empty lease from \(ip)")
                okCount += 1; report.append("\(ip):\(port) ok lease \(ipString(l.ip)) via \(ipString(l.router))")
            } catch { report.append("\(ip):\(port) FAILED \(error.localizedDescription)") }
            watchdog.cancel()
            c.close(nil)
            if okCount >= 3 { break }
        }
        print("    live report:"); report.forEach { print("      \($0)") }
        expect(okCount >= 1, "no relay completed handshake + DHCP (network blocking VPN Gate, or all tried relays are down): \(report)")
    }

    liveTest("live/list-sync-from-relays", timeout: 240) {
        // The relay-to-relay download of the signed list (GET /vgc_download_dat/): signature + freshness verified.
        let bundled = try VGDat.parse(data: fixtureData("VPNGate.dat"))
        var candidates = bundled.servers
        if let raw = ProcessInfo.processInfo.environment["VPNGATE_LIVE_RELAYS"], !raw.isEmpty {
            candidates = try liveRelays(limit: 10).map { r in
                var s = bundled.servers[0]; s.ip = r.ip; s.sslPorts = [r.port]; return s
            }
        }
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("vpngate-live-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let fetcher = VGDatFetcher(cacheURL: dir.appendingPathComponent("VPNGate.dat"), bundleURLs: [])
        let dat = try await fetcher.fetchFromRelays(candidates: candidates, proxy: ProxySettings())
        expect(dat.isSignatureValid, "signature must verify")
        expect(dat.isFresh, "relay served a stale list")
        expect(dat.servers.count >= 10, "only \(dat.servers.count) servers")
        print("    live report: \(dat.servers.count) servers, list time \(dat.timestamp)")
    }
}
