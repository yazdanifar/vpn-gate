import Foundation
import SystemConfiguration
import VPNGateCore

struct SystemRunner: CommandRunner {
    @discardableResult
    func run(_ path: String, _ args: [String]) -> (status: Int32, out: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let pipe = Pipe()
        p.standardOutput = pipe; p.standardError = pipe
        do { try p.run() } catch { return (-1, "\(error)") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

/// Publishes the tunnel to configd as a network service of its own (IPv4 + DNS entities).
///
/// A DNS entity alone (or one marked with supplemental match domains) only becomes a scoped/supplemental
/// resolver, so lookups kept going to the LAN's resolver. With an IPv4 entity carrying `OverridePrimary`,
/// configd ranks the tunnel as the primary service and its DNS becomes the default resolver — the same
/// approach vpnc-script and Tunnelblick use.
struct SystemDNS: DNSConfigurator {
    static let serviceID = "VPNGateMac"
    static var ipv4Key: String { "State:/Network/Service/\(serviceID)/IPv4" }
    static var dnsKey: String { "State:/Network/Service/\(serviceID)/DNS" }

    static func entities(servers: [String], iface: String, address: String, router: String) -> [String: [String: Any]] {
        [
            ipv4Key: [
                "InterfaceName": iface,
                "Addresses": [address],
                "SubnetMasks": ["255.255.255.255"],
                "Router": router,
                "OverridePrimary": 1,
            ],
            dnsKey: ["ServerAddresses": servers],
        ]
    }

    func set(servers: [String], iface: String, address: String, router: String) -> Bool {
        guard let store = SCDynamicStoreCreate(nil, "vpngate-mac" as CFString, nil, nil) else { return false }
        let e = Self.entities(servers: servers, iface: iface, address: address, router: router)
        // DNS first, then IPv4: configd re-evaluates the primary service when the IPv4 entity appears.
        let okDNS = SCDynamicStoreSetValue(store, Self.dnsKey as CFString, e[Self.dnsKey]! as CFDictionary)
        let okIPv4 = SCDynamicStoreSetValue(store, Self.ipv4Key as CFString, e[Self.ipv4Key]! as CFDictionary)
        if !(okDNS && okIPv4) {
            print("[dns] publishing resolver failed: \(String(cString: SCErrorString(SCError())))")
        }
        return okDNS || okIPv4          // record partial success too, so teardown removes whatever was set
    }

    func remove() {
        guard let store = SCDynamicStoreCreate(nil, "vpngate-mac" as CFString, nil, nil) else { return }
        SCDynamicStoreRemoveValue(store, Self.ipv4Key as CFString)
        SCDynamicStoreRemoveValue(store, Self.dnsKey as CFString)
    }
}

/// Interface address, routes and DNS for the tunnel. State is persisted so a crashed helper can clean up.
final class NetConfig: NetConfiguring {
    static let defaultStateFile = "/var/run/vpngate-mac.state"

    struct State: Codable {
        var iface: String
        var bypassHost: String
        var gateway: String
        var dnsSet: Bool
        /// `route` arguments that undo each route we really added, in the order they were added.
        /// nil in state files written by older versions (then everything is removed best-effort).
        var addedRoutes: [[String]]? = nil
    }

    private let runner: CommandRunner
    private let dns: DNSConfigurator
    private let stateFile: String
    private var state: State?
    private var originalRoute: (gateway: String?, iface: String)?

    init(runner: CommandRunner = SystemRunner(), dns: DNSConfigurator = SystemDNS(),
         stateFile: String = NetConfig.defaultStateFile) {
        self.runner = runner; self.dns = dns; self.stateFile = stateFile
    }

    /// Adds a route; remembers how to delete it only if `route add` succeeded, so teardown never removes
    /// a route that already existed (or that failed to be created).
    private func addRoute(_ addArgs: [String], undo: [String]) {
        let r = runner.run("/sbin/route", ["-n", "add"] + addArgs)
        if r.status == 0 {
            state?.addedRoutes?.append(undo)
            save()
        } else {
            // Surfaces in the foreground output / /var/log/vpngate-helper.log, e.g. "route add -inet6 ::/1: Network is unreachable".
            print("[route] add \(addArgs.joined(separator: " ")) failed (\(r.status)): \(r.out.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
    }

    /// Host route that keeps traffic to `host` on the original default path instead of the tunnel.
    private func addBypassRoute(_ host: String, via o: (gateway: String?, iface: String)) {
        if let g = o.gateway { addRoute(["-host", host, g], undo: ["-host", host]) }
        else { addRoute(["-host", host, "-interface", o.iface], undo: ["-host", host]) }
    }

    func apply(iface: String, lease: Lease, bypassHost: String, blockIPv6: Bool = true) throws {
        let ip = ipString(lease.ip), gw = ipString(lease.router)
        let orig = Self.defaultRoute(runner)
        originalRoute = orig
        var st = State(iface: iface, bypassHost: bypassHost, gateway: gw, dnsSet: false)
        st.addedRoutes = []
        state = st
        save()

        // The DHCP parser already ignores out-of-range option 26 values; check again for leases built elsewhere.
        let mtuVal = lease.mtu.flatMap { (576...1500).contains($0) ? String($0) : nil } ?? "1400"
        runner.run("/sbin/ifconfig", [iface, "inet", ip, gw, "netmask", "255.255.255.255", "mtu", mtuVal, "up"])
        // Keep the tunnel's own transport outside the tunnel (never for loopback/link-local proxies).
        if !InputValidation.isLocalAddress(bypassHost), let o = orig { addBypassRoute(bypassHost, via: o) }
        addRoute(["-host", gw, "-interface", iface], undo: ["-host", gw])
        addRoute(["-net", "0.0.0.0/1", gw], undo: ["-net", "0.0.0.0/1", gw])
        addRoute(["-net", "128.0.0.0/1", gw], undo: ["-net", "128.0.0.0/1", gw])
        // Both halves of the IPv6 space point at the tunnel either way, so native IPv6 never leaks around it. With
        // `blockIPv6` the utun reader drops every non-IPv4 packet and dual-stack sites fall back to IPv4 through the
        // VPN; without it the bridge forwards IPv6 once `configureIPv6` has given the interface an address, and
        // drops it while the hub offers no IPv6 router.
        addRoute(["-inet6", "::/1", "-interface", iface], undo: ["-inet6", "::/1", "-interface", iface])
        addRoute(["-inet6", "8000::/1", "-interface", iface], undo: ["-inet6", "8000::/1", "-interface", iface])

        if !lease.dns.isEmpty {
            st = state ?? st
            st.dnsSet = dns.set(servers: lease.dns.map(ipString), iface: iface, address: ip, router: gw)
            state = st; save()
        }
    }

    func addBypass(host: String) {
        // The host ends up as a `route` argument, so only a plain IPv4 literal is accepted.
        guard state != nil, InputValidation.isIPv4Literal(host), !InputValidation.isLocalAddress(host),
              host != state?.bypassHost, let o = originalRoute else { return }
        addBypassRoute(host, via: o)
    }

    func configureIPv6(address: [UInt8], prefixLength: Int) {
        // Never a placeholder, multicast or link-local address (the kernel already has its own link-local one).
        guard let iface = state?.iface, address.count == 16, (1...128).contains(prefixLength),
              address.contains(where: { $0 != 0 }), address[0] != 0xff, !IPv6.isLinkLocal(address) else { return }
        let r = runner.run("/sbin/ifconfig", [iface, "inet6", IPv6.string(address), "prefixlen", String(prefixLength)])
        if r.status != 0 {
            print("[ifconfig] inet6 \(IPv6.string(address)) failed (\(r.status)): \(r.out.trimmingCharacters(in: .whitespacesAndNewlines))")
        }
        // The address disappears with the utun, so there is nothing to undo or persist.
    }

    func teardown() {
        Self.cleanup(state, runner, dns)
        state = nil; originalRoute = nil
        try? FileManager.default.removeItem(atPath: stateFile)
    }

    /// Remove leftovers from a previous run that did not shut down cleanly.
    static func cleanupStale(runner: CommandRunner = SystemRunner(), dns: DNSConfigurator = SystemDNS(),
                             stateFile: String = defaultStateFile) {
        guard let d = try? Data(contentsOf: URL(fileURLWithPath: stateFile)),
              let st = try? JSONDecoder().decode(State.self, from: d) else { return }
        cleanup(st, runner, dns)
        try? FileManager.default.removeItem(atPath: stateFile)
    }

    private static func cleanup(_ st: State?, _ runner: CommandRunner, _ dns: DNSConfigurator) {
        guard let st = st else { return }
        if let added = st.addedRoutes {
            for undo in added.reversed() { runner.run("/sbin/route", ["-n", "delete"] + undo) }
        } else {            // state written by an older version: remove what it would have added
            runner.run("/sbin/route", ["-n", "delete", "-net", "0.0.0.0/1", st.gateway])
            runner.run("/sbin/route", ["-n", "delete", "-net", "128.0.0.0/1", st.gateway])
            runner.run("/sbin/route", ["-n", "delete", "-host", st.gateway])
            if !InputValidation.isLocalAddress(st.bypassHost) { runner.run("/sbin/route", ["-n", "delete", "-host", st.bypassHost]) }
        }
        if st.dnsSet { dns.remove() }
    }

    private func save() {
        if let s = state, let d = try? JSONEncoder().encode(s) {
            try? d.write(to: URL(fileURLWithPath: stateFile))
        }
    }

    static func defaultRoute(_ runner: CommandRunner) -> (gateway: String?, iface: String)? {
        let out = runner.run("/sbin/route", ["-n", "get", "default"]).out
        var gw: String?, iface: String?
        for l in out.split(separator: "\n") {
            let t = l.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") { gw = t.dropFirst(8).trimmingCharacters(in: .whitespaces) }
            if t.hasPrefix("interface:") { iface = t.dropFirst(10).trimmingCharacters(in: .whitespaces) }
        }
        if let g = gw, g.hasPrefix("link#") { gw = nil }
        guard let i = iface else { return nil }
        return (gw, i)
    }
}
