import Foundation
import VPNGateCore

/// Builds the tiny subset of wire-format DNS messages these tests need.
private func encodeName(_ name: String) -> [UInt8] {
    var out = [UInt8]()
    for label in name.split(separator: ".") {
        out.append(UInt8(label.utf8.count))
        out.append(contentsOf: Array(label.utf8))
    }
    out.append(0)
    return out
}

private func buildQuery(id: UInt16 = 0x1234, name: String, type: UInt16 = 1) -> [UInt8] {
    var p: [UInt8] = [
        UInt8(id >> 8), UInt8(id & 0xFF), 0x01, 0x00,  // flags: RD
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]  // QDCOUNT=1
    p += encodeName(name)
    p += [UInt8(type >> 8), UInt8(type & 0xFF), 0x00, 0x01]  // QTYPE, QCLASS=IN
    return p
}

private func ipv4Bytes(_ ip: String) -> [UInt8] { ip.split(separator: ".").compactMap { UInt8($0) } }

/// A response to `query` carrying one A record for each address in `answers`.
private func buildResponse(for query: [UInt8], answers: [String]) -> [UInt8] {
    var p = query
    p[2] |= 0x80  // QR = 1
    p[6] = UInt8(answers.count >> 8); p[7] = UInt8(answers.count & 0xFF)  // ANCOUNT
    for ip in answers {
        p += [0xC0, 0x0C]  // NAME: pointer to the question's name
        p += [0x00, 0x01, 0x00, 0x01]  // TYPE=A, CLASS=IN
        p += [0x00, 0x00, 0x00, 0x3C]  // TTL=60
        p += [0x00, 0x04]  // RDLENGTH=4
        p += ipv4Bytes(ip)
    }
    return p
}

private final class FakeDNSUpstream: DNSUpstream {
    struct Call { let server: String }
    private let state = Locked([Call]())
    var calls: [Call] { state.value }
    var responder: ([UInt8], String) -> [UInt8]? = { _, _ in nil }
    func query(_ message: [UInt8], server: String, timeoutMs: Int32) -> [UInt8]? {
        state.update { $0.append(Call(server: server)) }
        return responder(message, server)
    }
}

func registerDNSProxyTests() {
    test("dnsmessage/query-name-round-trips") {
        let q = buildQuery(name: "www.example.com")
        expectEqual(DNSMessage.queryName(q), "www.example.com")
    }
    test("dnsmessage/resolved-ipv4-addresses-reads-a-records") {
        let q = buildQuery(name: "example.com")
        let r = buildResponse(for: q, answers: ["93.184.216.34", "1.2.3.4"])
        expectEqual(DNSMessage.resolvedIPv4Addresses(r), ["93.184.216.34", "1.2.3.4"])
    }
    test("dnsmessage/resolved-ipv4-addresses-is-empty-for-a-plain-query") {
        expectEqual(DNSMessage.resolvedIPv4Addresses(buildQuery(name: "example.com")), [])
    }
    test("dnsmessage/blocked-response-is-nxdomain-with-no-answers") {
        let q = buildQuery(name: "example.com")
        let r = DNSMessage.blockedResponse(for: q)
        expect(r[2] & 0x80 != 0, "QR bit not set")
        expectEqual(r[3] & 0x0F, 3, "RCODE should be NXDOMAIN (3)")
        expectEqual(Int(r[6]) << 8 | Int(r[7]), 0, "ANCOUNT should be 0")
        expectEqual(DNSMessage.queryName(r), "example.com", "question must survive")
    }
    test("dnsmessage/servfail-response-sets-rcode-2") {
        let r = DNSMessage.servfailResponse(for: buildQuery(name: "example.com"))
        expectEqual(r[3] & 0x0F, 2)
    }

    func makeProxy(
        rules: [RoutingRule] = [], defaultAction: RoutingAction = .proxy,
        tunnel: [String] = ["10.0.0.1"], direct: [String] = ["9.9.9.9"]
    ) -> (DNSProxy, FakeDNSUpstream, FakeNet) {
        let net = FakeNet()
        let upstream = FakeDNSUpstream()
        let proxy = DNSProxy(net: net, upstream: upstream)
        proxy.routing = RoutingConfig(rules: rules, defaultAction: defaultAction)
        proxy.tunnelDNSServers = tunnel
        proxy.directDNSServers = direct
        return (proxy, upstream, net)
    }

    test("dnsproxy/blocked-domain-gets-nxdomain-without-asking-any-upstream") {
        let (proxy, upstream, _) = makeProxy(rules: [RoutingRule(type: .domainSuffix, value: "ads.example", action: .block)])
        let q = buildQuery(name: "ads.example")
        let r = proxy.handle(q)
        expectEqual(r[3] & 0x0F, 3)
        expectEqual(upstream.calls.count, 0, "a blocked domain must never be looked up anywhere")
    }
    test("dnsproxy/direct-domain-is-resolved-by-the-direct-server-and-gets-a-direct-route") {
        let (proxy, upstream, net) = makeProxy(rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .direct)])
        let q = buildQuery(name: "example.com")
        upstream.responder = { query, _ in buildResponse(for: query, answers: ["93.184.216.34"]) }
        _ = proxy.handle(q)
        expectEqual(upstream.calls.map(\.server), ["9.9.9.9"], "must ask the physical resolver, never the tunnel's")
        expectEqual(net.dynamicRulesApplied.map(\.ip), ["93.184.216.34"])
        expectEqual(net.dynamicRulesApplied.map(\.action), [.direct])
    }
    test("dnsproxy/unmatched-domain-is-resolved-by-the-tunnel-server-and-installs-no-dynamic-route") {
        let (proxy, upstream, net) = makeProxy()
        upstream.responder = { query, _ in buildResponse(for: query, answers: ["5.6.7.8"]) }
        _ = proxy.handle(buildQuery(name: "anything.example"))
        expectEqual(upstream.calls.map(\.server), ["10.0.0.1"])
        expectEqual(net.dynamicRulesApplied.count, 0, "the static capture already routes this; no explicit rule matched")
    }
    test("dnsproxy/proxy-rule-is-resolved-by-the-tunnel-server") {
        let (proxy, upstream, net) = makeProxy(
            rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .proxy)],
            defaultAction: .direct)
        upstream.responder = { query, _ in buildResponse(for: query, answers: ["5.6.7.8"]) }
        _ = proxy.handle(buildQuery(name: "example.com"))
        expectEqual(upstream.calls.map(\.server), ["10.0.0.1"])
        expectEqual(net.dynamicRulesApplied.map(\.action), [.proxy])
    }
    test("dnsproxy/no-direct-server-configured-fails-closed-instead-of-leaking-to-the-tunnel") {
        let (proxy, upstream, _) = makeProxy(rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .direct)], direct: [])
        let r = proxy.handle(buildQuery(name: "example.com"))
        expectEqual(r[3] & 0x0F, 2, "should be SERVFAIL")
        expectEqual(upstream.calls.count, 0)
    }
    test("dnsproxy/upstream-failure-is-servfail-not-a-fallback") {
        let (proxy, upstream, _) = makeProxy()
        upstream.responder = { _, _ in nil }
        let r = proxy.handle(buildQuery(name: "example.com"))
        expectEqual(r[3] & 0x0F, 2)
    }
    test("dnsproxy/unparsable-query-is-servfail-without-touching-any-upstream") {
        let (proxy, upstream, _) = makeProxy()
        let r = proxy.handle([0x12, 0x34])
        expectEqual(r, DNSMessage.servfailResponse(for: [0x12, 0x34]))
        expectEqual(upstream.calls.count, 0)
    }
    test("dnsproxy/first-matching-rule-still-wins-over-the-default-action") {
        let (proxy, upstream, _) = makeProxy(
            rules: [RoutingRule(type: .domainFull, value: "example.com", action: .block)],
            defaultAction: .direct)
        let r = proxy.handle(buildQuery(name: "example.com"))
        expectEqual(r[3] & 0x0F, 3)
        expectEqual(upstream.calls.count, 0)
    }
}
