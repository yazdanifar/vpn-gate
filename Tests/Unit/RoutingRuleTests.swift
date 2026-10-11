import Foundation
import VPNGateCore

func registerRoutingRuleTests() {
    test("routing/domain-suffix-matches-the-domain-and-its-subdomains") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .direct)])
        expectEqual(RoutingMatcher.match(domain: "example.com", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(domain: "www.example.com", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(domain: "evil-example.com", in: cfg), nil)
        expectEqual(RoutingMatcher.match(domain: "example.org", in: cfg), nil)
    }
    test("routing/domain-full-matches-only-the-exact-name") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .domainFull, value: "example.com", action: .block)])
        expectEqual(RoutingMatcher.match(domain: "example.com", in: cfg)?.action, .block)
        expectEqual(RoutingMatcher.match(domain: "www.example.com", in: cfg), nil)
    }
    test("routing/domain-keyword-matches-anywhere-in-the-name") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .domainKeyword, value: "ads", action: .block)])
        expectEqual(RoutingMatcher.match(domain: "ads.tracker.com", in: cfg)?.action, .block)
        expectEqual(RoutingMatcher.match(domain: "myads.example.com", in: cfg)?.action, .block)
        expectEqual(RoutingMatcher.match(domain: "adsense-free.com", in: cfg)?.action, .block)
        expectEqual(RoutingMatcher.match(domain: "example.com", in: cfg), nil)
    }
    test("routing/domain-regex-matches") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .domainRegex, value: "^(.+\\.)?ir$", action: .direct)])
        expectEqual(RoutingMatcher.match(domain: "digikala.ir", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(domain: "foo.digikala.ir", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(domain: "digikala.com", in: cfg), nil)
    }
    test("routing/first-matching-rule-wins") {
        let cfg = RoutingConfig(rules: [
            RoutingRule(type: .domainSuffix, value: "example.com", action: .block),
            RoutingRule(type: .domainSuffix, value: "example.com", action: .direct),
        ])
        expectEqual(RoutingMatcher.match(domain: "example.com", in: cfg)?.action, .block)
    }
    test("routing/disabled-rules-are-skipped") {
        let cfg = RoutingConfig(rules: [
            RoutingRule(type: .domainSuffix, value: "example.com", action: .block, enabled: false),
            RoutingRule(type: .domainSuffix, value: "example.com", action: .direct),
        ])
        expectEqual(RoutingMatcher.match(domain: "example.com", in: cfg)?.action, .direct)
    }
    test("routing/ip-rule-matches-the-literal-only") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .ip, value: "8.8.8.8", action: .direct)])
        expectEqual(RoutingMatcher.match(ip: "8.8.8.8", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(ip: "8.8.4.4", in: cfg), nil)
    }
    test("routing/cidr-v4-matches-the-whole-range") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .cidr, value: "10.0.0.0/8", action: .direct)])
        expectEqual(RoutingMatcher.match(ip: "10.1.2.3", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(ip: "11.0.0.1", in: cfg), nil)
    }
    test("routing/cidr-v6-matches-the-whole-range") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .cidr, value: "2001:db8::/32", action: .block)])
        expectEqual(RoutingMatcher.match(ip: "2001:db8::1234", in: cfg)?.action, .block)
        expectEqual(RoutingMatcher.match(ip: "2001:db9::1", in: cfg), nil)
    }
    test("routing/ipv6-literal-parses-compressed-and-full-forms") {
        let full = RoutingConfig(rules: [RoutingRule(type: .ip, value: "2001:0db8:0000:0000:0000:0000:0000:0001", action: .direct)])
        expectEqual(RoutingMatcher.match(ip: "2001:db8::1", in: full)?.action, .direct)
        let loopback = RoutingConfig(rules: [RoutingRule(type: .ip, value: "::1", action: .block)])
        expectEqual(RoutingMatcher.match(ip: "::1", in: loopback)?.action, .block)
    }
    test("routing/bypass-private-networks-adds-low-priority-direct-rules") {
        var cfg = RoutingConfig(bypassPrivateNetworks: true)
        expectEqual(RoutingMatcher.match(ip: "192.168.1.1", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(ip: "169.254.1.1", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(ip: "100.64.0.1", in: cfg)?.action, .direct)
        expectEqual(RoutingMatcher.match(ip: "8.8.8.8", in: cfg), nil)
        // an explicit user rule for an address inside a bypassed range still wins (user rules are searched first)
        cfg.rules = [RoutingRule(type: .cidr, value: "192.168.0.0/16", action: .block)]
        expectEqual(RoutingMatcher.match(ip: "192.168.1.1", in: cfg)?.action, .block)
    }
    test("routing/default-action-applies-when-nothing-matches") {
        let cfg = RoutingConfig(rules: [], defaultAction: .direct)
        expectEqual(RoutingMatcher.action(domain: "example.com", in: cfg), .direct)
        expectEqual(RoutingMatcher.action(ip: "8.8.8.8", in: cfg), .direct)
    }
    test("routing/empty-config-is-the-plain-pre-feature-behaviour") {
        expect(RoutingConfig().isEmpty)
        expect(!RoutingConfig(bypassPrivateNetworks: true).isEmpty)
        expect(!RoutingConfig(defaultAction: .direct).isEmpty)
        expect(!RoutingConfig(rules: [RoutingRule(type: .ip, value: "1.1.1.1", action: .direct)]).isEmpty)
    }
    test("routing/codable-roundtrip-and-tolerant-decoding") {
        let cfg = RoutingConfig(rules: [RoutingRule(type: .domainSuffix, value: "example.com", action: .direct)],
                                defaultAction: .proxy, bypassPrivateNetworks: true)
        let data = try JSONEncoder().encode(cfg)
        let decoded = try JSONDecoder().decode(RoutingConfig.self, from: data)
        expectEqual(decoded, cfg)
        // Older/partial JSON (e.g. missing fields) must still decode with defaults.
        let minimal = try JSONDecoder().decode(RoutingConfig.self, from: Data("{}".utf8))
        expect(minimal.isEmpty)
    }
    test("routing/validation-catches-malformed-values") {
        expect(RoutingRule.validationError(type: .ip, value: "not-an-ip") != nil)
        expect(RoutingRule.validationError(type: .cidr, value: "10.0.0.0") != nil)         // missing /prefix
        expect(RoutingRule.validationError(type: .cidr, value: "10.0.0.0/33") != nil)      // out of range
        expect(RoutingRule.validationError(type: .domainRegex, value: "(unterminated") != nil)
        expect(RoutingRule.validationError(type: .domainFull, value: "") != nil)
        expect(RoutingRule.validationError(type: .ip, value: "8.8.8.8") == nil)
        expect(RoutingRule.validationError(type: .cidr, value: "10.0.0.0/8") == nil)
        expect(RoutingRule.validationError(type: .domainKeyword, value: "anything goes") == nil)
    }
}
