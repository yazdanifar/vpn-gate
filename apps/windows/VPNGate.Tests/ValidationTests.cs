using System.Text.Json.Nodes;
using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

/// <summary>The editors' validation must agree with Tests/Fixtures/golden/validation.json.</summary>
public class ValidationTests
{
    private static JsonArray Cases(string function)
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Tests", "Fixtures", "golden", "validation.json"))) dir = dir.Parent;
        Assert.NotNull(dir);
        var root = JsonNode.Parse(File.ReadAllText(Path.Combine(dir!.FullName, "Tests", "Fixtures", "golden", "validation.json")))!;
        return root["cases"]!.AsArray().First(c => (string?)c!["function"] == function)!["cases"]!.AsArray();
    }

    [Fact]
    public void IsIPv4Literal() { foreach (var c in Cases("isIPv4Literal")) Assert.Equal((bool)c!["result"]!, InputValidation.IsIPv4Literal((string)c["input"]!)); }

    [Fact]
    public void IsValidHost() { foreach (var c in Cases("isValidHost")) Assert.Equal((bool)c!["result"]!, InputValidation.IsValidHost((string)c["input"]!)); }

    [Fact]
    public void IsValidPort() { foreach (var c in Cases("isValidPort")) Assert.Equal((bool)c!["result"]!, InputValidation.IsValidPort((int?)c["input"])); }

    [Fact]
    public void NormalizedFingerprint()
    {
        foreach (var c in Cases("normalizedFingerprint")) Assert.Equal((string?)c!["result"], InputValidation.NormalizedFingerprint((string)c["input"]!));
    }

    [Fact]
    public void ParseMacAddress()
    {
        foreach (var c in Cases("parseMacAddress"))
        {
            var got = InputValidation.ParseMacAddress((string)c!["input"]!);
            Assert.Equal((string?)c["result"], got is null ? null : Convert.ToHexString(got).ToLowerInvariant());
        }
    }

    [Fact]
    public void IsValidIdentityField() { foreach (var c in Cases("isValidIdentityField")) Assert.Equal((bool)c!["result"]!, InputValidation.IsValidIdentityField((string)c["input"]!)); }

    [Fact]
    public void IsIPLiteral() { foreach (var c in Cases("isIPLiteral")) Assert.Equal((bool)c!["result"]!, InputValidation.IsIPLiteral((string)c["input"]!)); }

    [Theory]
    [InlineData(RoutingRuleType.DomainSuffix, "", "Value is required.")]
    [InlineData(RoutingRuleType.DomainSuffix, "a..b", "Not a valid domain name.")]
    [InlineData(RoutingRuleType.DomainSuffix, "example.com", null)]
    [InlineData(RoutingRuleType.DomainKeyword, "ads", null)]
    [InlineData(RoutingRuleType.DomainRegex, "(", "Not a valid regular expression.")]
    [InlineData(RoutingRuleType.DomainRegex, @"^(.+\.)?example\.com$", null)]
    [InlineData(RoutingRuleType.Ip, "300.1.1.1", "Not a valid IPv4 or IPv6 address.")]
    [InlineData(RoutingRuleType.Ip, "2001:db8::1", null)]
    [InlineData(RoutingRuleType.Cidr, "10.0.0.0", "A CIDR needs a /prefix, e.g. 10.0.0.0/8.")]
    [InlineData(RoutingRuleType.Cidr, "10.0.0.0/33", "Not a valid CIDR range.")]
    [InlineData(RoutingRuleType.Cidr, "10.0.0.0/8", null)]
    [InlineData(RoutingRuleType.Cidr, "fe80::/10", null)]
    public void RoutingRuleErrors(RoutingRuleType type, string value, string? expected) =>
        Assert.Equal(expected, RoutingRuleValidation.Error(type, value));
}
