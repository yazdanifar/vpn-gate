using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace VPNGate.Core;

/// <summary>Editor validation (InputValidation.swift / crates/vpngate-core/src/validation.rs); pinned by golden/validation.json.</summary>
public static class InputValidation
{
    public static bool IsValidPort(int? p) => p is >= 1 and <= 65535;

    private static bool IsAsciiDigit(char c) => c is >= '0' and <= '9';

    public static bool IsIPv4Literal(string s)
    {
        var parts = s.Split('.');
        return parts.Length == 4 && parts.All(p => p.Length is >= 1 and <= 3 && p.All(IsAsciiDigit) && int.Parse(p) <= 255);
    }

    /// <summary>IPv4 literal or RFC 1123 hostname. Never starts with '-' (would be parsed as an option).</summary>
    public static bool IsValidHost(string s)
    {
        if (s.Length is 0 or > 253) return false;
        if (IsIPv4Literal(s)) return true;
        if (s.All(c => IsAsciiDigit(c) || c == '.')) return false; // malformed dotted number
        if (s[0] is '-' or '.' || s[^1] is '.' or '-') return false;
        return s.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or '-' or '.' || IsAsciiDigit(c)) && !s.Contains("..");
    }

    /// <summary>SHA-1 (40) or SHA-256 (64) hex digits, ':' ' ' '-' separators allowed. Returns bare lowercase hex or null.</summary>
    public static string? NormalizedFingerprint(string s)
    {
        var hex = new string(s.Where(c => !char.IsWhiteSpace(c) && c != ':' && c != '-').ToArray()).ToLowerInvariant();
        return hex.Length is 40 or 64 && hex.All(Uri.IsHexDigit) ? hex : null;
    }

    /// <summary>6 hex byte pairs separated by ':' or '-'.</summary>
    public static byte[]? ParseMacAddress(string s)
    {
        var parts = s.Split(new[] { ':', '-' }, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length != 6) return null;
        var bytes = new byte[6];
        for (var i = 0; i < 6; i++)
        {
            if (parts[i].Length is 0 or > 2 || !parts[i].All(Uri.IsHexDigit)) return null;
            bytes[i] = Convert.ToByte(parts[i], 16);
        }
        return bytes;
    }

    /// <summary>Hub and user names travel in the SoftEther handshake: at most 255 bytes, no NUL.</summary>
    public static bool IsValidIdentityField(string s) => Encoding.UTF8.GetByteCount(s) <= 255 && !s.Contains('\0');

    /// <summary>A bare IPv4 or IPv6 address (no "/prefix").</summary>
    public static bool IsIPLiteral(string s)
    {
        if (s.Contains('/') || s.Contains('%')) return false;
        if (!s.Contains(':')) return IsIPv4Literal(s);
        // The shared matcher does not accept IPv4-mapped tails ("::ffff:1.2.3.4").
        return !s.Contains('.') && IPAddress.TryParse(s, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6;
    }
}

/// <summary>Per-type validation of a routing rule's value (RoutingRule::validation_error).</summary>
public static class RoutingRuleValidation
{
    public static readonly (RoutingRuleType Type, string Label, string Placeholder)[] Types =
    {
        (RoutingRuleType.DomainSuffix, "Domain suffix", "example.com"),
        (RoutingRuleType.DomainFull, "Domain (exact)", "example.com"),
        (RoutingRuleType.DomainKeyword, "Domain keyword", "ads"),
        (RoutingRuleType.DomainRegex, "Domain regex", @"^(.+\.)?example\.com$"),
        (RoutingRuleType.Ip, "IP address", "203.0.113.5"),
        (RoutingRuleType.Cidr, "IP range (CIDR)", "10.0.0.0/8"),
    };

    private static string Trim(string s) => s.Trim(' ', '\t', ' ', ' ', ' ', ' ', '　')
        .Trim(Enumerable.Range(0x2000, 11).Select(c => (char)c).ToArray());

    /// <summary>Null when <paramref name="value"/> is well-formed for <paramref name="type"/>; else a short message.</summary>
    public static string? Error(RoutingRuleType type, string value)
    {
        var v = Trim(value);
        if (v.Length == 0) return "Value is required.";
        switch (type)
        {
            case RoutingRuleType.DomainSuffix:
            case RoutingRuleType.DomainFull:
                return IsPlausibleDomain(v) ? null : "Not a valid domain name.";
            case RoutingRuleType.DomainKeyword:
                return null;
            case RoutingRuleType.DomainRegex:
                try { _ = new Regex(v, RegexOptions.None, TimeSpan.FromSeconds(1)); return null; }
                catch (ArgumentException) { return "Not a valid regular expression."; }
            case RoutingRuleType.Ip:
                return InputValidation.IsIPLiteral(v) ? null : "Not a valid IPv4 or IPv6 address.";
            default:
                if (!v.Contains('/')) return "A CIDR needs a /prefix, e.g. 10.0.0.0/8.";
                return IsCidr(v) ? null : "Not a valid CIDR range.";
        }
    }

    private static bool IsPlausibleDomain(string s) =>
        s.Length <= 253 && s[0] != '.' && s[^1] != '.' && !s.Contains("..")
        && s.All(c => c is (>= 'a' and <= 'z') or (>= 'A' and <= 'Z') or (>= '0' and <= '9') or '-' or '.');

    private static bool IsCidr(string s)
    {
        var i = s.IndexOf('/');
        if (!IPAddress.TryParse(s[..i], out var ip) || s[..i].Contains('%')) return false;
        var prefix = s[(i + 1)..];
        if (prefix.Length == 0 || prefix.Length > 3 || !prefix.All(c => c is >= '0' and <= '9')) return false;
        return int.Parse(prefix) <= (ip.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
    }

    public static string? Error(RoutingRule rule) => Error(rule.Type, rule.Value);
}
