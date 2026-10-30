using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

public class SettingsHistoryTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "vg-set-" + Guid.NewGuid().ToString("N")[..8]);

    public SettingsHistoryTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    [Fact]
    public void SettingsRoundTripThroughTheFile()
    {
        var path = Path.Combine(_dir, "settings.json");
        var s = new JsonFileSettings(path);
        Assert.True(s.BlockIPv6);
        Assert.Equal(1080, s.SocksPort);
        s.HasAgreedToDisclaimer = true;
        s.Favorites.Add("b.opengw.net");
        s.ProxyKind = ProxyKind.Socks5; s.ProxyHost = "p"; s.ProxyPort = 9; s.ProxyUsername = "u";
        s.BlockIPv6 = false; s.TunnelMode = TunnelMode.SocksProxy; s.SocksPort = 2000; s.AutoReconnect = false;
        s.MirrorUrl = "https://m.example/list.csv";
        s.Routing = new RoutingConfig { BypassPrivateNetworks = true, Rules = { new RoutingRule { Type = RoutingRuleType.DomainSuffix, Value = "a.com", Action = RoutingAction.Direct } } };
        s.Save();
        var t = new JsonFileSettings(path);
        Assert.True(t.HasAgreedToDisclaimer);
        Assert.Contains("b.opengw.net", t.Favorites);
        Assert.Equal((ProxyKind.Socks5, "p", 9, "u"), (t.ProxyKind, t.ProxyHost, t.ProxyPort, t.ProxyUsername));
        Assert.False(t.BlockIPv6);
        Assert.Equal((TunnelMode.SocksProxy, 2000, false, "https://m.example/list.csv"), (t.TunnelMode, t.SocksPort, t.AutoReconnect, t.MirrorUrl));
        Assert.True(t.Routing.BypassPrivateNetworks);
        Assert.Equal("a.com", Assert.Single(t.Routing.Rules).Value);
        Assert.DoesNotContain("password", File.ReadAllText(path), StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void ADamagedSettingsFileMeansDefaults()
    {
        var path = Path.Combine(_dir, "settings.json");
        File.WriteAllText(path, "{{{");
        var s = new JsonFileSettings(path);
        Assert.False(s.HasAgreedToDisclaimer);
        Assert.True(s.AutoReconnect);
    }

    [Fact]
    public void HistoryKeepsNewestFirstAndCapsAtOneHundred()
    {
        var path = Path.Combine(_dir, "h.json");
        var now = DateTimeOffset.UtcNow;
        var h = new ConnectionHistoryStore(path, () => now);
        var first = h.RecordStart("first", "1.1.1.1");
        now = now.AddSeconds(90);
        h.RecordEnd(first, 10, 20, "boom");
        Assert.Equal(90, h.Entries[0].DurationSeconds);
        Assert.Equal("boom", h.Entries[0].Error);
        for (var i = 0; i < 120; i++) h.RecordStart($"s{i}", "2.2.2.2");
        Assert.Equal(ConnectionHistoryStore.MaxEntries, h.Entries.Count);
        Assert.Equal("s119", h.Entries[0].ServerName);
        var again = new ConnectionHistoryStore(path);
        Assert.Equal(100, again.Entries.Count);
        again.Clear();
        Assert.Empty(new ConnectionHistoryStore(path).Entries);
    }
}
