using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

public class FormatTests
{
    [Theory]
    [InlineData(0UL, "0 bytes")]
    [InlineData(1UL, "1 byte")]
    [InlineData(1023UL, "1023 bytes")]
    [InlineData(1536UL, "1.5 KB")]
    [InlineData(10UL * 1024 * 1024, "10 MB")]
    [InlineData(3UL * 1024 * 1024 * 1024 + 300UL * 1024 * 1024, "3.3 GB")]
    public void Bytes(ulong n, string text) => Assert.Equal(text, Fmt.Bytes(n));

    [Fact]
    public void SpeedRateAndDuration()
    {
        Assert.Equal("12.3 Mbps", Fmt.Speed(12_300_000));
        Assert.Equal("1.0 KB/s", Fmt.Rate(1024));
        Assert.Equal("1:01:05", Fmt.Duration(TimeSpan.FromSeconds(3665)));
        Assert.Equal("0:00:00", Fmt.Duration(TimeSpan.FromSeconds(-4)));
    }

    [Fact]
    public void TrafficTextHasDurationOnlyWhenKnown()
    {
        Assert.Equal("↓ 1.0 KB  ↑ 0 bytes", Fmt.Traffic(1024, 0));
        Assert.Equal("0:00:07  ↓ 1.0 KB  ↑ 0 bytes", Fmt.Traffic(1024, 0, TimeSpan.FromSeconds(7)));
    }

    [Fact]
    public void StateTitles()
    {
        Assert.Equal("Getting address…", Fmt.Title(ConnectionState.Dhcp));
        Assert.Equal("Reconnecting…", Fmt.Title(ConnectionState.Reconnecting));
    }

    [Theory]
    [InlineData(59_999L, "0 mins")]
    [InlineData(60_000L, "1 min")]
    [InlineData(3_600_001L, "1 hour")]
    [InlineData(86_400_001L, "1 day")]
    [InlineData(3L * 86_400_000, "3 days")]
    public void Uptime(long ms, string text) => Assert.Equal(text, ListFormat.Uptime(ms));

    [Fact]
    public void ListColumns()
    {
        Assert.Equal("2 sessions", ListFormat.Sessions(2));
        Assert.Equal("No Logs", ListFormat.Logging("none"));
        Assert.Equal("2 Weeks", ListFormat.Logging("2weeks"));
        Assert.Equal("Permanent", ListFormat.Logging("permanent"));
        Assert.Equal("-", ListFormat.Logging(""));
        Assert.Equal("-, 12 ms", ListFormat.Pings(0, 12));
        var now = DateTimeOffset.UtcNow;
        Assert.True(ListFormat.IsListOk(now.AddHours(-23), now));
        Assert.False(ListFormat.IsListOk(now.AddHours(-25), now));
    }
}

public class ServerFilterTests
{
    private static VpnServer S(string host, string country = "Japan", string log = "2weeks", string op = "") =>
        new() { HostName = host, Ip = "1.1.1." + host.Length, CountryLong = country, LogType = log, OperatorName = op };

    [Fact]
    public void SearchMatchesHostIpCountryAndOperatorIgnoringCase()
    {
        var all = new[] { S("alpha", op: "Müller"), S("beta", "Korea Republic of"), S("gamma") };
        var f = new ServerFilter { Search = "KOREA" };
        Assert.Equal(new[] { "beta" }, f.Apply(all).Select(s => s.HostName));
        f.Search = "müller";
        Assert.Equal(new[] { "alpha" }, f.Apply(all).Select(s => s.HostName));
        f.Search = "1.1.1.5";
        Assert.Equal(new[] { "alpha", "gamma" }, f.Apply(all).Select(s => s.HostName));
    }

    [Fact]
    public void CountryFavoritesAndLogging()
    {
        var all = new[] { S("a"), S("b", "Korea", "none"), S("c", log: "1year"), S("d", log: "weird") };
        Assert.Equal(new[] { "b" }, new ServerFilter { Country = "Korea" }.Apply(all).Select(s => s.HostName));
        Assert.Equal(new[] { "c" }, new ServerFilter { FavoritesOnly = true, Favorites = { "c" } }.Apply(all).Select(s => s.HostName));
        Assert.Equal(new[] { "b" }, new ServerFilter { MaxLogWeeks = 0 }.Apply(all).Select(s => s.HostName));
        Assert.Equal(new[] { "a", "b" }, new ServerFilter { MaxLogWeeks = 2 }.Apply(all).Select(s => s.HostName));
    }

    [Theory]
    [InlineData("2weeks", 2)]
    [InlineData("3months", 13)]
    [InlineData("1year", 52)]
    [InlineData("10days", 2)]
    [InlineData("no", 0)]
    [InlineData("0", 0)]
    public void LogWeeks(string s, int weeks) => Assert.Equal(weeks, ServerFilter.LogWeeks(s));

    [Fact]
    public void UnparseableLogWeeksIsNull() => Assert.Null(ServerFilter.LogWeeks("forever"));
}
