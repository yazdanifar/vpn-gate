using System.Text.Json;
using System.Text.Json.Nodes;
using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

/// <summary>The C# mirrors must read and write the JSON pinned in Tests/Fixtures/golden/ipc.json.</summary>
public class GoldenIpcTests
{
    private static JsonObject Golden()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null && !File.Exists(Path.Combine(dir.FullName, "Tests", "Fixtures", "golden", "ipc.json"))) dir = dir.Parent;
        Assert.NotNull(dir);
        return (JsonObject)JsonNode.Parse(File.ReadAllText(Path.Combine(dir!.FullName, "Tests", "Fixtures", "golden", "ipc.json")))!;
    }

    private static JsonNode Case(string name) =>
        Golden()["cases"]!.AsArray().First(c => (string?)c!["name"] == name)!;

    private static void SameJson(JsonNode expected, JsonNode? actual) =>
        Assert.True(JsonNode.DeepEquals(expected, actual), $"expected {expected.ToJsonString()}\n  actual {actual?.ToJsonString()}");

    private static JsonNode? Encode<T>(T v) => JsonSerializer.SerializeToNode(v, Ipc.Json);

    [Theory]
    [InlineData("connect-config-default")]
    [InlineData("connect-config-full")]
    public void ConnectConfigRoundTrips(string name)
    {
        var json = Case(name)["json"]!;
        var cfg = json.Deserialize<ConnectConfig>(Ipc.Json)!;
        SameJson(json, Encode(cfg));
    }

    [Fact]
    public void ConnectConfigDecodeFillsDefaultsAndIgnoresUnknownKeys()
    {
        foreach (var c in Case("connect-config-decode")["cases"]!.AsArray())
        {
            var input = (string)c!["input"]!;
            if (c["error"] is not null) continue; // C# does not mark `host` required; the daemon validates
            var cfg = JsonSerializer.Deserialize<ConnectConfig>(input, Ipc.Json)!;
            SameJson(c["config"]!, Encode(cfg));
        }
    }

    [Fact]
    public void BogusTunnelModeIsRejected() =>
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<ConnectConfig>("{\"host\":\"h\",\"tunnelMode\":\"bogus\"}", Ipc.Json));

    [Fact]
    public void ConnectRequestEncodesLikeTheDaemonExpects()
    {
        var expected = Case("request-encode")["cases"]!.AsArray().Last()!;
        var req = expected.Deserialize<HelperRequest>(Ipc.Json)!;
        SameJson(expected, Encode(req));
        var plain = Case("request-encode")["cases"]!.AsArray();
        SameJson(plain[0]!, Encode(HelperRequest.Of("status")));
        SameJson(plain[1]!, Encode(HelperRequest.Of("disconnect")));
    }

    [Fact]
    public void RequestDecodeCases()
    {
        foreach (var c in Case("request-decode")["cases"]!.AsArray())
        {
            var input = (string)c!["input"]!;
            if (c["error"] is not null) continue;
            var req = JsonSerializer.Deserialize<HelperRequest>(input, Ipc.Json)!;
            SameJson(c["request"]!, Encode(req)!.AsObject().Also(o => o.Remove("config", out _), c["request"]!["config"] is null));
        }
    }

    [Fact]
    public void EventsRoundTrip()
    {
        var c = Case("event-encode");
        foreach (var state in c["cases"]!.AsArray())
        {
            var e = JsonSerializer.Deserialize<HelperEvent>($"{{\"state\":\"{state}\",\"bytesIn\":0,\"bytesOut\":0}}", Ipc.Json)!;
            Assert.Equal(state!.ToString(), Encode(e)!["state"]!.ToString());
        }
        foreach (var ev in c["events"]!.AsArray())
        {
            var e = ev.Deserialize<HelperEvent>(Ipc.Json)!;
            SameJson(ev!, Encode(e));
        }
    }

    [Fact]
    public void EventDecodeCases()
    {
        var cases = Case("event-decode")["cases"]!.AsArray();
        var ok = cases.First(c => c!["event"] is not null)!;
        var e = JsonSerializer.Deserialize<HelperEvent>((string)ok["input"]!, Ipc.Json)!;
        SameJson(ok["event"]!, Encode(e));
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<HelperEvent>("{\"state\":\"bogus\"}", Ipc.Json));
    }

    [Fact]
    public void ProxySettingsAndConstants()
    {
        var p = Case("proxy-settings");
        SameJson(p["default"]!, Encode(new ProxySettings()));
        SameJson(p["json"]!, Encode(p["json"].Deserialize<ProxySettings>(Ipc.Json)));
        var k = Case("constants");
        Assert.Equal(Ipc.HelperVersion, (int)k["helperVersion"]!);
        Assert.Equal(Ipc.DefaultSocksPort, (int)k["defaultSocksPort"]!);
    }

    [Fact]
    public void ServerListResultDecodes()
    {
        const string json = """
            {"servers":[{"hostName":"vpn1.opengw.net","ip":"1.2.3.4","score":100,"ping":10,"speed":123456789,"countryLong":"Japan","countryShort":"JP",
            "sessions":3,"uptimeMs":7200000,"totalUsers":9,"totalTraffic":10,"logType":"2weeks","operatorName":"op","message":"","listedPort":443,"listedProto":"tcp",
            "fqdn":"vpn1.opengw.net","sslPorts":[995,443],"udpPort":null,"openVpnUdpPorts":[],"l2tp":true,"os":null,"soft":null,"build":9700,"owner":null,"abuse":null,
            "numLogin":null,"noLog":false,"logPermanent":false,"pingToGoogle":0,"sendSize":0,"recvSize":0,"isKernelModeNAT":false}],
            "source":"Relay P2P","timestampMs":1700000000000,"isFresh":true,"outcome":"synced","nextPollSeconds":3600.5}
            """;
        var r = JsonSerializer.Deserialize<ServerListResult>(json, Ipc.Json)!;
        Assert.Equal("Relay P2P", r.Source);
        Assert.Equal(SyncOutcome.Synced, r.Outcome);
        Assert.Equal(DateTimeOffset.FromUnixTimeMilliseconds(1700000000000), r.Timestamp);
        var s = Assert.Single(r.Servers);
        Assert.Equal(443, s.ConnectPort);
        Assert.Equal(new ushort[] { 443, 995 }, s.PrioritizedSslPorts);
        Assert.Equal("🇯🇵", s.Flag);
    }
}

internal static class JsonNodeExt
{
    public static JsonObject Also(this JsonObject o, Action<JsonObject> f, bool when)
    {
        if (when) f(o);
        return o;
    }
}
