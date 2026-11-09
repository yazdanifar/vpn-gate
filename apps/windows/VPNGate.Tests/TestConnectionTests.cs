using System.Text.Json.Nodes;
using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

/// <summary>"Test Connection" (UI-SPEC 4): the probe request, the batches, the row states and the sort.</summary>
public class TestConnectionTests
{
    private static string Server(string host, string ip, int score) =>
        $"{{\"hostName\":\"{host}\",\"ip\":\"{ip}\",\"score\":{score},\"countryLong\":\"Japan\",\"countryShort\":\"JP\",\"logType\":\"2weeks\",\"sslPorts\":[995,443],\"listedPort\":443,\"fqdn\":\"{host}\"}}";

    private static string List(IEnumerable<string> servers) =>
        "{\"servers\":[" + string.Join(",", servers) + "],\"source\":\"Cached\",\"timestampMs\":" +
        DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + ",\"isFresh\":true,\"outcome\":\"synced\"}";

    private static string Reply(JsonObject r, string result) =>
        $"{{\"reply\":\"{r["cmd"]}\",\"id\":{r["id"]},\"ok\":true,\"result\":{result}}}";

    /// <summary>Answers probe requests from <paramref name="outcome"/> (host -> connectMs, or null for a failure).</summary>
    private static async Task<(FakeDaemon d, IpcClient ipc, MainViewModel vm)> Make(Dictionary<string, long?> outcome, int servers = 3)
    {
        var d = new FakeDaemon().Start();
        var list = List(Enumerable.Range(1, servers).Select(i => Server($"h{i}.opengw.net", $"10.0.0.{i}", i * 10)));
        d.Respond = r => (string?)r["cmd"] switch
        {
            "listServers" => new[] { Reply(r, list) },
            "status" => new[] { FakeDaemon.Snapshot("disconnected") },
            "probe" => new[]
            {
                Reply(r, "{\"results\":[" + string.Join(",", r["targets"]!.AsArray().Select(t =>
                {
                    var host = (string)t!["host"]!;
                    return outcome.TryGetValue(host, out var ms) && ms is { } v
                        ? $"{{\"host\":\"{host}\",\"ok\":true,\"port\":443,\"connectMs\":{v},\"helloMs\":{v + 5}}}"
                        : $"{{\"host\":\"{host}\",\"ok\":false,\"error\":\"Cannot connect\"}}";
                })) + "]}"),
            },
            _ => Array.Empty<string>(),
        };
        var ipc = d.Client();
        var vm = new MainViewModel(ipc, new MemorySettings { HasAgreedToDisclaimer = true });
        await vm.StartAsync();
        return (d, ipc, vm);
    }

    [Fact]
    public async Task SendsOneProbeWithTheViewsServersAndTheirPortOrder()
    {
        var (d, ipc, vm) = await Make(new() { ["10.0.0.1"] = 40 });
        await using var _d = d; await using var _i = ipc;
        await vm.TestConnectionsAsync();
        var r = await d.NextRequestAsync("probe");
        var targets = r["targets"]!.AsArray();
        Assert.Equal(new[] { "10.0.0.3", "10.0.0.2", "10.0.0.1" }, targets.Select(t => (string)t!["host"]!));
        Assert.Equal(new[] { 443, 995 }, targets[0]!["ports"]!.AsArray().Select(p => (int)p!));
        Assert.Null(r["proxy"]);
    }

    [Fact]
    public async Task RowsShowTheConnectTimeOrWhyItFailed()
    {
        var (d, ipc, vm) = await Make(new() { ["10.0.0.1"] = 40, ["10.0.0.3"] = 15 });
        await using var _d = d; await using var _i = ipc;
        Assert.All(vm.Servers, s => Assert.Equal("—", s.Test.Text));
        await vm.TestConnectionsAsync();
        var by = vm.Servers.ToDictionary(s => s.Ip, s => s.Test.Text);
        Assert.Equal("40 ms", by["10.0.0.1"]);
        Assert.Equal("Cannot connect", by["10.0.0.2"]);
        Assert.Equal("15 ms", by["10.0.0.3"]);
        Assert.False(vm.IsTesting);
    }

    [Fact]
    public async Task OnlyTheFilteredServersAreTested()
    {
        var (d, ipc, vm) = await Make(new());
        await using var _d = d; await using var _i = ipc;
        vm.Filter.Search = "h2";
        vm.Rebuild();
        await vm.TestConnectionsAsync();
        var r = await d.NextRequestAsync("probe");
        Assert.Equal(new[] { "10.0.0.2" }, r["targets"]!.AsArray().Select(t => (string)t!["host"]!));
        Assert.Equal("Cannot connect", vm.Servers.Single().Test.Text);
    }

    [Fact]
    public async Task ManyServersGoInBatchesOfEight()
    {
        var (d, ipc, vm) = await Make(Enumerable.Range(1, 20).ToDictionary(i => $"10.0.0.{i}", i => (long?)i), servers: 20);
        await using var _d = d; await using var _i = ipc;
        await vm.TestConnectionsAsync();
        var sizes = new List<int>();
        for (int i = 0; i < 3; i++) sizes.Add((await d.NextRequestAsync("probe"))["targets"]!.AsArray().Count);
        Assert.Equal(new[] { 8, 8, 4 }, sizes);
        Assert.All(vm.Servers, s => Assert.EndsWith(" ms", s.Test.Text));
    }

    [Fact]
    public async Task SortingByTheColumnRanksWorkingServersByTimeThenUntestedThenFailed()
    {
        // h1 40 ms, h2 fails, h3 15 ms; h4 is reset afterwards as if it had never been tested.
        var (d, ipc, vm) = await Make(new() { ["10.0.0.1"] = 40, ["10.0.0.3"] = 15 }, servers: 4);
        await using var _d = d; await using var _i = ipc;
        await vm.TestConnectionsAsync();
        vm.Servers.Single(s => s.Ip == "10.0.0.4").Test.Set(ProbePhase.None);
        vm.Sort(SortKey.Test);
        Assert.Equal(SortKey.Test, vm.SortKey);
        Assert.False(vm.SortDescending);
        Assert.Equal(new[] { "10.0.0.3", "10.0.0.1", "10.0.0.4", "10.0.0.2" }, vm.Servers.Select(s => s.Ip));
    }

    [Fact]
    public async Task ResultsSurviveARefreshOfTheList()
    {
        var (d, ipc, vm) = await Make(new() { ["10.0.0.1"] = 40 });
        await using var _d = d; await using var _i = ipc;
        await vm.TestConnectionsAsync();
        await vm.LoadListAsync();   // new server objects from the daemon
        Assert.Equal("40 ms", vm.Servers.Single(s => s.Ip == "10.0.0.1").Test.Text);
    }

    [Fact]
    public async Task ADaemonErrorFailsTheBatchWithItsMessage()
    {
        await using var d = new FakeDaemon().Start();
        var list = List(new[] { Server("h1.opengw.net", "10.0.0.1", 10) });
        d.Respond = r => (string?)r["cmd"] switch
        {
            "listServers" => new[] { Reply(r, list) },
            "probe" => new[] { $"{{\"reply\":\"probe\",\"id\":{r["id"]},\"ok\":false,\"error\":\"This daemon has no server engine\"}}" },
            _ => Array.Empty<string>(),
        };
        await using var ipc = d.Client();
        var vm = new MainViewModel(ipc, new MemorySettings { HasAgreedToDisclaimer = true });
        await vm.StartAsync();
        await vm.TestConnectionsAsync();
        Assert.Equal("This daemon has no server engine", vm.Servers.Single().Test.Text);
        Assert.False(vm.IsTesting);
    }

    [Fact]
    public async Task ASecondTestWhileOneRunsIsIgnored()
    {
        var (d, ipc, vm) = await Make(new() { ["10.0.0.1"] = 40 });
        await using var _d = d; await using var _i = ipc;
        var a = vm.TestConnectionsAsync();
        var b = vm.TestConnectionsAsync();
        await Task.WhenAll(a, b);
        await d.NextRequestAsync("probe");
        await Task.Delay(100);
        Assert.DoesNotContain(d.Requests, r => (string?)r["cmd"] == "probe");
    }
}
