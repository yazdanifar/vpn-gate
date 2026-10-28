using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

public class MainViewModelTests
{
    private static string ListJson(params (string host, string ip, string country, int score)[] rows) =>
        "{\"servers\":[" + string.Join(",", rows.Select(r =>
            $"{{\"hostName\":\"{r.host}\",\"ip\":\"{r.ip}\",\"score\":{r.score},\"countryLong\":\"{r.country}\",\"countryShort\":\"JP\",\"logType\":\"2weeks\",\"sslPorts\":[995,443],\"listedPort\":443,\"fqdn\":\"{r.host}\"}}")) +
        "],\"source\":\"Cached\",\"timestampMs\":" + DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() + ",\"isFresh\":true,\"outcome\":\"synced\"}";

    private static IEnumerable<string> Serve(System.Text.Json.Nodes.JsonObject r, string list) => (string?)r["cmd"] switch
    {
        "listServers" or "refreshServers" => new[] { $"{{\"reply\":\"{r["cmd"]}\",\"id\":{r["id"]},\"ok\":true,\"result\":{list}}}" },
        "status" => new[] { FakeDaemon.Snapshot("disconnected") },
        _ => Array.Empty<string>(),
    };

    private static async Task<(FakeDaemon d, IpcClient ipc, MainViewModel vm, MemorySettings s)> Make(bool agreed = true, string? list = null,
        TimeSpan? reconnect = null, TimeSpan? answer = null)
    {
        var d = new FakeDaemon().Start();
        var l = list ?? ListJson(("a.opengw.net", "1.1.1.1", "Japan", 10), ("b.opengw.net", "2.2.2.2", "Korea", 90));
        d.Respond = r => Serve(r, l);
        var ipc = d.Client();
        var s = new MemorySettings { HasAgreedToDisclaimer = agreed };
        var vm = new MainViewModel(ipc, s, reconnectDelay: reconnect ?? TimeSpan.FromMilliseconds(80), answerTimeout: answer ?? TimeSpan.FromSeconds(30));
        await vm.StartAsync();
        return (d, ipc, vm, s);
    }

    private static async Task Until(Func<bool> cond)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (!cond()) { Assert.True(DateTime.UtcNow < until, "condition not reached"); await Task.Delay(10); }
    }

    [Fact]
    public async Task LoadsTheListSortedByScoreDescending()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        Assert.Equal(new[] { "b.opengw.net", "a.opengw.net" }, vm.Servers.Select(s => s.HostName));
        Assert.Equal(new[] { "Japan", "Korea" }, vm.Countries);
        Assert.Equal("Cached", vm.ListSource);
        Assert.StartsWith("2 Public VPN Relay Servers on the Earth!", vm.ListStatus);
        Assert.True(vm.ServiceRunning);
    }

    [Fact]
    public async Task FallsBackToADownloadWhenThereIsNoList()
    {
        await using var d = new FakeDaemon().Start();
        var list = ListJson(("a.opengw.net", "1.1.1.1", "Japan", 10));
        d.Respond = r => (string?)r["cmd"] == "listServers"
            ? new[] { $"{{\"reply\":\"listServers\",\"id\":{r["id"]},\"ok\":false,\"error\":\"none\"}}" }
            : Serve(r, list);
        await using var ipc = d.Client();
        var vm = new MainViewModel(ipc, new MemorySettings { HasAgreedToDisclaimer = true });
        await vm.StartAsync();
        Assert.Single(vm.Servers);
        Assert.False(vm.IsLoading);
        Assert.Equal("refreshServers", (string?)(await d.NextRequestAsync("refreshServers"))["cmd"]);
    }

    [Fact]
    public async Task ListErrorIsShown()
    {
        await using var d = new FakeDaemon().Start();
        d.Respond = r => (string?)r["cmd"] == "status" ? Array.Empty<string>()
            : new[] { $"{{\"reply\":\"{r["cmd"]}\",\"id\":{r["id"]},\"ok\":false,\"error\":\"offline\"}}" };
        await using var ipc = d.Client();
        var vm = new MainViewModel(ipc, new MemorySettings { HasAgreedToDisclaimer = true });
        await vm.StartAsync();
        Assert.Empty(vm.Servers);
        Assert.Equal("List update failed (offline). Try again.", vm.ListStatus);
    }

    [Fact]
    public async Task ServiceMissingExplainsItself()
    {
        await using var ipc = IpcClient.ForNamedPipe("vga" + Guid.NewGuid().ToString("N")[..10]);
        var vm = new MainViewModel(ipc, new MemorySettings { HasAgreedToDisclaimer = true }, answerTimeout: TimeSpan.FromMilliseconds(50));
        await vm.StartAsync();
        Assert.False(vm.ServiceRunning);
        vm.Connect(new VpnServer { HostName = "h", Ip = "1.1.1.1" });
        await Until(() => vm.Notice is not null);
        Assert.Contains("service is not running", vm.Notice);
        Assert.Equal(ConnectionState.Disconnected, vm.State);
    }

    [Fact]
    public async Task ConnectSendsTheLegacyRequestWithPrioritizedPorts()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        vm.Selected = vm.Servers.First(s => s.HostName == "a.opengw.net");
        Assert.True(vm.CanConnect);
        vm.PrimaryAction();
        var r = await d.NextRequestAsync("connect");
        Assert.Equal("1.1.1.1", (string?)r["host"]);
        Assert.Equal(443, (int?)r["port"]);
        Assert.Equal(new[] { 443, 995 }, r["ports"]!.AsArray().Select(p => (int)p!));
        Assert.False((bool)r["autoReconnect"]!);
        Assert.True((bool)r["blockIPv6"]!);
        Assert.Equal("fullTunnel", (string?)r["tunnelMode"]);
        Assert.Null(r["routing"]);
        await Until(() => vm.State == ConnectionState.Connecting);
    }

    [Fact]
    public async Task StateFollowsDaemonEventsAndShowsTraffic()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        await d.WaitConnectedAsync();
        await d.SendAsync("{\"state\":\"connected\",\"server\":\"2.2.2.2\",\"virtualIP\":\"10.211.0.5\",\"bytesIn\":2048,\"bytesOut\":0,\"log\":\"Connected\",\"ipcVersion\":9}");
        await Until(() => vm.State == ConnectionState.Connected);
        Assert.Equal("b.opengw.net", vm.ServerName);
        Assert.Equal("10.211.0.5", vm.VirtualIp);
        Assert.Equal("Disconnect", vm.ActionLabel);
        Assert.StartsWith("0:00:0", vm.TrafficText);
        Assert.Contains("↓ 2.0 KB", vm.TrafficText);
        Assert.Contains("Connected", vm.LogLines);
        Assert.NotNull(vm.ConnectedAt);
    }

    [Fact]
    public async Task ErrorEventSetsNoticeAndLog()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        await d.WaitConnectedAsync();
        await d.SendAsync("{\"state\":\"disconnected\",\"bytesIn\":0,\"bytesOut\":0,\"error\":\"Login failed\"}");
        await Until(() => vm.Notice == "Login failed");
        Assert.Contains("Error: Login failed", vm.LogLines);
    }

    [Fact]
    public async Task OldIpcVersionAsksForAReinstall()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        await d.WaitConnectedAsync();
        await d.SendAsync("{\"state\":\"disconnected\",\"bytesIn\":0,\"bytesOut\":0,\"helperVersion\":8}");
        vm.ApplyEvent(new HelperEvent { State = ConnectionState.Disconnected, IpcVersion = 8 });
        Assert.Contains("too old", vm.Notice);
    }

    [Fact]
    public async Task DisconnectSendsTheCommand()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        vm.Disconnect();
        Assert.Equal("disconnect", (string?)(await d.NextRequestAsync("disconnect"))["cmd"]);
    }

    [Fact]
    public async Task ListConnectionsReconnectAfterTheDelayUntilTheUserDisconnects()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        vm.Connect(vm.Servers.First());
        await d.NextRequestAsync("connect");
        await d.SendAsync(FakeDaemon.Snapshot("connected", ",\"server\":\"2.2.2.2\""));
        await Until(() => vm.State == ConnectionState.Connected);
        await d.SendAsync("{\"state\":\"disconnected\",\"bytesIn\":0,\"bytesOut\":0,\"error\":\"link lost\"}");
        await Until(() => vm.State == ConnectionState.Reconnecting);
        Assert.Equal(1, vm.ReconnectAttempts);
        var again = await d.NextRequestAsync("connect");
        Assert.Equal("2.2.2.2", (string?)again["host"]);

        await d.SendAsync("{\"state\":\"disconnected\",\"bytesIn\":0,\"bytesOut\":0}");
        await Until(() => vm.ReconnectAttempts == 2 && vm.State == ConnectionState.Reconnecting);
        vm.Disconnect();
        Assert.Equal(ConnectionState.Disconnected, vm.State);
        await d.NextRequestAsync("disconnect");
        await Task.Delay(250);
        Assert.DoesNotContain(d.Requests, r => (string?)r["cmd"] == "connect");
    }

    [Fact]
    public async Task UnansweredConnectGivesUpWithAHint()
    {
        var (d, ipc, vm, _) = await Make(answer: TimeSpan.FromMilliseconds(150));
        await using var _d = d; await using var _i = ipc;
        vm.Connect(vm.Servers.First());
        await Until(() => vm.Notice is not null);
        Assert.Contains("not responding", vm.Notice);
        Assert.Equal(ConnectionState.Disconnected, vm.State);
    }

    [Fact]
    public async Task PipeDropReturnsToDisconnected()
    {
        var (d, ipc, vm, _) = await Make();
        await using var _d = d; await using var _i = ipc;
        await d.WaitConnectedAsync();
        await d.SendAsync(FakeDaemon.Snapshot("connected", ",\"server\":\"2.2.2.2\""));
        await Until(() => vm.State == ConnectionState.Connected);
        d.Drop();
        await Until(() => vm.State == ConnectionState.Disconnected);
        Assert.False(vm.ServiceRunning);
        Assert.Null(vm.ConnectedAt);
    }

    // MARK: disclaimer

    [Fact]
    public async Task ConnectBeforeConsentParksTheActionUntilAgree()
    {
        var (d, ipc, vm, s) = await Make(agreed: false);
        await using var _d = d; await using var _i = ipc;
        Assert.True(vm.ShowDisclaimer);
        vm.Connect(vm.Servers.First());
        await Task.Delay(100);
        Assert.DoesNotContain(d.Requests, r => (string?)r["cmd"] == "connect");
        vm.Agree();
        Assert.False(vm.ShowDisclaimer);
        Assert.True(s.HasAgreedToDisclaimer);
        Assert.Equal("2.2.2.2", (string?)(await d.NextRequestAsync("connect"))["host"]);
    }

    [Fact]
    public async Task DisagreeAsksToQuitAndDropsTheParkedConnect()
    {
        var (d, ipc, vm, s) = await Make(agreed: false);
        await using var _d = d; await using var _i = ipc;
        bool quit = false;
        vm.QuitRequested += () => quit = true;
        vm.Connect(vm.Servers.First());
        vm.Disagree();
        Assert.True(quit);
        Assert.False(s.HasAgreedToDisclaimer);
        vm.Agree();
        await Task.Delay(100);
        Assert.DoesNotContain(d.Requests, r => (string?)r["cmd"] == "connect");
    }

    // MARK: filter and sort

    [Fact]
    public async Task FilterSortAndFavorites()
    {
        var (d, ipc, vm, s) = await Make();
        await using var _d = d; await using var _i = ipc;
        vm.Filter.Country = "Japan";
        vm.Rebuild();
        Assert.Equal(new[] { "a.opengw.net" }, vm.Servers.Select(x => x.HostName));
        Assert.True(vm.FilterActive);
        Assert.EndsWith("showing 1", vm.ListStatus);
        vm.ClearFilters();
        Assert.Equal(2, vm.Servers.Count);
        vm.Sort(SortKey.Host);
        Assert.Equal("a.opengw.net", vm.Servers[0].HostName);
        vm.Sort(SortKey.Host);
        Assert.Equal("b.opengw.net", vm.Servers[0].HostName);
        vm.ToggleFavorite(vm.Servers[0]);
        Assert.Contains("b.opengw.net", s.Favorites);
        vm.Filter.FavoritesOnly = true;
        vm.Rebuild();
        Assert.Equal(new[] { "b.opengw.net" }, vm.Servers.Select(x => x.HostName));
    }

    [Fact]
    public async Task SettingsFileRoundTripsConsentAndFavorites()
    {
        var path = Path.Combine(Path.GetTempPath(), "vpngate-settings-" + Guid.NewGuid().ToString("N"), "settings.json");
        var a = new JsonFileSettings(path) { HasAgreedToDisclaimer = true };
        a.Favorites.Add("x.opengw.net");
        a.Save();
        var b = new JsonFileSettings(path);
        Assert.True(b.HasAgreedToDisclaimer);
        Assert.Contains("x.opengw.net", b.Favorites);
        File.WriteAllText(path, "{broken");
        Assert.False(new JsonFileSettings(path).HasAgreedToDisclaimer);
        Directory.Delete(Path.GetDirectoryName(path)!, true);
        await Task.CompletedTask;
    }
}
