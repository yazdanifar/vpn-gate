using System.Text.Json.Nodes;
using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

public class IpcClientTests
{
    [Fact]
    public async Task ConnectFailsQuietlyWithoutADaemon()
    {
        await using var ipc = IpcClient.ForNamedPipe("vga" + Guid.NewGuid().ToString("N")[..10]);
        Assert.False(await ipc.ConnectAsync());
        Assert.False(await ipc.SendAsync(HelperRequest.Of("status")));
        var e = await Assert.ThrowsAsync<HelperRequestException>(() => ipc.ListServersAsync());
        Assert.Equal(HelperRequestFailure.Disconnected, e.Kind);
    }

    [Fact]
    public async Task EventsAreDeliveredAndRequestsAreRecorded()
    {
        await using var d = new FakeDaemon().Start();
        d.Respond = r => (string?)r["cmd"] == "status" ? new[] { FakeDaemon.Snapshot("connected", ",\"server\":\"1.2.3.4\",\"virtualIP\":\"10.0.0.2\"") } : Array.Empty<string>();
        await using var ipc = d.Client();
        var got = new TaskCompletionSource<HelperEvent>();
        ipc.EventReceived += e => got.TrySetResult(e);
        Assert.True(await ipc.SendAsync(HelperRequest.Of("status")));
        var e = await got.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(ConnectionState.Connected, e.State);
        Assert.Equal("10.0.0.2", e.VirtualIP);
        Assert.Equal(9, e.IpcVersion);
        Assert.Equal("status", (string?)(await d.NextRequestAsync())["cmd"]);
    }

    [Fact]
    public async Task RepliesAreMatchedByIdEvenOutOfOrder()
    {
        await using var d = new FakeDaemon().Start();
        var held = new List<JsonObject>();
        d.Respond = r =>
        {
            held.Add(r);
            if (held.Count < 2) return Array.Empty<string>();
            // answer the second request first
            return held.AsEnumerable().Reverse().Select(x =>
                $"{{\"reply\":\"{x["cmd"]}\",\"id\":{x["id"]},\"ok\":true,\"result\":{{\"valid\":true,\"which\":\"{x["cmd"]}\"}}}}");
        };
        await using var ipc = d.Client();
        var a = ipc.RequestAsync(HelperRequest.Of("validateAccount"));
        await d.NextRequestAsync("validateAccount");
        var b = ipc.RequestAsync(HelperRequest.Of("syncDat"));
        Assert.Equal("validateAccount", (string?)(await a.WaitAsync(TimeSpan.FromSeconds(10))).Result!["which"]);
        Assert.Equal("syncDat", (string?)(await b.WaitAsync(TimeSpan.FromSeconds(10))).Result!["which"]);
    }

    [Fact]
    public async Task OkFalseBecomesAFailedException()
    {
        await using var d = new FakeDaemon().Start();
        d.Respond = r => new[] { $"{{\"reply\":\"listServers\",\"id\":{r["id"]},\"ok\":false,\"error\":\"no list\"}}" };
        await using var ipc = d.Client();
        var e = await Assert.ThrowsAsync<HelperRequestException>(() => ipc.ListServersAsync());
        Assert.Equal(HelperRequestFailure.Failed, e.Kind);
        Assert.Equal("no list", e.Message);
    }

    [Fact]
    public async Task SilentDaemonTimesOut()
    {
        await using var d = new FakeDaemon().Start();
        await using var ipc = d.Client();
        var e = await Assert.ThrowsAsync<HelperRequestException>(() => ipc.RequestAsync(HelperRequest.Of("syncDat"), TimeSpan.FromMilliseconds(150)));
        Assert.Equal(HelperRequestFailure.Timeout, e.Kind);
    }

    [Fact]
    public async Task DropFailsOpenRequestsAndReconnectsOnNextSend()
    {
        await using var d = new FakeDaemon().Start();
        await using var ipc = d.Client();
        var dropped = new TaskCompletionSource();
        ipc.Disconnected += () => dropped.TrySetResult();
        var pending = ipc.RequestAsync(HelperRequest.Of("refreshServers"));
        await d.NextRequestAsync("refreshServers");
        d.Drop();
        var e = await Assert.ThrowsAsync<HelperRequestException>(() => pending);
        Assert.Equal(HelperRequestFailure.Disconnected, e.Kind);
        await dropped.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.False(ipc.IsConnected);

        Assert.True(await ipc.SendAsync(HelperRequest.Of("status")));
        Assert.Equal("status", (string?)(await d.NextRequestAsync("status"))["cmd"]);
    }

    [Fact]
    public async Task GarbageAndUnknownLinesAreIgnored()
    {
        await using var d = new FakeDaemon().Start();
        await using var ipc = d.Client();
        var events = new List<HelperEvent>();
        var two = new TaskCompletionSource();
        ipc.EventReceived += e => { lock (events) { events.Add(e); if (events.Count == 2) two.TrySetResult(); } };
        Assert.True(await ipc.ConnectAsync());
        await d.WaitConnectedAsync();
        await d.SendAsync("not json");
        await d.SendAsync("{\"state\":\"bogus\"}");
        await d.SendAsync("{\"reply\":\"x\",\"ok\":true}");
        await d.SendAsync("[1,2]");
        await d.SendAsync(FakeDaemon.Snapshot("connecting"));
        await d.SendAsync(FakeDaemon.Snapshot("dhcp"));
        await two.Task.WaitAsync(TimeSpan.FromSeconds(10));
        Assert.Equal(new[] { ConnectionState.Connecting, ConnectionState.Dhcp }, events.Select(e => e.State));
    }
}
