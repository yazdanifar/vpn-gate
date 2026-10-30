using System.Text.Json;
using Microsoft.UI.Dispatching;
using VPNGate.Core;
using VPNGate.Tests;

namespace VPNGate.UiTests;

/// <summary>A view model wired to a fake daemon on a named pipe, with its data files in a temp directory. Create it on the UI thread.</summary>
internal sealed class Rig : IAsyncDisposable
{
    public FakeDaemon Daemon { get; }
    public MainViewModel Vm { get; }
    public MemorySettings Settings { get; }
    public AccountStore Accounts { get; }
    public ConnectionHistoryStore History { get; }
    public string Dir { get; }
    /// <summary>What the daemon answers to every status poll.</summary>
    public string Status { get; set; } = FakeDaemon.Snapshot("disconnected");

    public static readonly VpnServer[] Servers =
    {
        Server("a.opengw.net", "1.1.1.1", "Japan", "JP", 500, 300_000_000, 30, 10, 3),
        Server("b.opengw.net", "2.2.2.2", "Korea Republic of", "KR", 900, 100_000_000, 80, 50, 12),
        Server("c.opengw.net", "3.3.3.3", "United States", "US", 700, 500_000_000, 200, 5, 1),
        Server("d.opengw.net", "4.4.4.4", "Japan", "JP", 100, 50_000_000, 15, 2, 30),
    };

    private static VpnServer Server(string host, string ip, string country, string cc, int score, long speed, int ping, int sessions, int days) => new()
    {
        HostName = host, Ip = ip, CountryLong = country, CountryShort = cc, Score = score, Speed = speed, Ping = ping, PingToGoogle = ping / 2,
        Sessions = sessions, UptimeMs = days * 86_400_000L, LogType = "2weeks", SslPorts = new() { 995, 443 }, ListedPort = 443, Fqdn = host,
        OperatorName = "Volunteer " + cc, Message = "Welcome to " + host,
    };

    public Rig(bool agreed = true)
    {
        Dir = Path.Combine(Path.GetTempPath(), "vg-ui-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(Dir);
        var json = JsonSerializer.Serialize(new
        {
            servers = Servers, source = "Cached", timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), isFresh = true, outcome = "synced",
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        Daemon = new FakeDaemon().Start();
        Daemon.Respond = r => (string?)r["cmd"] switch
        {
            "listServers" or "refreshServers" => new[] { $"{{\"reply\":\"{r["cmd"]}\",\"id\":{r["id"]},\"ok\":true,\"result\":{json}}}" },
            "status" => new[] { Status },
            _ => Array.Empty<string>(),
        };
        Settings = new MemorySettings { HasAgreedToDisclaimer = agreed };
        var secrets = new MemorySecretStore();
        Accounts = new AccountStore(Path.Combine(Dir, "accounts.json"), secrets);
        History = new ConnectionHistoryStore(Path.Combine(Dir, "history.json"));
        var queue = DispatcherQueue.GetForCurrentThread();
        Vm = new MainViewModel(Daemon.Client(), Settings, a => queue.TryEnqueue(() => a()), accounts: Accounts, secrets: secrets, history: History);
    }

    public async ValueTask DisposeAsync()
    {
        await Daemon.DisposeAsync();
        try { Directory.Delete(Dir, true); } catch (IOException) { }
    }
}
