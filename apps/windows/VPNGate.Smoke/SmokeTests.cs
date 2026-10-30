using System.Diagnostics;
using System.Text.Json;
using FlaUI.Core;
using FlaUI.Core.AutomationElements;
using FlaUI.Core.Capturing;
using FlaUI.Core.Definitions;
using FlaUI.UIA3;
using VPNGate.Core;
using VPNGate.Tests;
using Xunit;

namespace VPNGate.Smoke;

/// <summary>
/// Launches the real, unpackaged VPNGate.exe (path in VPNGATE_EXE) with VPNGATE_PIPE pointing at a fake daemon and VPNGATE_DATA_DIR at a
/// temp directory, then drives it through UI Automation like a user (or a screen reader) would.
/// </summary>
public class SmokeTests
{
    private static string Exe => Environment.GetEnvironmentVariable("VPNGATE_EXE")
        ?? throw new InvalidOperationException("set VPNGATE_EXE to the built VPNGate.exe");

    private static string ShotDir
    {
        get
        {
            var d = Environment.GetEnvironmentVariable("VPNGATE_SHOTS") is { Length: > 0 } e ? e : Path.Combine(AppContext.BaseDirectory, "shots");
            Directory.CreateDirectory(d);
            return d;
        }
    }

    private static void Shot(string name) => Capture.Screen().ToFile(Path.Combine(ShotDir, name + ".png"));

    private static string ListJson()
    {
        var servers = new[]
        {
            new VpnServer { HostName = "a.opengw.net", Ip = "1.1.1.1", CountryLong = "Japan", CountryShort = "JP", Score = 500, LogType = "2weeks", SslPorts = new() { 443 } },
            new VpnServer { HostName = "b.opengw.net", Ip = "2.2.2.2", CountryLong = "Korea Republic of", CountryShort = "KR", Score = 900, LogType = "2weeks", SslPorts = new() { 443 } },
            new VpnServer { HostName = "c.opengw.net", Ip = "3.3.3.3", CountryLong = "United States", CountryShort = "US", Score = 700, LogType = "2weeks", SslPorts = new() { 443 } },
        };
        return JsonSerializer.Serialize(new
        {
            servers, source = "Cached", timestampMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(), isFresh = true, outcome = "synced",
        }, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    }

    private static async Task<T> Retry<T>(Func<T?> get, string what, int seconds = 30) where T : class
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (DateTime.UtcNow < until)
        {
            try { if (get() is { } v) return v; } catch (Exception e) when (e is FlaUI.Core.Exceptions.FlaUIException or System.Runtime.InteropServices.COMException) { }
            await Task.Delay(200);
        }
        throw new TimeoutException("timed out waiting for " + what);
    }

    [Fact]
    public async Task RealAppLaunchesShowsTheDisclaimerThenTheListAndQuits()
    {
        var dir = Path.Combine(Path.GetTempPath(), "vg-smoke-" + Guid.NewGuid().ToString("N")[..8]);
        Directory.CreateDirectory(dir);
        await using var daemon = new FakeDaemon().Start();
        var list = ListJson();
        daemon.Respond = r => (string?)r["cmd"] switch
        {
            "listServers" or "refreshServers" => new[] { $"{{\"reply\":\"{r["cmd"]}\",\"id\":{r["id"]},\"ok\":true,\"result\":{list}}}" },
            "status" => new[] { FakeDaemon.Snapshot("disconnected") },
            _ => Array.Empty<string>(),
        };
        var psi = new ProcessStartInfo(Exe) { WorkingDirectory = Path.GetDirectoryName(Exe)!, UseShellExecute = false };
        psi.Environment["VPNGATE_PIPE"] = daemon.PipeName;
        psi.Environment["VPNGATE_DATA_DIR"] = dir;

        using var app = Application.Launch(psi);
        try
        {
            using var automation = new UIA3Automation();
            var window = await Retry(() => app.GetMainWindow(automation, TimeSpan.FromSeconds(2)), "the main window");
            Assert.Equal("VPN Gate Public VPN Relay Servers", window.Title);
            Assert.False(app.HasExited, "the app must stay alive");

            // 1. The disclaimer comes first and cannot be skipped.
            var agree = await Retry(() => window.FindFirstDescendant(c => c.ByAutomationId("PrimaryButton"))?.AsButton(), "the disclaimer's Agree button");
            Assert.Equal("Agree and Continue", agree.Name);
            Assert.NotNull(window.FindFirstDescendant(c => c.ByText("VPN Gate Academic Experiment Service")));
            Shot("smoke-1-disclaimer");
            agree.Invoke();

            // 2. After agreeing, the list is loaded from the daemon.
            var list = await Retry(() => window.FindFirstDescendant(c => c.ByAutomationId("ServerList")), "the server list");
            await Retry(() =>
            {
                var items = list.FindAllChildren(c => c.ByControlType(ControlType.ListItem));
                return items.Length == 3 ? items : null;
            }, "three rows in the list");
            Assert.NotNull(window.FindFirstDescendant(c => c.ByText("Total Score")));
            Assert.NotNull(window.FindFirstDescendant(c => c.ByAutomationId("SearchBox")));
            Assert.NotNull(window.FindFirstDescendant(c => c.ByAutomationId("CountryBox")));
            Shot("smoke-2-list");

            // 3. Typing in the search box filters the list.
            var search = window.FindFirstDescendant(c => c.ByAutomationId("SearchBox")).AsTextBox();
            search.Text = "korea";
            await Retry(() => list.FindAllChildren(c => c.ByControlType(ControlType.ListItem)) is { Length: 1 } r ? r : null, "one row after searching");
            Shot("smoke-3-filtered");

            // 4. Closing the window ends the process.
            window.Close();
            var until = DateTime.UtcNow.AddSeconds(20);
            while (!app.HasExited && DateTime.UtcNow < until) await Task.Delay(200);
            Assert.True(app.HasExited, "the app should exit when its window is closed");
        }
        finally
        {
            if (!app.HasExited) app.Kill();
            try { Directory.Delete(dir, true); } catch (IOException) { }
        }
        Assert.True(File.Exists(Path.Combine(ShotDir, "smoke-2-list.png")));
    }
}
