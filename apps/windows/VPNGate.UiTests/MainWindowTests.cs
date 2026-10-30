using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VPNGate.App;
using VPNGate.Core;
using VPNGate.Tests;
using Xunit;

namespace VPNGate.UiTests;

/// <summary>The main window (UI-SPEC 1-4, 11) in-process, over a view model wired to a fake daemon.</summary>
public class MainWindowTests
{
    private static async Task WithMain(Func<Rig, MainWindow, FrameworkElement, Task> body, bool agreed = true, bool waitForList = true)
    {
        await UiHost.Run(async () =>
        {
            await using var rig = new Rig(agreed);
            var w = new MainWindow(rig.Vm);
            try
            {
                var root = await Probe.Show(w);
                if (waitForList) await Probe.Until(() => rig.Vm.Servers.Count == 4, "the list to load");
                await Probe.Settle();
                await body(rig, w, root);
            }
            finally
            {
                w.Close();
            }
        });
    }

    private static ListView List(FrameworkElement root) => (ListView)root.FindName("ServerList");

    private static IEnumerable<string> RowHosts(FrameworkElement root) => List(root).Items.Cast<VpnServer>().Select(s => s.HostName);

    [Fact]
    public async Task ListShowsEveryServerSortedByScoreAndRenders() => await WithMain(async (rig, w, root) =>
    {
        Assert.Equal(new[] { "b.opengw.net", "c.opengw.net", "a.opengw.net", "d.opengw.net" }, RowHosts(root));
        Assert.True(Probe.HasText(root, "VPN Gate Public VPN Relay Servers"));
        Assert.Contains(Probe.Texts(root), t => t.StartsWith("4 Public VPN Relay Servers on the Earth!"));
        // The first row's cells (Hostname, IP, Region, Speed ...) are really bound.
        var list = List(root);
        Assert.True(Probe.HasText(list, "b.opengw.net"));
        Assert.True(Probe.HasText(list, "900"));
        Assert.Equal(0, UiHost.Unhandled.Count);
        await Probe.Shot(root, "main-list");
    });

    [Fact]
    public async Task ColumnHeadersAreAllThere() => await WithMain((rig, w, root) =>
    {
        foreach (var h in new[] { "IP Address (Hostname)", "Region", "Uptime", "VPN Sessions", "Line Speed", "Ping (Google, SE)", "Logging Policy", "Total Score" })
            Assert.Contains(Probe.All<HyperlinkButton>(root), b => b.Content as string == h);
        return Task.CompletedTask;
    });

    [Fact]
    public async Task ClickingAColumnHeaderSortsAndAgainReverses() => await WithMain(async (rig, w, root) =>
    {
        Probe.Invoke(Probe.Find<HyperlinkButton>(root, b => b.Content as string == "Line Speed", "Line Speed"));
        await Probe.Settle();
        Assert.Equal(new[] { "c.opengw.net", "a.opengw.net", "b.opengw.net", "d.opengw.net" }, RowHosts(root));
        Probe.Invoke(Probe.Find<HyperlinkButton>(root, b => b.Content as string == "Line Speed", "Line Speed"));
        await Probe.Settle();
        Assert.Equal(new[] { "d.opengw.net", "b.opengw.net", "a.opengw.net", "c.opengw.net" }, RowHosts(root));
        Probe.Invoke(Probe.Find<HyperlinkButton>(root, b => b.Content as string == "IP Address (Hostname)", "host header"));
        await Probe.Settle();
        Assert.Equal("a.opengw.net", RowHosts(root).First());
        await Probe.Shot(root, "main-sorted-by-host");
    });

    [Fact]
    public async Task SearchCountryAndClearFiltersWork() => await WithMain(async (rig, w, root) =>
    {
        var search = (TextBox)root.FindName("SearchBox");
        var country = (ComboBox)root.FindName("CountryBox");
        Assert.Equal(new object[] { "All countries", "Japan", "Korea Republic of", "United States" }, country.Items.Cast<object>().ToArray());
        Assert.DoesNotContain(Probe.All<Button>(root), b => b.Content as string == "Clear Filters" && b.Visibility == Visibility.Visible);

        search.Text = "korea";
        await Probe.Settle();
        Assert.Equal(new[] { "b.opengw.net" }, RowHosts(root));
        Assert.Contains(Probe.All<Button>(root), b => b.Content as string == "Clear Filters" && b.Visibility == Visibility.Visible);
        await Probe.Shot(root, "main-filtered");

        Probe.Invoke(Probe.ButtonNamed(root, "Clear Filters"));
        await Probe.Settle();
        Assert.Equal("", search.Text);
        Assert.Equal(4, RowHosts(root).Count());

        country.SelectedIndex = 1;
        await Probe.Settle();
        Assert.Equal(new[] { "a.opengw.net", "d.opengw.net" }, RowHosts(root).OrderBy(h => h));
        var logging = (ComboBox)root.FindName("LoggingBox");
        Assert.Equal(4, logging.Items.Count);
        logging.SelectedIndex = 3; // "No logs only": none of the fake servers qualifies
        await Probe.Settle();
        Assert.Empty(RowHosts(root));
    });

    [Fact]
    public async Task ToolbarAndMenuAreComplete() => await WithMain((rig, w, root) =>
    {
        Assert.Equal(new[] { "File", "View", "Help" }, Probe.All<MenuBarItem>(root).Select(m => m.Title).ToArray());
        foreach (var b in new[] { "Details", "Refresh List", "Settings" })
            Assert.Contains(Probe.All<Button>(root), x => x.Content as string == b);
        Assert.NotNull(root.FindName("FavoritesToggle"));
        // No selection yet: Details is off and the action button cannot connect.
        Assert.False(Probe.ButtonNamed(root, "Details").IsEnabled);
        return Task.CompletedTask;
    });

    [Fact]
    public async Task SelectingARowEnablesDetailsAndTheDetailsSheetListsTheServer() => await WithMain(async (rig, w, root) =>
    {
        List(root).SelectedIndex = 0;
        await Probe.Settle();
        Assert.Equal("b.opengw.net", rig.Vm.Selected?.HostName);
        Assert.True(Probe.ButtonNamed(root, "Details").IsEnabled);

        Probe.Invoke(Probe.ButtonNamed(root, "Details"));
        var dialog = await Probe.OpenDialog(root.XamlRoot);
        Assert.Contains("b.opengw.net", dialog.Title as string);
        foreach (var label in new[] { "DDNS Hostname:", "IP Address:", "Country:", "Line Speed:", "Score:", "Ping to Japan:", "Ping to Google:", "UDP port:",
                     "SSL-VPN Ports:", "OpenVPN UDP Ports:", "L2TP / IPsec:", "Logging Policy:", "Operator / Owner:" })
            Assert.True(Probe.HasText(dialog, label), "missing row " + label);
        Assert.True(Probe.HasText(dialog, "Korea Republic of (KR)"));
        Assert.True(Probe.HasText(dialog, "900"));
        Assert.Contains(Probe.All<TextBox>(dialog), t => t.Text == "Welcome to b.opengw.net" && t.IsReadOnly);
        await Probe.Shot(dialog, "server-details");
        dialog.Hide();
        await Probe.Settle();
    });

    [Fact]
    public async Task DisclaimerBlocksUntilAgreed() => await WithMain(async (rig, w, root) =>
    {
        var dialog = await Probe.OpenDialog(root.XamlRoot);
        Assert.Equal("VPN Gate Academic Experiment Service", dialog.Title as string);
        Assert.Equal("Agree and Continue", dialog.PrimaryButtonText);
        Assert.Equal("Disagree & Quit", dialog.CloseButtonText);
        Assert.True(rig.Vm.ShowDisclaimer);
        await Probe.Shot(root, "disclaimer");
        Probe.Invoke(Probe.ButtonNamed(dialog, "Agree and Continue"));
        await Probe.Until(() => !rig.Vm.ShowDisclaimer, "the disclaimer to close");
        Assert.True(rig.Settings.HasAgreedToDisclaimer);
        // After agreeing the list loads.
        await Probe.Until(() => rig.Vm.Servers.Count == 4, "the list to load after agreeing");
    }, agreed: false, waitForList: false);

    [Fact]
    public async Task ConnectedStateShowsTheConnectionCard() => await WithMain(async (rig, w, root) =>
    {
        rig.Status = FakeDaemon.Snapshot("connected", ",\"server\":\"2.2.2.2\",\"virtualIP\":\"10.21.0.5\"");
        await rig.Vm.PollAsync();
        await Probe.Until(() => rig.Vm.State == ConnectionState.Connected, "the status poll to report connected. Unhandled: " + string.Join(";", UiHost.Unhandled));
        await Probe.Settle();
        Assert.Equal(ConnectionState.Connected, rig.Vm.State);
        Assert.True(Probe.HasText(root, Fmt.Title(ConnectionState.Connected)));
        Assert.True(Probe.HasText(root, "b.opengw.net"));
        Assert.True(Probe.HasText(root, "Virtual IP 10.21.0.5"));
        Assert.Contains(Probe.All<Button>(root), b => b.Content as string == rig.Vm.ActionLabel);
        await Probe.Shot(root, "main-connected");
    });

    [Fact]
    public async Task TheWindowPollsTheServiceOnATimer() => await WithMain(async (rig, w, root) =>
    {
        int Polls() => rig.Daemon.Requests.Count(r => (string?)r["cmd"] == "status");
        var before = Polls();
        await Probe.Until(() => Polls() >= before + 2, "two more status polls from the window's timer", seconds: 20);
    });
}
