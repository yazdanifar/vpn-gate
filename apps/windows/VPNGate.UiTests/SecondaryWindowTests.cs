using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VPNGate.App;
using VPNGate.Core;
using Xunit;

namespace VPNGate.UiTests;

/// <summary>Accounts list and editor, routing editor, Settings tabs, History and Log (UI-SPEC 5-10).</summary>
public class SecondaryWindowTests
{
    private static async Task WithWindow<TWindow>(Rig rig, Func<TWindow> make, Func<TWindow, FrameworkElement, Task> body) where TWindow : Window
    {
        var w = make();
        try
        {
            var root = await Probe.Show(w);
            await body(w, root);
        }
        finally
        {
            w.Close();
        }
    }

    private static ClientAccount Account(string name, string host, string hub) => new() { Name = name, Host = host, Hub = hub, Username = "alice" };

    // MARK: accounts

    [Fact]
    public async Task AccountsListShowsThePinnedRowAndTheSavedSettings() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        rig.Accounts.Add(Account("Home", "vpn.example.com", "HOME"), "pw");
        rig.Accounts.Add(Account("Work", "10.1.2.3", "OFFICE"), "pw");
        await WithWindow(rig, () => new AccountsWindow(rig.Vm, () => { }), async (w, root) =>
        {
            Assert.Equal("VPN Connection Settings", w.Title);
            Assert.True(Probe.HasText(root, "VPN Gate Public VPN Relay Servers"));
            foreach (var t in new[] { "Home", "Work", "vpn.example.com:443", "10.1.2.3:443", "HOME", "OFFICE" })
                Assert.True(Probe.HasText(root, t), "missing " + t);
            Assert.Equal(2, Probe.Texts(root).Count(t => t == "Offline"));
            foreach (var b in new[] { "New Setting", "Connect", "Disconnect", "Properties", "Delete" })
                Assert.Contains(Probe.All<Button>(root), x => x.Content as string == b);
            // Nothing selected, nothing connected: everything but New Setting is off.
            foreach (var b in new[] { "Connect", "Disconnect", "Properties", "Delete" })
                Assert.False(Probe.ButtonNamed(root, b).IsEnabled, b + " should be disabled");
            await Probe.Shot(root, "accounts-list");
        });
    });

    [Fact]
    public async Task AccountsListWithoutSettingsShowsTheEmptyState() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        await WithWindow(rig, () => new AccountsWindow(rig.Vm, () => { }), async (w, root) =>
        {
            Assert.True(Probe.HasText(root, "No VPN connection settings yet"));
            Assert.True(Probe.HasText(root, "Add one to connect to your own SoftEther VPN server."));
            await Probe.Shot(root, "accounts-empty");
        });
    });

    [Fact]
    public async Task NewSettingOpensTheEditorWhichSavesOnlyWhenValid() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        await WithWindow(rig, () => new AccountsWindow(rig.Vm, () => { }), async (w, root) =>
        {
            Probe.Invoke(Probe.ButtonNamed(root, "New Setting"));
            var dialog = await Probe.OpenDialog(root.XamlRoot);
            Assert.Equal("New VPN Connection Setting", dialog.Title as string);
            foreach (var h in new[] { "General Setting", "Destination VPN Server", "User Authentication Setting", "Setting Name:", "Host Name / IP Address:",
                         "Port Number (comma separated):", "Virtual HUB Name:", "Auth Type:", "User Name:", "Password:" })
                Assert.True(Probe.HasText(dialog, h), "missing " + h);
            Assert.False(dialog.IsPrimaryButtonEnabled, "an empty form cannot be saved");
            await Probe.Shot(dialog, "account-editor-empty");

            var boxes = Probe.All<TextBox>(dialog).ToList();
            boxes[0].Text = "Lab";           // Setting Name
            boxes[1].Text = "not a host!";   // Host Name / IP Address
            await Probe.Settle(200);
            Assert.True(Probe.HasText(dialog, "Not a valid host name or IP address."));
            Assert.False(dialog.IsPrimaryButtonEnabled);
            boxes[1].Text = "lab.example.com";
            boxes[4].Text = "alice";         // User Name
            await Probe.Settle(200);
            Assert.True(dialog.IsPrimaryButtonEnabled, "name, host and user are enough");
            await Probe.Shot(dialog, "account-editor-filled");

            Probe.Invoke(Probe.ButtonNamed(dialog, "Save"));
            await Probe.Until(() => rig.Accounts.Accounts.Count == 1, "the setting to be saved");
            Assert.Equal("Lab", rig.Accounts.Accounts[0].Name);
            Assert.Equal("lab.example.com", rig.Accounts.Accounts[0].Host);
            await Probe.Until(() => Probe.HasText(root, "lab.example.com:443"), "the list to show the new row");
        });
    });

    [Fact]
    public async Task EditorForAnExistingSettingIsPrefilledAndCancelKeepsIt() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        var acc = Account("Home", "vpn.example.com", "HOME");
        rig.Accounts.Add(acc, "pw");
        await WithWindow(rig, () => new AccountsWindow(rig.Vm, () => { }), async (w, root) =>
        {
            var edit = AccountEditor.ShowAsync(w, root.XamlRoot, rig.Vm, rig.Accounts.Accounts[0]);
            var dialog = await Probe.OpenDialog(root.XamlRoot);
            Assert.Equal("Edit VPN Connection Setting", dialog.Title as string);
            var boxes = Probe.All<TextBox>(dialog).ToList();
            Assert.Equal("Home", boxes[0].Text);
            Assert.Equal("vpn.example.com", boxes[1].Text);
            Assert.Equal("HOME", boxes[3].Text);
            Assert.Equal("alice", boxes[4].Text);
            Assert.True(dialog.IsPrimaryButtonEnabled);
            await Probe.Shot(dialog, "account-editor-existing");
            Probe.Invoke(Probe.ButtonNamed(dialog, "Cancel"));
            Assert.False(await edit);
            Assert.Single(rig.Accounts.Accounts);
        });
    });

    // MARK: routing editor

    [Fact]
    public async Task RoutingEditorShowsRulesAndWritesChangesBack() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        var config = new RoutingConfig
        {
            DefaultAction = RoutingAction.Proxy,
            Rules =
            {
                new RoutingRule { Type = RoutingRuleType.DomainSuffix, Value = "example.com", Action = RoutingAction.Direct },
                new RoutingRule { Type = RoutingRuleType.Cidr, Value = "10.0.0.0/8", Action = RoutingAction.Block, Enabled = false },
                new RoutingRule { Type = RoutingRuleType.Ip, Value = "8.8.8.8", Action = RoutingAction.Proxy },
            },
        };
        var changes = 0;
        var host = new Window();
        RoutingEditor? editor = null;
        try
        {
            editor = new RoutingEditor(config, () => changes++, () => host.Content.XamlRoot);
            host.Content = new ScrollViewer { Content = new Border { Padding = new Thickness(16), Child = editor } };
            var root = await Probe.Show(host);
            foreach (var t in new[] { "example.com", "10.0.0.0/8", "8.8.8.8", "Off", "Unmatched traffic", "Rules", "By default" })
                Assert.True(Probe.HasText(root, t), "missing " + t);
            foreach (var pill in new[] { "Direct", "Block", "Proxy" })
                Assert.True(Probe.HasText(root, pill), "missing pill " + pill);
            Assert.Contains(Probe.All<Button>(root), b => b.Content as string == "Add Rule…");
            await Probe.Shot(root, "routing-editor");

            var bypass = Probe.All<ToggleSwitch>(root).Single();
            bypass.IsOn = true;
            await Probe.Settle(200);
            Assert.True(config.BypassPrivateNetworks);
            Assert.Equal(1, changes);

            var def = Probe.All<ComboBox>(root).First();
            def.SelectedIndex = 1;
            await Probe.Settle(200);
            Assert.Equal(RoutingAction.Direct, config.DefaultAction);
            Assert.Equal(2, changes);
            Assert.Contains(Probe.Texts(root), t => t.StartsWith("Everything bypasses the tunnel"));
        }
        finally
        {
            host.Close();
        }
    });

    [Fact]
    public async Task RoutingEditorWithNoRulesSaysSo() => await UiHost.Run(async () =>
    {
        var host = new Window();
        try
        {
            host.Content = new ScrollViewer { Content = new RoutingEditor(new RoutingConfig(), () => { }, () => host.Content.XamlRoot) };
            var root = await Probe.Show(host);
            Assert.True(Probe.HasText(root, "No custom rules. Traffic follows the default action above."));
            await Probe.Shot(root, "routing-editor-empty");
        }
        finally
        {
            host.Close();
        }
    });

    // MARK: settings

    [Fact]
    public async Task SettingsHasFourTabsAndSavesWhatTheyChange() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        var saved = 0;
        var settings = new CountingSettings(() => saved++);
        // The window reads vm.Settings, so build a view model over the counting store.
        var vm = new MainViewModel(rig.Daemon.Client(), settings, a => a());
        var shown = 0;
        await WithWindow(rig, () => new SettingsWindow(vm, () => shown++, () => shown += 10), async (w, root) =>
        {
            var pivot = Probe.All<Pivot>(root).FirstOrDefault() ?? (Pivot)w.Content;
            Assert.Equal(new[] { "General", "Proxy", "Routing", "Advanced" }, pivot.Items.Cast<PivotItem>().Select(i => (string)i.Header).ToArray());

            // General
            foreach (var t in new[] { "Connection", "Mode", "VPN connections", "VPN component", "Use the VPN as" })
                Assert.True(Probe.HasText(root, t), "General is missing " + t);
            Assert.Contains(Probe.All<ToggleSwitch>(root), s => s.Header as string == "Launch at login");
            Assert.Contains(Probe.Texts(root), t => t.StartsWith("Status: "));
            await Probe.Shot(root, "settings-general");
            var reconnect = Probe.All<ToggleSwitch>(root).First(s => s.Header as string == "Reconnect automatically");
            reconnect.IsOn = false;
            await Probe.Settle(100);
            Assert.False(settings.AutoReconnect);
            Assert.True(saved > 0);
            var ipv6 = Probe.All<ToggleSwitch>(root).First(s => s.Header as string == "Block IPv6 while connected");
            ipv6.IsOn = false;
            await Probe.Settle(100);
            Assert.False(settings.BlockIPv6);
            Assert.Contains(Probe.Texts(root), t => t.StartsWith("Off: IPv6 only works"));
            var mode = Probe.All<ComboBox>(root).First(c => c.Items.Contains("SOCKS5 proxy only"));
            mode.SelectedIndex = 1;
            await Probe.Settle(200);
            Assert.Equal(TunnelMode.SocksProxy, settings.TunnelMode);
            Assert.Contains(Probe.All<NumberBox>(root), n => n.Header as string == "SOCKS port" && n.Visibility == Visibility.Visible);
            await Probe.Shot(root, "settings-general-socks");
            Probe.Invoke(Probe.ButtonNamed(root, "Open VPN Connection Settings…"));
            Assert.Equal(1, shown);

            // Proxy
            pivot.SelectedIndex = 1;
            await Probe.Settle();
            var kind = Probe.All<ComboBox>(root).First(c => c.Items.Contains("HTTP proxy (CONNECT)"));
            Assert.Equal(0, kind.SelectedIndex);
            var host = Probe.All<TextBox>(root).First(t => t.Header as string == "Proxy host");
            Assert.False(IsShown(host), "the proxy fields are hidden while no proxy is selected");
            kind.SelectedIndex = 2;
            await Probe.Settle(200);
            Assert.Equal(ProxyKind.Socks5, settings.ProxyKind);
            Assert.True(IsShown(host));
            host.Text = " proxy.example.com ";
            await Probe.Settle(100);
            Assert.Equal("proxy.example.com", settings.ProxyHost);
            await Probe.Shot(root, "settings-proxy");

            // Routing
            pivot.SelectedIndex = 2;
            await Probe.Settle();
            Assert.True(Probe.HasText(root, "Unmatched traffic"));
            await Probe.Shot(root, "settings-routing");

            // Advanced
            pivot.SelectedIndex = 3;
            await Probe.Settle();
            var mirror = Probe.All<TextBox>(root).First(t => t.Header as string == "Mirror URL (optional)");
            mirror.Text = "https://mirror.example/list";
            await Probe.Settle(100);
            Assert.Equal("https://mirror.example/list", settings.MirrorUrl);
            await Probe.Shot(root, "settings-advanced");
            Probe.Invoke(Probe.ButtonNamed(root, "Show Log…"));
            Assert.Equal(11, shown);
        });
    });

    /// <summary>Visible in the tree: itself and every parent not collapsed.</summary>
    private static bool IsShown(UIElement e)
    {
        for (DependencyObject? d = e; d is not null; d = Microsoft.UI.Xaml.Media.VisualTreeHelper.GetParent(d))
            if (d is UIElement u && u.Visibility == Visibility.Collapsed) return false;
        return true;
    }

    private sealed class CountingSettings : MemorySettings
    {
        private readonly Action _saved;
        public CountingSettings(Action saved) => _saved = saved;
        public override void Save() => _saved();
    }

    // MARK: history and log

    [Fact]
    public async Task HistoryListsConnectionsAndClearEmptiesIt() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        var a = rig.History.RecordStart("b.opengw.net", "2.2.2.2");
        rig.History.RecordEnd(a, 5_000_000, 1_000_000, null);
        var b = rig.History.RecordStart("c.opengw.net", "3.3.3.3");
        rig.History.RecordEnd(b, 10, 20, "Login failed");
        rig.History.RecordStart("active.opengw.net", "5.5.5.5");
        await WithWindow(rig, () => new HistoryWindow(rig.History), async (w, root) =>
        {
            Assert.Equal("Connection History", w.Title);
            foreach (var h in new[] { "Server", "Address", "Connected", "Duration", "Traffic", "Result" })
                Assert.True(Probe.HasText(root, h), "missing column " + h);
            foreach (var t in new[] { "b.opengw.net", "c.opengw.net", "active.opengw.net", "2.2.2.2", "Login failed", "ended", "active" })
                Assert.True(Probe.HasText(root, t), "missing " + t);
            var empty = Probe.Find<TextBlock>(root, t => t.Text == "No connections yet.", "empty message");
            Assert.Equal(Visibility.Collapsed, empty.Visibility);
            await Probe.Shot(root, "history");

            Probe.Invoke(Probe.ButtonNamed(root, "Clear"));
            await Probe.Until(() => empty.Visibility == Visibility.Visible, "the empty message");
            Assert.Empty(rig.History.Entries);
            Assert.False(Probe.ButtonNamed(root, "Clear").IsEnabled);
            await Probe.Shot(root, "history-empty");
        });
    });

    [Fact]
    public async Task LogWindowShowsTheConnectionLog() => await UiHost.Run(async () =>
    {
        await using var rig = new Rig();
        rig.Vm.ApplyEvent(new HelperEvent { State = ConnectionState.Connecting, Log = "Connecting to b.opengw.net" });
        rig.Vm.ApplyEvent(new HelperEvent { State = ConnectionState.Disconnected, Error = "Login failed" });
        await WithWindow(rig, () => new LogWindow(rig.Vm), async (w, root) =>
        {
            Assert.Equal("Connection Log", w.Title);
            var box = Probe.All<TextBox>(root).Single();
            Assert.Contains("Connecting to b.opengw.net", box.Text);
            Assert.Contains("Error: Login failed", box.Text);
            Assert.True(Probe.ButtonNamed(root, "Copy").IsEnabled);
            await Probe.Shot(root, "log");
        });
    });
}
