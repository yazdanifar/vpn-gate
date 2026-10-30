using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>Settings with the tabs General, Proxy, Routing and Advanced (UI-SPEC 8). Every change is saved at once.</summary>
internal sealed class SettingsWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly ISettingsStore _s;
    private readonly Action _showAccounts;
    private readonly Action _showLog;

    public SettingsWindow(MainViewModel vm, Action showAccounts, Action showLog)
    {
        _vm = vm;
        _s = vm.Settings;
        _showAccounts = showAccounts;
        _showLog = showLog;
        Title = "Settings";
        Ui.Size(this, 620, 640);
        var pivot = new Pivot { Margin = new Thickness(12) };
        pivot.Items.Add(Tab("General", General()));
        pivot.Items.Add(Tab("Proxy", Proxy()));
        pivot.Items.Add(Tab("Routing", new RoutingEditor(_s.Routing, _s.Save, () => Content.XamlRoot)));
        pivot.Items.Add(Tab("Advanced", Advanced()));
        Content = pivot;
    }

    private static PivotItem Tab(string header, UIElement body) => new()
    {
        Header = header,
        Content = new ScrollViewer { Content = new StackPanel { Padding = new Thickness(0, 0, 16, 16), Children = { body } } },
    };

    private ToggleSwitch Toggle(string header, bool on, Action<bool> set)
    {
        var t = new ToggleSwitch { Header = header, IsOn = on };
        t.Toggled += (_, _) => { set(t.IsOn); _s.Save(); };
        return t;
    }

    private UIElement General()
    {
        var p = new StackPanel { Spacing = 8 };
        p.Children.Add(Ui.Header("Connection"));
        var notice = Ui.Error(null);
        var login = new ToggleSwitch { Header = "Launch at login", IsOn = StartupRegistration.IsEnabled };
        login.Toggled += (_, _) =>
        {
            if (StartupRegistration.Set(login.IsOn)) { Ui.SetError(notice, null); return; }
            // Windows refused: put the switch back and say so.
            login.IsOn = StartupRegistration.IsEnabled;
            Ui.SetError(notice, "Windows did not allow changing the startup setting.");
        };
        p.Children.Add(login);
        p.Children.Add(notice);
        p.Children.Add(Toggle("Reconnect automatically", _s.AutoReconnect, v => _s.AutoReconnect = v));
        var ipv6Caption = Ui.Caption("");
        var ipv6 = new ToggleSwitch { Header = "Block IPv6 while connected", IsOn = _s.BlockIPv6 };
        void IPv6Text() => ipv6Caption.Text = ipv6.IsOn
            ? "On: IPv6 is captured and dropped, which prevents IPv6 leaks; dual-stack sites fall back to IPv4 through the VPN."
            : "Off: IPv6 only works if the VPN network provides it (a router advertising an IPv6 prefix). Otherwise IPv6 is still captured and dropped, so nothing leaks.";
        ipv6.Toggled += (_, _) => { _s.BlockIPv6 = ipv6.IsOn; _s.Save(); IPv6Text(); };
        IPv6Text();
        p.Children.Add(ipv6);
        p.Children.Add(ipv6Caption);

        p.Children.Add(Ui.Header("Mode"));
        var mode = new ComboBox { MinWidth = 260 };
        mode.Items.Add("Full tunnel (whole PC)");
        mode.Items.Add("SOCKS5 proxy only");
        mode.SelectedIndex = _s.TunnelMode == TunnelMode.SocksProxy ? 1 : 0;
        var socksPanel = new StackPanel { Spacing = 6 };
        var socksError = Ui.Error(null);
        var socks = new NumberBox { Header = "SOCKS port", Value = _s.SocksPort, Minimum = 0, Maximum = 99999, Width = 160, HorizontalAlignment = HorizontalAlignment.Left };
        socks.ValueChanged += (_, e) =>
        {
            if (double.IsNaN(e.NewValue)) return;
            var port = (int)e.NewValue;
            var ok = port is >= 1024 and <= 65535;
            Ui.SetError(socksError, ok ? null : "Use a port from 1024 to 65535.");
            if (ok) { _s.SocksPort = port; _s.Save(); }
        };
        socksPanel.Children.Add(socks);
        socksPanel.Children.Add(socksError);
        var modeCaption = Ui.Caption("");
        void ModeText()
        {
            var socksMode = mode.SelectedIndex == 1;
            socksPanel.Visibility = socksMode ? Visibility.Visible : Visibility.Collapsed;
            modeCaption.Text = socksMode
                ? $"Apps you point at 127.0.0.1:{_s.SocksPort} use the VPN, and their DNS lookups are resolved remotely. Routing rules and IPv6 blocking do not apply. Applies to the next connection."
                : "All traffic of this PC goes through the VPN. Applies to the next connection.";
        }
        mode.SelectionChanged += (_, _) =>
        {
            _s.TunnelMode = mode.SelectedIndex == 1 ? TunnelMode.SocksProxy : TunnelMode.FullTunnel;
            _s.Save();
            ModeText();
        };
        ModeText();
        p.Children.Add(new TextBlock { Text = "Use the VPN as" });
        p.Children.Add(mode);
        p.Children.Add(socksPanel);
        p.Children.Add(modeCaption);

        p.Children.Add(Ui.Header("VPN connections"));
        var open = new Button { Content = "Open VPN Connection Settings…" };
        open.Click += (_, _) => _showAccounts();
        p.Children.Add(open);
        p.Children.Add(Ui.Caption("Manage your own SoftEther servers and accounts in a separate window."));

        p.Children.Add(Ui.Header("VPN component"));
        var status = new TextBlock();
        void Status() => status.Text = "Status: " + (_vm.ServiceRunning ? "Running" : "Not running");
        Status();
        _vm.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.ServiceRunning)) DispatcherQueue.TryEnqueue(Status);
        };
        p.Children.Add(status);
        p.Children.Add(Ui.Caption("The “VPN Gate” Windows service creates the VPN adapter, routes and DNS. It is installed and removed by the VPN Gate installer."));
        return p;
    }

    private UIElement Proxy()
    {
        var p = new StackPanel { Spacing = 8 };
        p.Children.Add(Ui.Header("Connect through"));
        var kind = new ComboBox { MinWidth = 260 };
        kind.Items.Add("No proxy (direct)");
        kind.Items.Add("HTTP proxy (CONNECT)");
        kind.Items.Add("SOCKS5 proxy");
        kind.SelectedIndex = (int)_s.ProxyKind;
        p.Children.Add(kind);

        var fields = new StackPanel { Spacing = 8 };
        TextBox Text(string header, string value, Action<string> set)
        {
            var t = new TextBox { Header = header, Text = value, Width = 320, HorizontalAlignment = HorizontalAlignment.Left };
            t.TextChanged += (_, _) => { set(t.Text); _s.Save(); };
            return t;
        }
        fields.Children.Add(Text("Proxy host", _s.ProxyHost, v => _s.ProxyHost = v.Trim()));
        var port = new NumberBox { Header = "Proxy port", Value = _s.ProxyPort, Minimum = 0, Maximum = 65535, Width = 160, HorizontalAlignment = HorizontalAlignment.Left };
        port.ValueChanged += (_, e) => { if (!double.IsNaN(e.NewValue)) { _s.ProxyPort = (int)e.NewValue; _s.Save(); } };
        fields.Children.Add(port);
        fields.Children.Add(Text("Username (optional)", _s.ProxyUsername, v => _s.ProxyUsername = v));
        var pw = new PasswordBox { Header = "Password", Password = _vm.ProxyPassword ?? "", Width = 320, HorizontalAlignment = HorizontalAlignment.Left };
        pw.PasswordChanged += (_, _) => _vm.ProxyPassword = pw.Password;
        fields.Children.Add(pw);
        p.Children.Add(fields);
        void Show() => fields.Visibility = kind.SelectedIndex == 0 ? Visibility.Collapsed : Visibility.Visible;
        kind.SelectionChanged += (_, _) =>
        {
            _s.ProxyKind = (ProxyKind)Math.Max(0, kind.SelectedIndex);
            _s.Save();
            Show();
        };
        Show();
        p.Children.Add(Ui.Caption(
            "If you are using a proxy server, you might not be able to use VPN Relay Servers which don't support the TCP port 443 as “SSL-VPN Connection” from such a proxy-mandated network."));
        return p;
    }

    private UIElement Advanced()
    {
        var p = new StackPanel { Spacing = 8 };
        p.Children.Add(Ui.Header("Server list"));
        var mirror = new TextBox { Header = "Mirror URL (optional)", Text = _s.MirrorUrl, Width = 420, HorizontalAlignment = HorizontalAlignment.Left };
        mirror.TextChanged += (_, _) => { _s.MirrorUrl = mirror.Text.Trim(); _s.Save(); };
        p.Children.Add(mirror);
        p.Children.Add(Ui.Caption("Used first when set, e.g. if vpngate.net is blocked."));
        p.Children.Add(Ui.Header("Log"));
        var log = new Button { Content = "Show Log…" };
        log.Click += (_, _) => _showLog();
        p.Children.Add(log);
        return p;
    }
}
