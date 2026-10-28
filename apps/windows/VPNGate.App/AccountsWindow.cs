using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using Microsoft.UI.Xaml.Media;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>"VPN Connection Settings": the user's own SoftEther servers (UI-SPEC 5).</summary>
internal sealed class AccountsWindow : Window
{
    private readonly MainViewModel _vm;
    private readonly Action _showMain;
    private readonly StackPanel _rows = new() { Spacing = 2 };
    private readonly Grid _root = new() { Padding = new Thickness(12), RowSpacing = 8 };
    private ClientAccount? _selected;
    private Button _connect = null!, _disconnect = null!, _properties = null!, _delete = null!;

    public AccountsWindow(MainViewModel vm, Action showMain)
    {
        _vm = vm;
        _showMain = showMain;
        Title = "VPN Connection Settings";
        Ui.Size(this, 760, 420);

        _root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        _root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var bar = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        var add = new Button { Content = "New Setting" };
        add.Click += async (_, _) => await EditAsync(null);
        _connect = new Button { Content = "Connect" };
        _connect.Click += (_, _) => ConnectSelected();
        _disconnect = new Button { Content = "Disconnect" };
        _disconnect.Click += (_, _) => _vm.Disconnect();
        _properties = new Button { Content = "Properties" };
        _properties.Click += async (_, _) => await EditAsync(_selected);
        _delete = new Button { Content = "Delete" };
        _delete.Click += (_, _) => DeleteSelected();
        foreach (var b in new[] { add, _connect, _disconnect, _properties, _delete }) bar.Children.Add(b);
        _root.Children.Add(bar);

        var notice = Ui.Error(_vm.Accounts?.LoadNotice);
        notice.Foreground = new SolidColorBrush(Colors.DarkOrange);
        Grid.SetRow(notice, 1);
        _root.Children.Add(notice);

        var scroll = new ScrollViewer { Content = _rows };
        Grid.SetRow(scroll, 2);
        _root.Children.Add(scroll);
        Content = _root;

        if (_vm.Accounts is { } a) a.Changed += OnAccountsChanged;
        _vm.PropertyChanged += OnVmChanged;
        Closed += (_, _) =>
        {
            if (_vm.Accounts is { } x) x.Changed -= OnAccountsChanged;
            _vm.PropertyChanged -= OnVmChanged;
        };
        Refresh();
    }

    private void OnAccountsChanged() => DispatcherQueue.TryEnqueue(Refresh);

    private void OnVmChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(MainViewModel.State) or nameof(MainViewModel.Server)) Refresh();
    }

    private static string StatusOf(ConnectionState s) => s switch
    {
        ConnectionState.Connected => "Connected",
        ConnectionState.Connecting or ConnectionState.Authenticating or ConnectionState.Dhcp => "Connecting",
        ConnectionState.Reconnecting => "Reconnecting…",
        _ => "Offline",
    };

    private void Refresh()
    {
        var accounts = _vm.Accounts?.Accounts ?? new List<ClientAccount>();
        if (_selected is not null && accounts.All(a => a.Id != _selected.Id)) _selected = null;
        _rows.Children.Clear();

        // Pinned first row: the public list.
        var pinned = RowGrid("VPN Gate Public VPN Relay Servers", "Free servers run by volunteers — open the list", "", "", true);
        pinned.DoubleTapped += (_, _) => _showMain();
        _rows.Children.Add(Wrap(pinned, null));

        if (accounts.Count == 0)
        {
            var empty = new StackPanel { Spacing = 6, Margin = new Thickness(0, 24, 0, 0), HorizontalAlignment = HorizontalAlignment.Center };
            empty.Children.Add(new TextBlock { Text = "No VPN connection settings yet", FontWeight = Microsoft.UI.Text.FontWeights.SemiBold });
            empty.Children.Add(Ui.Text("Add one to connect to your own SoftEther VPN server.", opacity: 0.7));
            var b = new Button { Content = "New Setting…", HorizontalAlignment = HorizontalAlignment.Center };
            b.Click += async (_, _) => await EditAsync(null);
            empty.Children.Add(b);
            _rows.Children.Add(empty);
        }
        foreach (var a in accounts)
        {
            var status = _vm.ActiveAccount?.Id == a.Id ? StatusOf(_vm.State) : "Offline";
            var grid = RowGrid(a.Name, status, $"{a.Host}:{(a.PortList.Count > 0 ? a.PortList[0] : 443)}", a.Hub, false);
            grid.DoubleTapped += (_, _) => { _selected = a; ConnectSelected(); };
            _rows.Children.Add(Wrap(grid, a));
        }
        var idle = _vm.State == ConnectionState.Disconnected;
        _connect.IsEnabled = _selected is not null && idle;
        _disconnect.IsEnabled = !idle;
        _properties.IsEnabled = _delete.IsEnabled = _selected is not null;
    }

    // Column order: name, status, host, hub (the header row is the first child of the pinned row's captions).
    private static Grid RowGrid(string name, string status, string host, string hub, bool pinned)
    {
        var g = new Grid { ColumnSpacing = 8, Padding = new Thickness(8, 6, 8, 6) };
        foreach (var w in new[] { 2.0, 1.0, 2.0, 1.0 }) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(w, GridUnitType.Star) });
        void Add(string t, int col, bool dim = false, Brush? brush = null)
        {
            var tb = new TextBlock { Text = t, TextTrimming = TextTrimming.CharacterEllipsis, Opacity = dim ? 0.7 : 1 };
            if (brush is not null) tb.Foreground = brush;
            Grid.SetColumn(tb, col);
            g.Children.Add(tb);
        }
        if (pinned)
        {
            var tb = new TextBlock { Text = name, FontWeight = Microsoft.UI.Text.FontWeights.SemiBold };
            var sub = Ui.Caption(status);
            var st = new StackPanel();
            st.Children.Add(tb);
            st.Children.Add(sub);
            Grid.SetColumnSpan(st, 4);
            g.Children.Add(st);
            return g;
        }
        Add(name, 0);
        Add(status, 1, brush: status switch
        {
            "Connected" => new SolidColorBrush(Colors.SeaGreen),
            "Connecting" or "Reconnecting…" => new SolidColorBrush(Colors.DarkOrange),
            _ => null,
        });
        Add(host, 2, true);
        Add(hub, 3, true);
        return g;
    }

    private Border Wrap(Grid grid, ClientAccount? account)
    {
        var selected = account is not null && _selected?.Id == account.Id;
        var border = new Border
        {
            CornerRadius = new CornerRadius(4),
            Background = new SolidColorBrush(selected ? Windows.UI.Color.FromArgb(0x33, 0x25, 0x63, 0xEB) : Windows.UI.Color.FromArgb(0x11, 0x80, 0x80, 0x80)),
            Child = grid,
        };
        if (account is null) return border;
        border.Tapped += (_, _) => { _selected = account; Refresh(); };
        var menu = new MenuFlyout();
        var connect = new MenuFlyoutItem { Text = "Connect", IsEnabled = _vm.State == ConnectionState.Disconnected };
        connect.Click += (_, _) => { _selected = account; ConnectSelected(); };
        var props = new MenuFlyoutItem { Text = "Properties…" };
        props.Click += async (_, _) => { _selected = account; await EditAsync(account); };
        var dup = new MenuFlyoutItem { Text = "Duplicate" };
        dup.Click += (_, _) => _vm.Accounts?.Duplicate(account);
        var del = new MenuFlyoutItem { Text = "Delete" };
        del.Click += (_, _) => { _selected = account; DeleteSelected(); };
        foreach (var i in new[] { connect, props, dup, del }) menu.Items.Add(i);
        border.ContextFlyout = menu;
        return border;
    }

    private void ConnectSelected()
    {
        if (_selected is not null && _vm.State == ConnectionState.Disconnected) _vm.Connect(_selected);
    }

    private void DeleteSelected()
    {
        if (_selected is null) return;
        _vm.Accounts?.Delete(_selected);
        _selected = null;
    }

    private async Task EditAsync(ClientAccount? account)
    {
        if (_root.XamlRoot is null) return;
        await AccountEditor.ShowAsync(this, _root.XamlRoot, _vm, account);
    }
}
