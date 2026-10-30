using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Input;
using VPNGate.Core;
using Windows.Graphics;

namespace VPNGate.App;

public sealed partial class MainWindow : Window
{
    private readonly DispatcherQueueTimer _tick;
    private LogWindow? _log;
    private AccountsWindow? _accounts;
    private HistoryWindow? _history;
    private SettingsWindow? _settingsWindow;
    private bool _dialogOpen;
    private bool _suppressFilter = true;
    private int _tickCount;

    public MainViewModel Vm { get; }

    public MainWindow() : this(CreateViewModel())
    {
    }

    /// <summary>The production view model: the daemon's pipe (VPNGATE_PIPE overrides the name, for CI) and the files in <see cref="DataDir"/>.</summary>
    private static MainViewModel CreateViewModel()
    {
        var queue = DispatcherQueue.GetForCurrentThread();
        var secrets = CredentialStore.Create();
        var pipe = Environment.GetEnvironmentVariable("VPNGATE_PIPE");
        var ipc = string.IsNullOrEmpty(pipe) ? IpcClient.ForNamedPipe() : IpcClient.ForNamedPipe(pipe);
        return new MainViewModel(ipc, new JsonFileSettings(JsonFileSettings.DefaultPath), a => queue.TryEnqueue(() => a()),
            accounts: new AccountStore(AccountStore.DefaultPath, secrets), secrets: secrets,
            history: new ConnectionHistoryStore(ConnectionHistoryStore.DefaultPath));
    }

    /// <summary>The window over a given view model (UI tests pass one wired to a fake daemon).</summary>
    internal MainWindow(MainViewModel vm)
    {
        Vm = vm;
        var queue = DispatcherQueue.GetForCurrentThread();
        InitializeComponent();
        Ui.Size(this, 1100, 720);
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (File.Exists(icon)) Tray.Icon = new System.Drawing.Icon(icon);

        Vm.QuitRequested += () => Application.Current.Exit();
        Vm.PropertyChanged += OnVmChanged;

        // One tick a second: traffic text every time, a status poll every second one (UI-SPEC 11: the service is polled every 2 s).
        _tick = queue.CreateTimer();
        _tick.Interval = TimeSpan.FromSeconds(1);
        _tick.Tick += async (_, _) =>
        {
            Vm.RefreshTraffic();
            if (++_tickCount % 2 == 0) await Vm.PollAsync();
        };

        // A closed window must stop reacting to the view model (a disposed tray icon throws), which matters once tests open and close many.
        Closed += (_, _) =>
        {
            _tick.Stop();
            Vm.PropertyChanged -= OnVmChanged;
            Tray.Dispose();
        };

        Root.Loaded += async (_, _) =>
        {
            Tray.ForceCreate();
            UpdateTray();
            if (Vm.ShowDisclaimer) await ShowDisclaimerAsync();
            _tick.Start();
            await Vm.StartAsync();
            FillCountries();
            _suppressFilter = false;
        };
    }

    private void OnVmChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        switch (e.PropertyName)
        {
            case nameof(MainViewModel.ShowDisclaimer) when Vm.ShowDisclaimer:
                _ = ShowDisclaimerAsync();
                break;
            case nameof(MainViewModel.Countries):
                FillCountries();
                break;
            case nameof(MainViewModel.State):
            case nameof(MainViewModel.ServerName):
            case nameof(MainViewModel.VirtualIp):
            case nameof(MainViewModel.TrafficText):
                UpdateTray();
                break;
        }
    }

    // MARK: disclaimer (UI-SPEC 1): cannot be dismissed otherwise

    private async Task ShowDisclaimerAsync()
    {
        if (_dialogOpen) return;
        _dialogOpen = true;
        try
        {
            var dialog = new ContentDialog
            {
                XamlRoot = Root.XamlRoot,
                Title = "VPN Gate Academic Experiment Service",
                Content = new StackPanel
                {
                    Spacing = 12,
                    Children =
                    {
                        new TextBlock
                        {
                            TextWrapping = TextWrapping.Wrap,
                            Text = "VPN Gate is an academic research project of the Graduate School of University of Tsukuba, Japan.\n\n" +
                                   "Public VPN relay servers are hosted by volunteers around the world. Anyone can connect through these servers to " +
                                   "achieve anonymity and bypass censorship.\n\n" +
                                   "By clicking “Agree and Continue”, you confirm that you will use this service in compliance with local laws.",
                        },
                    },
                },
                PrimaryButtonText = "Agree and Continue",
                CloseButtonText = "Disagree & Quit",
                DefaultButton = ContentDialogButton.Primary,
            };
            var result = await dialog.ShowAsync();
            if (result == ContentDialogResult.Primary) Vm.Agree();
            else Vm.Disagree();
        }
        finally
        {
            _dialogOpen = false;
        }
    }

    // MARK: toolbar

    private void FillCountries()
    {
        _suppressFilter = true;
        var keep = Vm.Filter.Country;
        CountryBox.Items.Clear();
        CountryBox.Items.Add("All countries");
        foreach (var c in Vm.Countries) CountryBox.Items.Add(c);
        CountryBox.SelectedIndex = Math.Max(0, Vm.Countries.ToList().IndexOf(keep) + 1);
        _suppressFilter = false;
    }

    private void OnSearchChanged(object sender, TextChangedEventArgs e)
    {
        if (_suppressFilter) return;
        Vm.Filter.Search = SearchBox.Text.Trim();
        Vm.Rebuild();
    }

    private void OnCountryChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressFilter) return;
        Vm.Filter.Country = CountryBox.SelectedIndex <= 0 ? ServerFilter.AllCountries : (string)CountryBox.SelectedItem;
        Vm.Rebuild();
    }

    private void OnLoggingChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_suppressFilter) return;
        var weeks = int.Parse((string)((ComboBoxItem)LoggingBox.SelectedItem).Tag);
        Vm.Filter.MaxLogWeeks = weeks < 0 ? null : weeks;
        Vm.Rebuild();
    }

    private void OnFavoritesToggled(object sender, RoutedEventArgs e)
    {
        Vm.Filter.FavoritesOnly = FavoritesToggle.IsChecked == true;
        Vm.Rebuild();
    }

    private void OnClearFilters(object sender, RoutedEventArgs e)
    {
        _suppressFilter = true;
        SearchBox.Text = "";
        CountryBox.SelectedIndex = 0;
        LoggingBox.SelectedIndex = 0;
        FavoritesToggle.IsChecked = false;
        _suppressFilter = false;
        Vm.ClearFilters();
    }

    private async void OnRefresh(object sender, RoutedEventArgs e) => await Vm.RefreshAsync();

    private void OnShowLog(object sender, RoutedEventArgs e) => ShowLog();

    private void ShowLog()
    {
        if (_log is null)
        {
            _log = new LogWindow(Vm);
            _log.Closed += (_, _) => _log = null;
        }
        _log.Activate();
    }

    private void OnShowAccounts(object sender, RoutedEventArgs e) => ShowAccounts();

    private void ShowAccounts()
    {
        if (_accounts is null)
        {
            _accounts = new AccountsWindow(Vm, () => Activate());
            _accounts.Closed += (_, _) => _accounts = null;
        }
        _accounts.Activate();
    }

    private void OnShowHistory(object sender, RoutedEventArgs e)
    {
        if (Vm.History is null) return;
        if (_history is null)
        {
            _history = new HistoryWindow(Vm.History);
            _history.Closed += (_, _) => _history = null;
        }
        _history.Activate();
    }

    private void OnShowSettings(object sender, RoutedEventArgs e)
    {
        if (_settingsWindow is null)
        {
            _settingsWindow = new SettingsWindow(Vm, ShowAccounts, ShowLog);
            _settingsWindow.Closed += (_, _) => _settingsWindow = null;
        }
        _settingsWindow.Activate();
    }

    private void OnWebSite(object sender, RoutedEventArgs e) =>
        _ = Windows.System.Launcher.LaunchUriAsync(new Uri("http://www.vpngate.net/"));

    private async void OnDetails(object sender, RoutedEventArgs e)
    {
        if (Vm.Selected is { } s) await ServerDetails.ShowAsync(Root.XamlRoot, s);
    }

    private async void OnRowDetails(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).Tag is VpnServer s) await ServerDetails.ShowAsync(Root.XamlRoot, s);
    }

    private void OnSort(object sender, RoutedEventArgs e) =>
        Vm.Sort(Enum.Parse<SortKey>((string)((FrameworkElement)sender).Tag));

    // MARK: rows and connect button

    private void OnRowDoubleTapped(object sender, DoubleTappedRoutedEventArgs e)
    {
        if (Vm.State == ConnectionState.Disconnected && Vm.Selected is not null) Vm.Connect();
    }

    private void OnRowConnect(object sender, RoutedEventArgs e)
    {
        if (Vm.State == ConnectionState.Disconnected && ((FrameworkElement)sender).Tag is VpnServer s) Vm.Connect(s);
    }

    private void OnRowFavorite(object sender, RoutedEventArgs e)
    {
        if (((FrameworkElement)sender).Tag is VpnServer s) Vm.ToggleFavorite(s);
    }

    private void OnPrimaryAction(object sender, RoutedEventArgs e) => Vm.PrimaryAction();

    // MARK: tray (UI-SPEC 2)

    private void UpdateTray()
    {
        Tray.ToolTipText = $"VPN Gate: {Fmt.Title(Vm.State)}";
        TrayState.Text = Fmt.Title(Vm.State);
        TrayServer.Text = Vm.ServerName ?? "";
        TrayServer.Visibility = string.IsNullOrEmpty(Vm.ServerName) ? Visibility.Collapsed : Visibility.Visible;
        TrayVirtualIp.Text = Cols.VirtualIp(Vm.VirtualIp);
        TrayVirtualIp.Visibility = string.IsNullOrEmpty(Vm.VirtualIp) ? Visibility.Collapsed : Visibility.Visible;
        TrayTraffic.Text = Vm.TrafficText;
        TrayTraffic.Visibility = Vm.IsConnected ? Visibility.Visible : Visibility.Collapsed;
        var idle = Vm.State == ConnectionState.Disconnected;
        var target = TrayTarget();
        TrayConnect.Text = target is null ? "Connect" : $"Connect to {target.HostName}";
        TrayConnect.Visibility = idle && target is not null ? Visibility.Visible : Visibility.Collapsed;
        TrayDisconnect.Visibility = idle ? Visibility.Collapsed : Visibility.Visible;
        TrayReconnect.Visibility = !idle && Vm.LastServer is not null ? Visibility.Visible : Visibility.Collapsed;
    }

    /// <summary>The last server, else the first favourite (UI-SPEC 2).</summary>
    private VpnServer? TrayTarget() => Vm.LastServer ?? Vm.Servers.FirstOrDefault(Vm.IsFavorite);

    private void OnTrayConnect(object sender, RoutedEventArgs e)
    {
        if (TrayTarget() is { } s) Vm.Connect(s);
    }

    private void OnTrayReconnect(object sender, RoutedEventArgs e) => Vm.Reconnect();

    private void OnTrayDisconnect(object sender, RoutedEventArgs e) => Vm.Disconnect();

    private void OnTrayShow(object sender, RoutedEventArgs e) => Activate();

    private void OnTrayQuit(object sender, RoutedEventArgs e) => Application.Current.Exit();
}
