using System.Text.Json;
using CommunityToolkit.Mvvm.ComponentModel;

namespace VPNGate.Core;

public enum SortKey { Score, Host, Country, Uptime, Sessions, Speed, Ping, Logging }

/// <summary>
/// The main window's state: the daemon's session, the server list and the disclaimer gate (UI-SPEC sections 1, 4, 10, 11).
/// It has no WinUI types, so it runs under plain xunit. Events arrive on the IPC reader thread and are marshalled with
/// <c>post</c> (the UI dispatcher in the app, inline in tests).
/// </summary>
public sealed partial class MainViewModel : ObservableObject
{
    public const int MaxLogLines = 300;
    public static readonly TimeSpan DefaultReconnectDelay = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan DefaultAnswerTimeout = TimeSpan.FromSeconds(10);

    private readonly IpcClient _ipc;
    private readonly ISettingsStore _settings;
    private readonly Action<Action> _post;
    private readonly TimeSpan _reconnectDelay;
    private readonly TimeSpan _answerTimeout;
    private readonly Func<DateTimeOffset> _clock;
    private Action? _parked;
    private List<VpnServer> _all = new();
    private VpnServer? _wanted;
    private CancellationTokenSource? _reconnect;
    private DateTimeOffset _lastEventAt = DateTimeOffset.MinValue;
    private int _loading;

    public MainViewModel(IpcClient ipc, ISettingsStore settings, Action<Action>? post = null,
        TimeSpan? reconnectDelay = null, TimeSpan? answerTimeout = null, Func<DateTimeOffset>? clock = null)
    {
        _ipc = ipc;
        _settings = settings;
        _post = post ?? (a => a());
        _reconnectDelay = reconnectDelay ?? DefaultReconnectDelay;
        _answerTimeout = answerTimeout ?? DefaultAnswerTimeout;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        _hasAgreed = settings.HasAgreedToDisclaimer;
        _showDisclaimer = !_hasAgreed;
        Filter.Favorites = settings.Favorites;
        _ipc.EventReceived += e => _post(() => ApplyEvent(e));
        _ipc.Disconnected += () => _post(OnPipeDropped);
        UpdateListStatus();
    }

    public ServerFilter Filter { get; } = new();

    [ObservableProperty] private ConnectionState _state = ConnectionState.Disconnected;
    [ObservableProperty] private string? _server;
    [ObservableProperty] private string? _virtualIp;
    [ObservableProperty] private ulong _bytesIn;
    [ObservableProperty] private ulong _bytesOut;
    [ObservableProperty] private DateTimeOffset? _connectedAt;
    [ObservableProperty] private string? _notice;
    [ObservableProperty] private bool _serviceRunning;
    [ObservableProperty] private bool _hasAgreed;
    [ObservableProperty] private bool _showDisclaimer;
    [ObservableProperty] private bool _isLoading;
    [ObservableProperty] private string? _listError;
    [ObservableProperty] private string _listStatus = "";
    [ObservableProperty] private string? _listSource;
    [ObservableProperty] private DateTimeOffset? _listTimestamp;
    [ObservableProperty] private IReadOnlyList<VpnServer> _servers = Array.Empty<VpnServer>();
    [ObservableProperty] private IReadOnlyList<string> _countries = Array.Empty<string>();
    [ObservableProperty] private VpnServer? _selected;
    [ObservableProperty] private SortKey _sortKey = SortKey.Score;
    [ObservableProperty] private bool _sortDescending = true;
    [ObservableProperty] private IReadOnlyList<string> _logLines = Array.Empty<string>();

    private readonly List<string> _log = new();

    /// <summary>Raised when the user declines the disclaimer; the app closes.</summary>
    public event Action? QuitRequested;

    public bool IsBusy => State is not ConnectionState.Disconnected and not ConnectionState.Connected;
    public bool IsConnectedOrBusy => State != ConnectionState.Disconnected;
    public string StateTitle => Fmt.Title(State);
    public string TrafficText => Fmt.Traffic(BytesIn, BytesOut, ConnectedAt is { } t ? _clock() - t : null);
    public string? ServerName => Server is null ? null : _all.FirstOrDefault(s => s.Ip == Server)?.HostName ?? Server;
    public bool IsConnected => State == ConnectionState.Connected;
    public bool IsDisconnected => State == ConnectionState.Disconnected;
    public bool IsNotLoading => !IsLoading;
    /// <summary>The bottom-bar button: Connect needs a selection, Disconnect / Cancel are always possible.</summary>
    public bool CanAct => State != ConnectionState.Disconnected || Selected is not null;
    public bool CanConnect => State == ConnectionState.Disconnected && Selected is not null;
    public string ActionLabel => State switch
    {
        ConnectionState.Disconnected => "Connect to the VPN Server",
        ConnectionState.Connected => "Disconnect",
        _ => "Cancel",
    };

    partial void OnStateChanged(ConnectionState value)
    {
        OnPropertyChanged(nameof(IsBusy));
        OnPropertyChanged(nameof(IsConnectedOrBusy));
        OnPropertyChanged(nameof(StateTitle));
        OnPropertyChanged(nameof(CanConnect));
        OnPropertyChanged(nameof(CanAct));
        OnPropertyChanged(nameof(IsConnected));
        OnPropertyChanged(nameof(IsDisconnected));
        OnPropertyChanged(nameof(ActionLabel));
    }

    partial void OnSelectedChanged(VpnServer? value)
    {
        OnPropertyChanged(nameof(CanConnect));
        OnPropertyChanged(nameof(CanAct));
    }
    partial void OnServerChanged(string? value) => OnPropertyChanged(nameof(ServerName));
    partial void OnBytesInChanged(ulong value) => OnPropertyChanged(nameof(TrafficText));
    partial void OnBytesOutChanged(ulong value) => OnPropertyChanged(nameof(TrafficText));

    // MARK: disclaimer

    /// <summary>True when the caller may proceed; otherwise the action is parked and the disclaimer shown.</summary>
    private bool RequireAgreement(Action resume)
    {
        if (HasAgreed) return true;
        _parked = resume;
        ShowDisclaimer = true;
        return false;
    }

    public void Agree()
    {
        HasAgreed = true;
        ShowDisclaimer = false;
        _settings.HasAgreedToDisclaimer = true;
        _settings.Save();
        var parked = _parked;
        _parked = null;
        parked?.Invoke();
    }

    public void Disagree()
    {
        _parked = null;
        QuitRequested?.Invoke();
    }

    // MARK: session

    public async Task StartAsync()
    {
        await PollAsync();
        await LoadListAsync();
    }

    /// <summary>Called every 2 s: asks the daemon for a snapshot, or notices it is gone.</summary>
    public async Task PollAsync()
    {
        bool up = await _ipc.SendAsync(HelperRequest.Of("status"));
        ServiceRunning = up;
        if (!up && State != ConnectionState.Disconnected && _reconnect is null) State = ConnectionState.Disconnected;
    }

    private void OnPipeDropped()
    {
        ServiceRunning = false;
        if (_reconnect is null) State = ConnectionState.Disconnected;
        ConnectedAt = null;
    }

    public void ApplyEvent(HelperEvent e)
    {
        _lastEventAt = _clock();
        ServiceRunning = true;
        if (e.IpcVersion is { } v && v < Ipc.IpcVersion)
            Notice = "The installed VPN service is too old for this app. Reinstall VPN Gate.";
        if (e.Log is { Length: > 0 } l) AppendLog(l);
        if (e.Error is { Length: > 0 } err)
        {
            AppendLog($"Error: {err}");
            Notice = err;
        }
        // While a reconnect is pending the daemon's own "disconnected" must not wipe the "Reconnecting…" state.
        if (!(_reconnect is not null && e.State == ConnectionState.Disconnected))
        {
            State = e.State;
            Server = e.Server;
            VirtualIp = e.VirtualIP;
        }
        BytesIn = e.BytesIn;
        BytesOut = e.BytesOut;
        if (e.State == ConnectionState.Connected)
        {
            ConnectedAt ??= _clock();
            Notice = null;
            _reconnectAttempts = 0;
        }
        else if (e.State == ConnectionState.Disconnected)
        {
            ConnectedAt = null;
            ConsiderReconnect(e);
        }
        OnPropertyChanged(nameof(TrafficText));
    }

    public void RefreshTraffic() => OnPropertyChanged(nameof(TrafficText));

    private void AppendLog(string line)
    {
        _log.Add(line);
        if (_log.Count > MaxLogLines) _log.RemoveRange(0, _log.Count - MaxLogLines);
        LogLines = _log.ToArray();
    }

    public string LogText => string.Join("\n", _log);

    // MARK: reconnect (list connections retry forever, every 15 s)

    private int _reconnectAttempts;
    public int ReconnectAttempts => _reconnectAttempts;

    private void ConsiderReconnect(HelperEvent e)
    {
        if (_wanted is not { } server || _reconnect is not null) return;
        _reconnectAttempts++;
        AppendLog($"Reconnecting to {server.HostName} in {(int)Math.Ceiling(_reconnectDelay.TotalSeconds)} s (attempt {_reconnectAttempts})");
        State = ConnectionState.Reconnecting;
        Server = server.Ip;
        var cts = _reconnect = new CancellationTokenSource();
        _ = ReconnectAfterDelay(server, cts);
    }

    private async Task ReconnectAfterDelay(VpnServer server, CancellationTokenSource cts)
    {
        try
        {
            await Task.Delay(_reconnectDelay, cts.Token);
        }
        catch (OperationCanceledException)
        {
            return;
        }
        _post(() =>
        {
            if (!ReferenceEquals(_reconnect, cts)) return;
            _reconnect = null;
            cts.Dispose();
            if (_wanted?.Id != server.Id || State != ConnectionState.Reconnecting)
            {
                if (State == ConnectionState.Reconnecting) State = ConnectionState.Disconnected;
                return;
            }
            _ = SendConnectAsync(server);
        });
    }

    private void CancelReconnect()
    {
        var cts = _reconnect;
        _reconnect = null;
        cts?.Cancel();
        cts?.Dispose();
    }

    // MARK: commands

    public void Connect(VpnServer? server = null)
    {
        server ??= Selected;
        if (server is null) return;
        if (!RequireAgreement(() => Connect(server))) return;
        Notice = null;
        CancelReconnect();
        _wanted = _lastServer = server;
        _reconnectAttempts = 0;
        _ = SendConnectAsync(server);
    }

    private async Task SendConnectAsync(VpnServer s)
    {
        var r = HelperRequest.Of("connect");
        r.Host = s.Ip;
        r.Port = s.ConnectPort;
        if (s.SslPorts.Count > 0) r.Ports = s.PrioritizedSslPorts.Select(p => (int)p).ToList();
        // Retrying is done here (ConsiderReconnect), so the daemon makes a single attempt.
        r.Proxy = new ProxySettings();
        r.AutoReconnect = false;
        r.BlockIPv6 = true;
        r.TunnelMode = TunnelMode.FullTunnel;
        r.SocksPort = Ipc.DefaultSocksPort;
        var sentAt = _clock();
        // Optimistic: the daemon's events may arrive before SendAsync returns, and must not be overwritten afterwards.
        State = ConnectionState.Connecting;
        Server = s.Ip;
        if (!await _ipc.SendAsync(r))
        {
            ServiceRunning = false;
            _wanted = null;
            State = ConnectionState.Disconnected;
            Notice = "The VPN Gate service is not running. Reinstall VPN Gate or start the “VPN Gate” service.";
            AppendLog("Cannot reach the VPN Gate service");
            return;
        }
        // A daemon that accepts the pipe but never answers must not leave the UI on "Connecting…" forever.
        try { await Task.Delay(_answerTimeout); } catch (OperationCanceledException) { return; }
        if (_lastEventAt < sentAt && State == ConnectionState.Connecting && _wanted?.Id == s.Id)
        {
            State = ConnectionState.Disconnected;
            _wanted = null;
            Notice = "The VPN Gate service is not responding. Restart the “VPN Gate” service.";
            AppendLog($"No answer from the service within {(int)_answerTimeout.TotalSeconds} s");
        }
    }

    public void Disconnect()
    {
        _wanted = null;
        CancelReconnect();
        if (State == ConnectionState.Reconnecting) State = ConnectionState.Disconnected;
        _ = _ipc.SendAsync(HelperRequest.Of("disconnect"));
    }

    /// <summary>The bottom-bar button: connect when disconnected, otherwise disconnect / cancel.</summary>
    public void PrimaryAction()
    {
        if (State == ConnectionState.Disconnected) Connect();
        else Disconnect();
    }

    public void Reconnect()
    {
        if (_lastServer is { } s) Connect(s);
    }

    private VpnServer? _lastServer;

    // MARK: list

    public async Task LoadListAsync()
    {
        try
        {
            ApplyList(await _ipc.ListServersAsync());
            return;
        }
        catch (HelperRequestException e) when (e.Kind == HelperRequestFailure.Failed)
        {
            // no cache and no bundle: fall through to a download
        }
        catch (HelperRequestException e)
        {
            ListError = e.Message;
            UpdateListStatus();
            return;
        }
        await RefreshAsync();
    }

    public async Task RefreshAsync()
    {
        if (Interlocked.Exchange(ref _loading, 1) == 1) return;
        IsLoading = true;
        ListError = null;
        UpdateListStatus();
        try
        {
            ApplyList(await _ipc.RefreshServersAsync(new ProxySettings(), null));
        }
        catch (HelperRequestException e)
        {
            ListError = e.Message;
        }
        finally
        {
            IsLoading = false;
            Interlocked.Exchange(ref _loading, 0);
            UpdateListStatus();
        }
    }

    private void ApplyList(ServerListResult r)
    {
        _all = r.Servers;
        ListSource = r.Source;
        ListTimestamp = r.Timestamp;
        ListError = null;
        Countries = _all.Select(s => s.CountryLong).Where(c => c.Length > 0).Distinct().Order(StringComparer.CurrentCultureIgnoreCase).ToList();
        if (Selected is { } sel) Selected = _all.FirstOrDefault(s => s.Id == sel.Id);
        Rebuild();
        OnPropertyChanged(nameof(ServerName));
    }

    /// <summary>Re-applies filter and sort after the caller changed <see cref="Filter"/>.</summary>
    public void Rebuild()
    {
        Func<VpnServer, object> key = SortKey switch
        {
            SortKey.Host => s => s.HostName.ToLowerInvariant(),
            SortKey.Country => s => s.CountryLong.ToLowerInvariant(),
            SortKey.Uptime => s => s.UptimeMs,
            SortKey.Sessions => s => s.Sessions,
            SortKey.Speed => s => s.Speed,
            SortKey.Ping => s => s.Ping == 0 ? int.MaxValue : s.Ping,
            SortKey.Logging => s => FilterWeeks(s),
            _ => s => s.Score,
        };
        var rows = Filter.Apply(_all);
        Servers = (SortDescending ? rows.OrderByDescending(key) : rows.OrderBy(key)).ToList();
        UpdateListStatus();
        OnPropertyChanged(nameof(FilterActive));
    }

    private static int FilterWeeks(VpnServer s) => ServerFilter.LogWeeks(s.LogType) ?? int.MaxValue;

    public bool FilterActive => Filter.IsActive;

    public void Sort(SortKey key)
    {
        if (SortKey == key) SortDescending = !SortDescending;
        else
        {
            SortKey = key;
            SortDescending = key is SortKey.Score or SortKey.Uptime or SortKey.Sessions or SortKey.Speed;
        }
        Rebuild();
    }

    public void ClearFilters()
    {
        Filter.Search = "";
        Filter.Country = ServerFilter.AllCountries;
        Filter.FavoritesOnly = false;
        Filter.MaxLogWeeks = null;
        Rebuild();
    }

    public bool IsFavorite(VpnServer s) => Filter.Favorites.Contains(s.Id);

    public void ToggleFavorite(VpnServer s)
    {
        if (!Filter.Favorites.Remove(s.Id)) Filter.Favorites.Add(s.Id);
        _settings.Save();
        Rebuild();
    }

    private void UpdateListStatus()
    {
        if (ListError is { } err) ListStatus = $"List update failed ({err}). Try again.";
        else if (IsLoading) ListStatus = _all.Count == 0 ? "Refreshing the List… (about 1 MB, can take 10–20 s)" : "Refreshing the List…";
        else if (_all.Count == 0) ListStatus = "No servers yet. Press Refresh List.";
        else
        {
            var s = $"{_all.Count} Public VPN Relay Servers on the Earth!";
            if (ListTimestamp is { } t)
            {
                s += $" (Updated at {t.LocalDateTime:g})";
                if (!ListFormat.IsListOk(t, _clock())) s += " — The list is old — press Refresh List.";
            }
            if (Servers.Count != _all.Count) s += $" — showing {Servers.Count}";
            ListStatus = s;
        }
    }

    public bool ListIsStale => ListTimestamp is { } t && !ListFormat.IsListOk(t, _clock());

    partial void OnIsLoadingChanged(bool value)
    {
        OnPropertyChanged(nameof(IsNotLoading));
        UpdateListStatus();
    }
}
