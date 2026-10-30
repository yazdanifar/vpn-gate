using System.Text.Json;
using System.Text.Json.Serialization;

namespace VPNGate.Core;

/// <summary>Where passwords, certificates and keys live (Credential Manager in the app, memory in tests). Never a file.</summary>
public interface ISecretStore
{
    string? Get(string key);
    void Set(string key, string value);
    void Delete(string key);
}

public sealed class MemorySecretStore : ISecretStore
{
    public Dictionary<string, string> Items { get; } = new();
    public string? Get(string key) => Items.GetValueOrDefault(key);
    public void Set(string key, string value) => Items[key] = value;
    public void Delete(string key) => Items.Remove(key);
}

public static class SecretStoreExtensions
{
    public static byte[]? GetBytes(this ISecretStore s, string key) =>
        s.Get(key) is { } v ? Convert.FromBase64String(v) : null;

    public static void SetBytes(this ISecretStore s, string key, byte[] value) => s.Set(key, Convert.ToBase64String(value));
}

/// <summary>The four authentication types of a connection setting; the raw strings are the accounts-file and daemon values.</summary>
public static class AuthTypes
{
    public const string Anonymous = "Anonymous";
    public const string Password = "Standard Password (SHA-0)";
    public const string PlainPassword = "Plain Password";
    public const string Certificate = "User Certificate";

    public static readonly string[] All = { Anonymous, Password, PlainPassword, Certificate };

    public static bool UsesPassword(string t) => t is Password or PlainPassword;
}

/// <summary>A SoftEther connection setting (ClientAccount.swift). Secrets never live here: see <see cref="AccountStore"/>.</summary>
public sealed class ClientAccount
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Name { get; set; } = "";
    public string Host { get; set; } = "";
    public List<int> PortList { get; set; } = new() { 443, 992, 5555, 1194 };
    public string Hub { get; set; } = "DEFAULT";
    public string Username { get; set; } = "";
    public string AuthType { get; set; } = AuthTypes.Password;
    public ProxySettings Proxy { get; set; } = new();
    public bool CheckServerCert { get; set; }
    public string? ServerCertFingerprint { get; set; }
    public int MaxConnection { get; set; } = 1;
    public bool HalfConnection { get; set; }
    public bool Compression { get; set; }
    public bool UdpAcceleration { get; set; } = true;
    public bool DisableQoS { get; set; }
    public bool AutoReconnect { get; set; } = true;
    public double ReconnectInterval { get; set; } = 3;
    public int ReconnectCount { get; set; } = 8;
    public string? VirtualMacAddress { get; set; }
    public int? Mtu { get; set; }
    /// <summary>Per-account routing; null means "use the app's global rules".</summary>
    public RoutingConfig? Routing { get; set; }
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;

    /// <summary>The account as the daemon wants it. <c>GlobalRouting</c> applies only when the account has no rules of its own.</summary>
    public ConnectConfig ToConnectConfig(string? password, byte[]? certDer, byte[]? keyDer, bool blockIPv6,
        RoutingConfig? globalRouting, TunnelMode tunnelMode, int socksPort) => new()
    {
        Host = Host,
        Ports = PortList.ToList(),
        HubName = Hub,
        UserName = Username,
        AuthType = AuthType,
        Password = password,
        CertDer = certDer,
        PrivateKeyDer = keyDer,
        Proxy = Proxy,
        MaxConnection = MaxConnection,
        UseCompress = Compression,
        UseUdpAccel = UdpAcceleration,
        DisableQoS = DisableQoS,
        HalfConnection = HalfConnection,
        AutoReconnect = AutoReconnect,
        ReconnectInterval = ReconnectInterval,
        ReconnectCount = ReconnectCount,
        BlockIPv6 = blockIPv6,
        CheckServerCert = CheckServerCert,
        ServerCertFingerprint = ServerCertFingerprint,
        Mtu = Mtu,
        VirtualMacAddress = VirtualMacAddress,
        Routing = Routing ?? globalRouting,
        TunnelMode = tunnelMode,
        SocksPort = socksPort,
    };

    public ClientAccount Clone()
    {
        var json = JsonSerializer.Serialize(this, AccountStore.Json);
        return JsonSerializer.Deserialize<ClientAccount>(json, AccountStore.Json)!;
    }
}

/// <summary>accounts.json plus the secrets in an <see cref="ISecretStore"/> (AccountManager.swift).</summary>
public sealed class AccountStore
{
    internal static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly string _path;
    private readonly ISecretStore _secrets;

    public AccountStore(string path, ISecretStore secrets)
    {
        _path = path;
        _secrets = secrets;
        Load();
    }

    public static string DefaultPath =>
        Path.Combine(DataDir.Path, "accounts.json");

    public List<ClientAccount> Accounts { get; private set; } = new();
    /// <summary>Set when the file could not be read completely (the original is kept next to it).</summary>
    public string? LoadNotice { get; private set; }

    public event Action? Changed;

    public void Load()
    {
        LoadNotice = null;
        Accounts = new();
        string text;
        try { text = File.ReadAllText(_path); }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException) { return; }
        List<JsonElement> records;
        try { records = JsonSerializer.Deserialize<List<JsonElement>>(text, Json) ?? new(); }
        catch (JsonException)
        {
            var kept = SetAside(move: true);
            LoadNotice = "The saved connection settings could not be read" + (kept is null ? "." : $" (kept as {kept}).");
            return;
        }
        foreach (var r in records)
        {
            try
            {
                var a = r.Deserialize<ClientAccount>(Json);
                if (a is null || a.Name is null || a.Host is null) continue;
                if (a.PortList.Count == 0) a.PortList = new() { 443 };
                Accounts.Add(a);
            }
            catch (JsonException)
            {
            }
        }
        if (Accounts.Count < records.Count)
        {
            var kept = SetAside(move: false);
            LoadNotice = $"{records.Count - Accounts.Count} saved connection setting(s) could not be read and were skipped"
                + (kept is null ? "." : $" (original kept as {kept}).");
        }
    }

    private string? SetAside(bool move)
    {
        try
        {
            var stamp = DateTime.UtcNow.ToString("yyyy-MM-ddTHH-mm-ssZ");
            var dest = _path + ".corrupt-" + stamp;
            File.Delete(dest);
            if (move) File.Move(_path, dest); else File.Copy(_path, dest);
            return Path.GetFileName(dest);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            // The proxy password is a secret: it goes to the secret store, never into this file.
            var safe = Accounts.Select(a =>
            {
                var c = a.Clone();
                c.Proxy.Password = null;
                return c;
            }).ToList();
            var tmp = _path + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(safe, Json));
            File.Move(tmp, _path, overwrite: true);
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
        Changed?.Invoke();
    }

    private static string Key(ClientAccount a, string suffix) => $"account-{a.Id}-{suffix}";

    public string? Password(ClientAccount a) => _secrets.Get(Key(a, "pw"));
    public byte[]? Certificate(ClientAccount a) => _secrets.GetBytes(Key(a, "cert"));
    /// <summary>PKCS#1 RSA private key (DER).</summary>
    public byte[]? PrivateKey(ClientAccount a) => _secrets.GetBytes(Key(a, "key"));
    public string? ProxyPassword(ClientAccount a) => _secrets.Get(Key(a, "proxypw"));
    public bool HasCertificateIdentity(ClientAccount a) => Certificate(a) is not null && PrivateKey(a) is not null;

    /// <summary>Stores what was given (null keeps the stored value) and strips the proxy password from the account.</summary>
    private void SaveSecrets(ClientAccount a, string? password, byte[]? cert, byte[]? key)
    {
        if (!string.IsNullOrEmpty(password)) _secrets.Set(Key(a, "pw"), password);
        if (cert is { Length: > 0 }) _secrets.SetBytes(Key(a, "cert"), cert);
        if (key is { Length: > 0 }) _secrets.SetBytes(Key(a, "key"), key);
        if (!string.IsNullOrEmpty(a.Proxy.Password)) _secrets.Set(Key(a, "proxypw"), a.Proxy.Password);
        a.Proxy.Password = null;
        if (a.AuthType != AuthTypes.Certificate) // no stale key material for password accounts
        {
            _secrets.Delete(Key(a, "cert"));
            _secrets.Delete(Key(a, "key"));
        }
        if (!AuthTypes.UsesPassword(a.AuthType)) _secrets.Delete(Key(a, "pw"));
    }

    public void Add(ClientAccount account, string? password = null, byte[]? cert = null, byte[]? key = null)
    {
        SaveSecrets(account, password, cert, key);
        Accounts.Add(account);
        Save();
    }

    public void Update(ClientAccount account, string? password = null, byte[]? cert = null, byte[]? key = null)
    {
        var i = Accounts.FindIndex(a => a.Id == account.Id);
        if (i < 0) return;
        account.UpdatedAt = DateTimeOffset.UtcNow;
        SaveSecrets(account, password, cert, key);
        Accounts[i] = account;
        Save();
    }

    public void Duplicate(ClientAccount account)
    {
        var copy = account.Clone();
        copy.Id = Guid.NewGuid();
        copy.Name = $"{account.Name} (Copy)";
        copy.CreatedAt = copy.UpdatedAt = DateTimeOffset.UtcNow;
        copy.Proxy.Password = ProxyPassword(account);
        SaveSecrets(copy, Password(account), Certificate(account), PrivateKey(account));
        Accounts.Add(copy);
        Save();
    }

    public void Delete(ClientAccount account)
    {
        Accounts.RemoveAll(a => a.Id == account.Id);
        foreach (var s in new[] { "pw", "cert", "key", "proxypw" }) _secrets.Delete(Key(account, s));
        Save();
    }
}

/// <summary>Form state of the connection-setting editor (AccountEditorState.swift); free of UI types so it can be tested.</summary>
public sealed class AccountEditorState
{
    public string Name { get; set; } = "New Connection";
    public string Host { get; set; } = "";
    public string PortString { get; set; } = "443, 992, 5555, 1194";
    public string Hub { get; set; } = "DEFAULT";
    public string Username { get; set; } = "";
    public string AuthType { get; set; } = AuthTypes.Password;
    public string Password { get; set; } = "";
    public int MaxConnection { get; set; } = 1;
    public bool Compression { get; set; }
    public bool UdpAcceleration { get; set; } = true;
    public bool UseQoS { get; set; } = true;
    public bool HalfConnection { get; set; }
    public bool AutoReconnect { get; set; } = true;
    public int ReconnectIntervalSeconds { get; set; } = 3;
    public int ReconnectCount { get; set; } = 8;
    public bool CheckServerCert { get; set; }
    public string Fingerprint { get; set; } = "";
    /// <summary>Blank = automatic (the DHCP lease decides).</summary>
    public string MtuString { get; set; } = "";
    /// <summary>Blank = random.</summary>
    public string MacString { get; set; } = "";
    public bool UseCustomRouting { get; set; }
    public RoutingConfig Routing { get; set; } = new();
    /// <summary>Freshly imported certificate material (null = keep what is stored).</summary>
    public byte[]? CertDer { get; set; }
    public byte[]? PrivateKeyDer { get; set; }
    public bool HasStoredIdentity { get; set; }
    public string? ImportError { get; set; }

    public AccountEditorState() { }

    public AccountEditorState(ClientAccount account, string? password = null, bool hasStoredIdentity = false)
    {
        Name = account.Name;
        Host = account.Host;
        PortString = string.Join(", ", account.PortList);
        Hub = account.Hub;
        Username = account.Username;
        AuthType = account.AuthType;
        Password = password ?? "";
        MaxConnection = account.MaxConnection;
        Compression = account.Compression;
        UdpAcceleration = account.UdpAcceleration;
        UseQoS = !account.DisableQoS;
        HalfConnection = account.HalfConnection;
        AutoReconnect = account.AutoReconnect;
        ReconnectIntervalSeconds = (int)Math.Round(account.ReconnectInterval);
        ReconnectCount = account.ReconnectCount;
        CheckServerCert = account.CheckServerCert;
        Fingerprint = account.ServerCertFingerprint ?? "";
        MtuString = account.Mtu?.ToString() ?? "";
        MacString = account.VirtualMacAddress ?? "";
        UseCustomRouting = account.Routing is not null;
        // A copy: the routing editor edits it live, and cancelling must leave the account alone.
        Routing = account.Routing is null ? new RoutingConfig()
            : JsonSerializer.Deserialize<RoutingConfig>(JsonSerializer.Serialize(account.Routing, Ipc.Json), Ipc.Json)!;
        HasStoredIdentity = hasStoredIdentity;
    }

    public List<int> ParsedPorts => PortString.Split(',')
        .Select(p => int.TryParse(p.Trim(), out var n) && n is > 0 and <= 65535 ? n : 0)
        .Where(n => n > 0).ToList();

    private string TrimmedFingerprint => Fingerprint.Trim();
    private string TrimmedMtu => MtuString.Trim();
    private string TrimmedMac => MacString.Trim();

    public string? FingerprintError =>
        TrimmedFingerprint.Length == 0 || InputValidation.NormalizedFingerprint(TrimmedFingerprint) is not null
            ? null : "Fingerprint must be 40 (SHA-1) or 64 (SHA-256) hex digits.";

    public bool CertificateReady => AuthType != AuthTypes.Certificate || (CertDer is not null && PrivateKeyDer is not null) || HasStoredIdentity;

    public string? MtuError =>
        TrimmedMtu.Length == 0 || (int.TryParse(TrimmedMtu, out var m) && m is >= 576 and <= 1500)
            ? null : "MTU must be 576–1500, or blank for automatic.";

    public string? MacError =>
        TrimmedMac.Length == 0 || InputValidation.ParseMacAddress(TrimmedMac) is not null
            ? null : "MAC must be 6 hex byte pairs, e.g. 00:AC:DE:12:34:56.";

    public bool AdvancedInvalid => FingerprintError is not null || MtuError is not null || MacError is not null;

    public bool CanSave =>
        Name.Trim().Length > 0 && Host.Trim().Length > 0 && InputValidation.IsValidHost(Host.Trim())
        && FingerprintError is null && CertificateReady && MtuError is null && MacError is null
        && InputValidation.IsValidIdentityField(Hub) && InputValidation.IsValidIdentityField(Username);

    /// <summary>Starts from <paramref name="baseAccount"/> (when editing) so fields the form does not show survive.</summary>
    public ClientAccount MakeAccount(ClientAccount? baseAccount)
    {
        var a = baseAccount ?? new ClientAccount();
        var ports = ParsedPorts;
        a.Name = Name.Trim();
        a.Host = Host.Trim();
        a.PortList = ports.Count == 0 ? new() { 443 } : ports;
        var h = Hub.Trim();
        a.Hub = h.Length == 0 ? "DEFAULT" : h;
        a.Username = Username.Trim();
        a.AuthType = AuthType;
        a.CheckServerCert = CheckServerCert;
        a.ServerCertFingerprint = InputValidation.NormalizedFingerprint(TrimmedFingerprint);
        a.MaxConnection = Math.Clamp(MaxConnection, 1, 32);
        a.Compression = Compression;
        a.UdpAcceleration = UdpAcceleration;
        a.DisableQoS = !UseQoS;
        a.HalfConnection = HalfConnection;
        a.AutoReconnect = AutoReconnect;
        a.ReconnectInterval = Math.Max(1, ReconnectIntervalSeconds);
        a.ReconnectCount = Math.Max(1, ReconnectCount);
        a.Mtu = TrimmedMtu.Length == 0 ? null : int.Parse(TrimmedMtu);
        a.VirtualMacAddress = TrimmedMac.Length == 0 ? null : TrimmedMac;
        a.Routing = UseCustomRouting ? Routing : null;
        return a;
    }
}

/// <summary>
/// Splits long values over several entries of <paramref name="inner"/>, for stores with a small value limit (Credential Manager
/// holds at most 2560 bytes per credential, less than a certificate in base64). The first entry holds the chunk count.
/// </summary>
public sealed class ChunkedSecretStore : ISecretStore
{
    private const string CountPrefix = "chunks:";
    private readonly ISecretStore _inner;
    private readonly int _chunk;

    public ChunkedSecretStore(ISecretStore inner, int maxChars = 1000)
    {
        _inner = inner;
        _chunk = maxChars;
    }

    public string? Get(string key)
    {
        if (_inner.Get(key) is not { } head) return null;
        if (!head.StartsWith(CountPrefix) || !int.TryParse(head[CountPrefix.Length..], out var n)) return head;
        var sb = new System.Text.StringBuilder();
        for (var i = 0; i < n; i++)
        {
            if (_inner.Get(ChunkKey(key, i)) is not { } part) return null;
            sb.Append(part);
        }
        return sb.ToString();
    }

    public void Set(string key, string value)
    {
        Delete(key);
        var n = (value.Length + _chunk - 1) / _chunk;
        for (var i = 0; i < n; i++) _inner.Set(ChunkKey(key, i), value.Substring(i * _chunk, Math.Min(_chunk, value.Length - i * _chunk)));
        _inner.Set(key, CountPrefix + n);
    }

    public void Delete(string key)
    {
        if (_inner.Get(key) is { } head && head.StartsWith(CountPrefix) && int.TryParse(head[CountPrefix.Length..], out var n))
            for (var i = 0; i < n; i++) _inner.Delete(ChunkKey(key, i));
        _inner.Delete(key);
    }

    private static string ChunkKey(string key, int i) => $"{key}#{i}";
}
