using System.Text.Json;
using System.Text.Json.Serialization;

namespace VPNGate.Core;

/// <summary>The per-user settings (UI-SPEC 8). The proxy password is not here: it lives in the secret store.</summary>
public interface ISettingsStore
{
    bool HasAgreedToDisclaimer { get; set; }
    /// <summary>Hostnames of the favourite servers.</summary>
    HashSet<string> Favorites { get; }
    ProxyKind ProxyKind { get; set; }
    string ProxyHost { get; set; }
    int ProxyPort { get; set; }
    string ProxyUsername { get; set; }
    bool BlockIPv6 { get; set; }
    TunnelMode TunnelMode { get; set; }
    int SocksPort { get; set; }
    /// <summary>"Reconnect automatically" (General).</summary>
    bool AutoReconnect { get; set; }
    string MirrorUrl { get; set; }
    /// <summary>The global routing rules; accounts with their own rules ignore them.</summary>
    RoutingConfig Routing { get; set; }
    void Save();
}

public class MemorySettings : ISettingsStore
{
    public bool HasAgreedToDisclaimer { get; set; }
    public HashSet<string> Favorites { get; set; } = new();
    public ProxyKind ProxyKind { get; set; } = ProxyKind.None;
    public string ProxyHost { get; set; } = "";
    public int ProxyPort { get; set; }
    public string ProxyUsername { get; set; } = "";
    public bool BlockIPv6 { get; set; } = true;
    public TunnelMode TunnelMode { get; set; } = TunnelMode.FullTunnel;
    public int SocksPort { get; set; } = Ipc.DefaultSocksPort;
    public bool AutoReconnect { get; set; } = true;
    public string MirrorUrl { get; set; } = "";
    public RoutingConfig Routing { get; set; } = new();
    public virtual void Save() { }
}

/// <summary>A JSON file, by default %LocalAppData%\VPNGate\settings.json. A missing or damaged file means defaults.</summary>
public sealed class JsonFileSettings : MemorySettings
{
    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
    };

    private readonly string _path;

    public JsonFileSettings(string path)
    {
        _path = path;
        try
        {
            if (JsonSerializer.Deserialize<MemorySettings>(File.ReadAllText(path), Options) is { } s)
            {
                HasAgreedToDisclaimer = s.HasAgreedToDisclaimer;
                Favorites = s.Favorites ?? new();
                ProxyKind = s.ProxyKind;
                ProxyHost = s.ProxyHost ?? "";
                ProxyPort = s.ProxyPort;
                ProxyUsername = s.ProxyUsername ?? "";
                BlockIPv6 = s.BlockIPv6;
                TunnelMode = s.TunnelMode;
                SocksPort = s.SocksPort;
                AutoReconnect = s.AutoReconnect;
                MirrorUrl = s.MirrorUrl ?? "";
                Routing = s.Routing ?? new();
            }
        }
        catch (Exception e) when (e is IOException or JsonException or InvalidOperationException or UnauthorizedAccessException or NotSupportedException)
        {
        }
    }

    public static string DefaultPath =>
        Path.Combine(DataDir.Path, "settings.json");

    public override void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var plain = new MemorySettings
            {
                HasAgreedToDisclaimer = HasAgreedToDisclaimer,
                Favorites = Favorites.Order(StringComparer.Ordinal).ToHashSet(),
                ProxyKind = ProxyKind, ProxyHost = ProxyHost, ProxyPort = ProxyPort, ProxyUsername = ProxyUsername,
                BlockIPv6 = BlockIPv6, TunnelMode = TunnelMode, SocksPort = SocksPort, AutoReconnect = AutoReconnect,
                MirrorUrl = MirrorUrl, Routing = Routing,
            };
            File.WriteAllText(_path, JsonSerializer.Serialize(plain, Options));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}
