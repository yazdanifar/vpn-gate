// Mirrors of the daemon's JSON (crates/vpngate-core/src/ipc.rs, docs/cross-platform/IPC.md). The shapes are pinned by the
// golden vectors in Tests/Fixtures/golden/ipc.json (see VPNGate.Tests/GoldenIpcTests.cs).
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace VPNGate.Core;

public static class Ipc
{
    public const int HelperVersion = 8;
    public const int IpcVersion = 9;
    public const int DefaultSocksPort = 1080;
    /// <summary>The daemon's named pipe is \\.\pipe\VPNGate (backend::WINDOWS_PIPE_NAME).</summary>
    public const string PipeName = "VPNGate";

    public static readonly JsonSerializerOptions Json = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = false,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) },
        NumberHandling = JsonNumberHandling.Strict,
    };
}

public enum ConnectionState { Disconnected, Connecting, Authenticating, Dhcp, Connected, Reconnecting }

public enum ProxyKind { None, Http, Socks5 }

public enum TunnelMode { FullTunnel, SocksProxy }

public enum RoutingAction { Proxy, Direct, Block }

public enum RoutingRuleType { DomainSuffix, DomainFull, DomainKeyword, DomainRegex, Ip, Cidr }

public enum SyncOutcome { Synced, RelaysFailed, NoRelays }

public sealed class ProxySettings
{
    public ProxyKind Kind { get; set; } = ProxyKind.None;
    public string Host { get; set; } = "";
    public int Port { get; set; }
    public string? Username { get; set; }
    public string? Password { get; set; }
}

public sealed class RoutingRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public RoutingRuleType Type { get; set; }
    public string Value { get; set; } = "";
    public RoutingAction Action { get; set; }
    public bool Enabled { get; set; } = true;
}

public sealed class RoutingConfig
{
    public List<RoutingRule> Rules { get; set; } = new();
    public RoutingAction DefaultAction { get; set; } = RoutingAction.Proxy;
    public bool BypassPrivateNetworks { get; set; }

    /// <summary>True when the config changes nothing: everything through the tunnel, no rules.</summary>
    [JsonIgnore]
    public bool IsEmpty => Rules.Count == 0 && DefaultAction == RoutingAction.Proxy && !BypassPrivateNetworks;
}

/// <summary>Full configuration for a SoftEther session (accounts, U19). Optional fields stay null to keep the daemon's defaults.</summary>
public sealed class ConnectConfig
{
    public string Host { get; set; } = "";
    public List<int> Ports { get; set; } = new() { 443, 992, 5555, 1194 };
    public string HubName { get; set; } = "VPNGATE";
    public string UserName { get; set; } = "vpn";
    public string AuthType { get; set; } = "anonymous";
    public string? Password { get; set; }
    public byte[]? CertDer { get; set; }
    public byte[]? PrivateKeyDer { get; set; }
    public byte[]? Ticket { get; set; }
    public ProxySettings Proxy { get; set; } = new();
    public int MaxConnection { get; set; } = 1;
    public bool UseCompress { get; set; }
    public bool UseUdpAccel { get; set; } = true;
    public bool DisableQoS { get; set; }
    public bool HalfConnection { get; set; }
    public bool AutoReconnect { get; set; } = true;
    public double? ReconnectInterval { get; set; }
    public int? ReconnectCount { get; set; }
    public bool BlockIPv6 { get; set; } = true;
    public bool CheckServerCert { get; set; }
    public string? ServerCertFingerprint { get; set; }
    public int? Mtu { get; set; }
    public string? VirtualMacAddress { get; set; }
    public RoutingConfig? Routing { get; set; }
    public TunnelMode TunnelMode { get; set; } = TunnelMode.FullTunnel;
    public int SocksPort { get; set; } = Ipc.DefaultSocksPort;
}

public sealed class ProbeTarget
{
    public string Host { get; set; } = "";
    public List<int>? Ports { get; set; }
}

public sealed class HelperRequest
{
    public string Cmd { get; set; } = "";
    public string? Host { get; set; }
    public int? Port { get; set; }
    public List<int>? Ports { get; set; }
    public ProxySettings? Proxy { get; set; }
    public bool? AutoReconnect { get; set; }
    public bool? BlockIPv6 { get; set; }
    public RoutingConfig? Routing { get; set; }
    public TunnelMode? TunnelMode { get; set; }
    public int? SocksPort { get; set; }
    public ConnectConfig? Config { get; set; }
    // IPC v9
    public int? Id { get; set; }
    public string? Mirror { get; set; }
    public List<ProbeTarget>? Targets { get; set; }
    public double? Timeout { get; set; }

    public static HelperRequest Of(string cmd) => new() { Cmd = cmd };
}

public sealed class HelperEvent
{
    public ConnectionState State { get; set; }
    public string? Server { get; set; }
    public string? VirtualIP { get; set; }
    public ulong BytesIn { get; set; }
    public ulong BytesOut { get; set; }
    public string? Log { get; set; }
    public string? Error { get; set; }
    public int? HelperVersion { get; set; }
    public int? IpcVersion { get; set; }
}

public sealed class HelperReply
{
    public string Reply { get; set; } = "";
    public int? Id { get; set; }
    public bool Ok { get; set; }
    public string? Error { get; set; }
    public JsonNode? Result { get; set; }

    public T Decode<T>()
    {
        if (Result is null) throw new HelperRequestException(HelperRequestFailure.Failed, "The helper sent no result");
        return Result.Deserialize<T>(Ipc.Json) ?? throw new HelperRequestException(HelperRequestFailure.Failed, "The helper sent no result");
    }
}

public enum HelperRequestFailure { Failed, Timeout, Disconnected, Unsupported }

public sealed class HelperRequestException : Exception
{
    public HelperRequestFailure Kind { get; }

    public HelperRequestException(HelperRequestFailure kind, string? message = null)
        : base(message ?? kind switch
        {
            HelperRequestFailure.Timeout => "The helper did not answer in time",
            HelperRequestFailure.Disconnected => "The helper is not running",
            HelperRequestFailure.Unsupported => "The installed service is too old for this app. Reinstall VPN Gate.",
            _ => "The helper refused the request",
        })
    {
        Kind = kind;
    }
}

public sealed class VpnServer
{
    public string HostName { get; set; } = "";
    public string Ip { get; set; } = "";
    public int Score { get; set; }
    public int Ping { get; set; }
    public long Speed { get; set; }
    public string CountryLong { get; set; } = "";
    public string CountryShort { get; set; } = "";
    public int Sessions { get; set; }
    public long UptimeMs { get; set; }
    public long TotalUsers { get; set; }
    public long TotalTraffic { get; set; }
    public string LogType { get; set; } = "";
    public string OperatorName { get; set; } = "";
    public string Message { get; set; } = "";
    public int ListedPort { get; set; }
    public string ListedProto { get; set; } = "";
    public string Fqdn { get; set; } = "";
    public List<ushort> SslPorts { get; set; } = new();
    public ushort? UdpPort { get; set; }
    public List<ushort> OpenVpnUdpPorts { get; set; } = new();
    public bool L2tp { get; set; }
    public string? Os { get; set; }
    public string? Soft { get; set; }
    public int? Build { get; set; }
    public string? Owner { get; set; }
    public string? Abuse { get; set; }
    public long? NumLogin { get; set; }
    public bool NoLog { get; set; }
    public bool LogPermanent { get; set; }
    public string? Name { get; set; }
    public int PingToGoogle { get; set; }
    public ulong SendSize { get; set; }
    public ulong RecvSize { get; set; }
    public bool IsKernelModeNat { get; set; }

    /// <summary>The DDNS host name is the only unique key: one IP can appear several times on different ports.</summary>
    [JsonIgnore]
    public string Id => HostName;

    private static readonly ushort[] PreferredPorts = { 443, 992, 995, 465, 585, 993, 22 };

    /// <summary>The Windows client's port order: 443, 992, 995, 465, 585, 993, 22 (those offered), then the rest.</summary>
    public static List<ushort> PortPriority(IEnumerable<ushort> ports)
    {
        var all = ports.ToList();
        var outList = PreferredPorts.Where(all.Contains).ToList();
        outList.AddRange(all.Where(p => !outList.Contains(p)));
        return outList;
    }

    [JsonIgnore]
    public List<ushort> PrioritizedSslPorts => PortPriority(SslPorts);

    /// <summary>Port to try first: the first SSL port in priority order, then the listed port.</summary>
    [JsonIgnore]
    public int? ConnectPort
    {
        get
        {
            var first = PrioritizedSslPorts.FirstOrDefault();
            if (first != 0) return first;
            return ListedPort is > 0 and <= 65535 ? ListedPort : null;
        }
    }

    [JsonIgnore]
    public string Flag
    {
        get
        {
            var s = CountryShort.ToUpperInvariant();
            if (s.Length != 2 || s.Any(c => c is < 'A' or > 'Z')) return "";
            return string.Concat(s.Select(c => char.ConvertFromUtf32(0x1F1E6 + (c - 'A'))));
        }
    }
}

public sealed class ServerListResult
{
    public List<VpnServer> Servers { get; set; } = new();
    /// <summary>"HTTP API", "Relay P2P", "Cached", "Built-in" or "CSV Mirror".</summary>
    public string Source { get; set; } = "";
    public ulong? TimestampMs { get; set; }
    public bool IsFresh { get; set; }
    public SyncOutcome Outcome { get; set; }
    public double? NextPollSeconds { get; set; }

    [JsonIgnore]
    public DateTimeOffset? Timestamp => TimestampMs is { } ms ? DateTimeOffset.FromUnixTimeMilliseconds((long)ms) : null;
}
