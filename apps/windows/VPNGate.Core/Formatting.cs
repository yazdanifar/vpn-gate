using System.Globalization;

namespace VPNGate.Core;

/// <summary>Text of the UI, following UI-SPEC.md section 0 and Sources/VPNGateMac/UI/Formatting.swift.</summary>
public static class Fmt
{
    public static string Speed(long bitsPerSecond) =>
        string.Create(CultureInfo.InvariantCulture, $"{bitsPerSecond / 1_000_000.0:F1} Mbps");

    /// <summary>Binary units like ByteCountFormatter: "0 bytes", "12 bytes", "1.5 KB", "3.2 MB".</summary>
    public static string Bytes(ulong n)
    {
        if (n < 1024) return n == 1 ? "1 byte" : $"{n} bytes";
        string[] units = { "KB", "MB", "GB", "TB", "PB" };
        double v = n;
        int i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < units.Length - 1);
        var s = v < 10 ? v.ToString("0.0", CultureInfo.InvariantCulture) : v.ToString("0", CultureInfo.InvariantCulture);
        return $"{s} {units[i]}";
    }

    public static string Rate(double bytesPerSecond) => Bytes((ulong)Math.Max(0, bytesPerSecond)) + "/s";

    public static string Duration(TimeSpan t)
    {
        long s = (long)Math.Max(0, t.TotalSeconds);
        return string.Create(CultureInfo.InvariantCulture, $"{s / 3600}:{s % 3600 / 60:00}:{s % 60:00}");
    }

    public static string Title(ConnectionState s) => s switch
    {
        ConnectionState.Disconnected => "Disconnected",
        ConnectionState.Connecting => "Connecting…",
        ConnectionState.Authenticating => "Authenticating…",
        ConnectionState.Dhcp => "Getting address…",
        ConnectionState.Connected => "Connected",
        ConnectionState.Reconnecting => "Reconnecting…",
        _ => s.ToString(),
    };

    /// <summary>Segoe Fluent Icons glyph: locked shield, open lock, or spinning arrows.</summary>
    public static string Glyph(ConnectionState s) => s switch
    {
        ConnectionState.Connected => "",
        ConnectionState.Disconnected => "",
        _ => "",
    };

    /// <summary>"↓ in  ↑ out"; with a start time it is prefixed by the duration.</summary>
    public static string Traffic(ulong bytesIn, ulong bytesOut, TimeSpan? since = null)
    {
        var t = $"↓ {Bytes(bytesIn)}  ↑ {Bytes(bytesOut)}";
        return since is { } d ? $"{Duration(d)}  {t}" : t;
    }
}

/// <summary>Text of the list table, following the Windows client (client_exe.c) like ServerModel.swift's ListFormat.</summary>
public static class ListFormat
{
    private static string Unit(long n, string word) => $"{n} {word}{(n == 1 ? "" : "s")}";

    public static string Uptime(long ms)
    {
        ms = Math.Max(0, ms);
        if (ms < 3_600_001) return Unit(ms / 60_000, "min");
        if (ms < 86_400_001) return Unit(ms / 3_600_000, "hour");
        return Unit(ms / 86_400_000, "day");
    }

    public static string Sessions(long n) => Unit(n, "session");

    public static string Logging(string logType)
    {
        var t = logType.ToLowerInvariant();
        if (t.StartsWith("no", StringComparison.Ordinal)) return "No Logs";
        if (t.Contains('2') && t.Contains("week", StringComparison.Ordinal)) return "2 Weeks";
        if (t.StartsWith("perm", StringComparison.Ordinal)) return "Permanent";
        return logType.Length == 0 ? "-" : logType;
    }

    public static string Pings(int google, int japan)
    {
        static string One(int v) => v == 0 ? "-" : $"{v} ms";
        return $"{One(google)}, {One(japan)}";
    }

    /// <summary>The list is OK within 24 h of its timestamp, older it is "stale".</summary>
    public static bool IsListOk(DateTimeOffset timestamp, DateTimeOffset now) =>
        Math.Abs((now - timestamp).TotalMilliseconds) < 86_400_001;
}
