using System.Text.Json;

namespace VPNGate.Core;

public sealed class ConnectionLogEntry
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string ServerName { get; set; } = "";
    public string ServerIp { get; set; } = "";
    public DateTimeOffset ConnectedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? DisconnectedAt { get; set; }
    public double? DurationSeconds { get; set; }
    public ulong BytesIn { get; set; }
    public ulong BytesOut { get; set; }
    public string? Error { get; set; }
}

/// <summary>Connection history (UI-SPEC 9): newest first, at most 100 entries, one per connected period.</summary>
public sealed class ConnectionHistoryStore
{
    public const int MaxEntries = 100;
    private static readonly JsonSerializerOptions Json = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    private readonly string _path;
    private readonly Func<DateTimeOffset> _clock;

    public ConnectionHistoryStore(string path, Func<DateTimeOffset>? clock = null)
    {
        _path = path;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
        try { Entries = JsonSerializer.Deserialize<List<ConnectionLogEntry>>(File.ReadAllText(path), Json) ?? new(); }
        catch (Exception e) when (e is IOException or JsonException or UnauthorizedAccessException) { Entries = new(); }
    }

    public static string DefaultPath =>
        Path.Combine(DataDir.Path, "connection_history.json");

    public List<ConnectionLogEntry> Entries { get; private set; }
    public event Action? Changed;

    public Guid RecordStart(string serverName, string serverIp)
    {
        var e = new ConnectionLogEntry { ServerName = serverName, ServerIp = serverIp, ConnectedAt = _clock() };
        Entries.Insert(0, e);
        if (Entries.Count > MaxEntries) Entries.RemoveRange(MaxEntries, Entries.Count - MaxEntries);
        Save();
        return e.Id;
    }

    public void RecordEnd(Guid id, ulong bytesIn, ulong bytesOut, string? error)
    {
        var e = Entries.FirstOrDefault(x => x.Id == id);
        if (e is null) return;
        var now = _clock();
        e.DisconnectedAt = now;
        e.DurationSeconds = (now - e.ConnectedAt).TotalSeconds;
        e.BytesIn = bytesIn;
        e.BytesOut = bytesOut;
        e.Error = error;
        Save();
    }

    public void Clear()
    {
        Entries.Clear();
        Save();
    }

    private void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, JsonSerializer.Serialize(Entries, Json));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
        Changed?.Invoke();
    }
}
