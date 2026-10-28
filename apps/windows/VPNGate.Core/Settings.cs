using System.Text.Json;
using System.Text.Json.Nodes;

namespace VPNGate.Core;

/// <summary>The few per-user settings U18 needs; U19 adds the rest (proxy, routing, mirror, ...).</summary>
public interface ISettingsStore
{
    bool HasAgreedToDisclaimer { get; set; }
    /// <summary>Hostnames of the favourite servers.</summary>
    HashSet<string> Favorites { get; }
    void Save();
}

public sealed class MemorySettings : ISettingsStore
{
    public bool HasAgreedToDisclaimer { get; set; }
    public HashSet<string> Favorites { get; } = new();
    public void Save() { }
}

/// <summary>A JSON file, by default %LocalAppData%\VPNGate\settings.json. A missing or damaged file means defaults.</summary>
public sealed class JsonFileSettings : ISettingsStore
{
    private readonly string _path;

    public JsonFileSettings(string path)
    {
        _path = path;
        try
        {
            if (JsonNode.Parse(File.ReadAllText(path)) is JsonObject o)
            {
                HasAgreedToDisclaimer = o["hasAgreedToDisclaimer"]?.GetValue<bool>() ?? false;
                if (o["favorites"] is JsonArray a)
                    foreach (var f in a) if (f?.GetValue<string>() is { } s) Favorites.Add(s);
            }
        }
        catch (Exception e) when (e is IOException or JsonException or InvalidOperationException or UnauthorizedAccessException)
        {
        }
    }

    public static string DefaultPath =>
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPNGate", "settings.json");

    public bool HasAgreedToDisclaimer { get; set; }
    public HashSet<string> Favorites { get; } = new();

    public void Save()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            var o = new JsonObject
            {
                ["hasAgreedToDisclaimer"] = HasAgreedToDisclaimer,
                ["favorites"] = new JsonArray(Favorites.Order(StringComparer.Ordinal).Select(f => (JsonNode?)f).ToArray()),
            };
            File.WriteAllText(_path, o.ToJsonString(new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (Exception e) when (e is IOException or UnauthorizedAccessException)
        {
        }
    }
}
