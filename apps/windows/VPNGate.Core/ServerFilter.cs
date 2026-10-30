using System.Globalization;

namespace VPNGate.Core;

/// <summary>Search, country, favourites and logging-policy filter of the server list (ServerFilter.swift).</summary>
public sealed class ServerFilter
{
    public const string AllCountries = "All";

    public string Search { get; set; } = "";
    public string Country { get; set; } = AllCountries;
    public bool FavoritesOnly { get; set; }
    public HashSet<string> Favorites { get; set; } = new();
    /// <summary>Hide servers that keep logs longer than this many weeks (null = show all).</summary>
    public int? MaxLogWeeks { get; set; }

    public bool IsActive => Search.Length > 0 || Country != AllCountries || FavoritesOnly || MaxLogWeeks is not null;

    public IEnumerable<VpnServer> Apply(IEnumerable<VpnServer> servers) => servers.Where(Matches);

    private bool Matches(VpnServer s)
    {
        if (Country != AllCountries && s.CountryLong != Country) return false;
        if (FavoritesOnly && !Favorites.Contains(s.Id)) return false;
        if (MaxLogWeeks is { } max)
        {
            // unknown retention is treated as "too long"
            if (LogWeeks(s.LogType) is not { } w || w > max) return false;
        }
        if (Search.Length > 0)
        {
            var cmp = CultureInfo.CurrentCulture.CompareInfo;
            bool Hit(string f) => cmp.IndexOf(f, Search, CompareOptions.IgnoreCase) >= 0;
            if (!(Hit(s.HostName) || Hit(s.Ip) || Hit(s.CountryLong) || Hit(s.OperatorName))) return false;
        }
        return true;
    }

    /// <summary>"2weeks" → 2, "3months" → 13, "1year" → 52, "no" / "none" / "0" → 0, unparseable → null.</summary>
    public static int? LogWeeks(string s)
    {
        var t = s.ToLowerInvariant().Trim();
        if (t is "no" or "none" or "nolog" or "0") return 0;
        int d = 0;
        while (d < t.Length && char.IsDigit(t[d])) d++;
        if (d == 0 || !int.TryParse(t.AsSpan(0, d), NumberStyles.None, CultureInfo.InvariantCulture, out var n)) return null;
        return t[d..].Trim() switch
        {
            "day" or "days" => (n + 6) / 7,
            "week" or "weeks" => n,
            "month" or "months" => n * 52 / 12 + (n * 52 % 12 == 0 ? 0 : 1),
            "year" or "years" => n * 52,
            _ => null,
        };
    }
}
