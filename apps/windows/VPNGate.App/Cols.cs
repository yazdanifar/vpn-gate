using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Media;
using VPNGate.Core;
using Windows.UI;

namespace VPNGate.App;

/// <summary>Static helpers for x:Bind function bindings (the list columns, visibility, card colours).</summary>
public static class Cols
{
    public static Visibility Vis(bool v) => v ? Visibility.Visible : Visibility.Collapsed;
    public static Visibility VisNotNull(string? s) => string.IsNullOrEmpty(s) ? Visibility.Collapsed : Visibility.Visible;

    public static string Region(string flag, string country) => flag.Length == 0 ? country : $"{flag} {country}";
    public static string Uptime(long ms) => ListFormat.Uptime(ms);
    public static string Sessions(int n) => ListFormat.Sessions(n);
    public static string Speed(long bps) => Fmt.Speed(bps);
    public static string Pings(int google, int japan) => ListFormat.Pings(google, japan);
    public static string Logging(string logType) => ListFormat.Logging(logType);

    public static string Glyph(ConnectionState s) => Fmt.Glyph(s);

    public static string CardTitle(ConnectionState s) => s == ConnectionState.Disconnected ? "Not connected" : Fmt.Title(s);

    public static string Hint(string? notice) => string.IsNullOrEmpty(notice) ? "Select a server and press Connect." : notice;

    public static string VirtualIp(string? ip) => string.IsNullOrEmpty(ip) ? "" : $"Virtual IP {ip}";

    public static Brush CardBrush(ConnectionState s) => new SolidColorBrush(s switch
    {
        ConnectionState.Connected => Color.FromArgb(0x33, 0x2E, 0xA0, 0x43),
        ConnectionState.Disconnected => Color.FromArgb(0x22, 0x80, 0x80, 0x80),
        _ => Color.FromArgb(0x33, 0xF0, 0x8C, 0x00),
    });

    public static Brush NoticeBrush(bool stale) =>
        new SolidColorBrush(stale ? Colors.DarkOrange : Colors.Gray);

    public static Brush ErrorBrush() => new SolidColorBrush(Colors.IndianRed);
}
