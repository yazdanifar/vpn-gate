using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>The "Server Details" sheet (UI-SPEC 4).</summary>
internal static class ServerDetails
{
    public static async Task ShowAsync(XamlRoot root, VpnServer s)
    {
        var rows = new List<(string, string)>
        {
            ("DDNS Hostname:", s.Fqdn.Length > 0 ? s.Fqdn : s.HostName),
            ("IP Address:", s.Ip),
            ("Country:", $"{s.CountryLong} ({s.CountryShort})"),
            ("Line Speed:", Fmt.Speed(s.Speed)),
            ("Score:", s.Score.ToString()),
            ("Ping to Japan:", s.Ping.ToString() + " ms"),
            ("Ping to Google:", s.PingToGoogle == 0 ? "-" : s.PingToGoogle + " ms"),
            ("UDP port:", s.UdpPort is { } u && u != 0 ? u.ToString() : "-"),
            ("SSL-VPN Ports:", s.SslPorts.Count == 0 ? "Default (443)" : string.Join(", ", s.PrioritizedSslPorts)),
            ("OpenVPN UDP Ports:", s.OpenVpnUdpPorts.Count == 0 ? "None" : string.Join(", ", s.OpenVpnUdpPorts)),
            ("L2TP / IPsec:", s.L2tp ? "Supported" : "Not supported"),
            ("Logging Policy:", ListFormat.Logging(s.LogType)),
            ("Operator / Owner:", (s.Owner ?? s.OperatorName) is { Length: > 0 } o ? o : "Anonymous"),
        };
        if (!string.IsNullOrEmpty(s.Abuse)) rows.Add(("Abuse Contact:", s.Abuse));
        if (!string.IsNullOrEmpty(s.Os)) rows.Add(("Operating System:", s.Os));
        if (!string.IsNullOrEmpty(s.Soft)) rows.Add(("SoftEther Build:", s.Build is { } b ? $"{s.Soft} (build {b})" : s.Soft));

        var grid = new Grid { RowSpacing = 4, ColumnSpacing = 12, MinWidth = 440 };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < rows.Count; i++)
        {
            grid.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
            var k = new TextBlock { Text = rows[i].Item1, Opacity = 0.7 };
            var v = new TextBlock { Text = rows[i].Item2, IsTextSelectionEnabled = true, TextWrapping = TextWrapping.Wrap };
            Grid.SetRow(k, i);
            Grid.SetRow(v, i);
            Grid.SetColumn(v, 1);
            grid.Children.Add(k);
            grid.Children.Add(v);
        }
        var body = new StackPanel { Spacing = 12 };
        body.Children.Add(grid);
        if (!string.IsNullOrWhiteSpace(s.Message))
        {
            body.Children.Add(new TextBlock { Text = "Server Message:", Opacity = 0.7 });
            body.Children.Add(new TextBox { Text = s.Message, IsReadOnly = true, AcceptsReturn = true, TextWrapping = TextWrapping.Wrap, MaxHeight = 140 });
        }
        await new ContentDialog
        {
            XamlRoot = root,
            Title = s.HostName, // no flag: Windows shows flag emoji as two letters
            Content = new ScrollViewer { Content = body, MaxHeight = 480 },
            CloseButtonText = "Done",
        }.ShowAsync();
    }
}
