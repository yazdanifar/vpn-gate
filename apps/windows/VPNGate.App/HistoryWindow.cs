using Microsoft.UI;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>"Connection History" (UI-SPEC 9).</summary>
internal sealed class HistoryWindow : Window
{
    private readonly ConnectionHistoryStore _history;
    private readonly StackPanel _rows = new() { Spacing = 1 };
    private readonly TextBlock _empty = Ui.Text("No connections yet.", opacity: 0.7);
    private readonly Button _clear = new() { Content = "Clear" };

    public HistoryWindow(ConnectionHistoryStore history)
    {
        _history = history;
        Title = "Connection History";
        Ui.Size(this, 820, 420);
        var root = new Grid { Padding = new Thickness(12), RowSpacing = 8 };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        var top = new Grid();
        top.Children.Add(new TextBlock { Text = "Connection history", Style = (Style)Application.Current.Resources["SubtitleTextBlockStyle"] });
        _clear.HorizontalAlignment = HorizontalAlignment.Right;
        _clear.Click += (_, _) => _history.Clear();
        top.Children.Add(_clear);
        root.Children.Add(top);
        var head = Row("Server", "Address", "Connected", "Duration", "Traffic", "Result", true);
        Grid.SetRow(head, 1);
        root.Children.Add(head);
        var body = new StackPanel();
        body.Children.Add(_empty);
        body.Children.Add(_rows);
        var scroll = new ScrollViewer { Content = body };
        Grid.SetRow(scroll, 2);
        root.Children.Add(scroll);
        Content = root;
        _history.Changed += OnChanged;
        Closed += (_, _) => _history.Changed -= OnChanged;
        Refresh();
    }

    private void OnChanged() => DispatcherQueue.TryEnqueue(Refresh);

    private void Refresh()
    {
        _rows.Children.Clear();
        _empty.Visibility = _history.Entries.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        _clear.IsEnabled = _history.Entries.Count > 0;
        foreach (var e in _history.Entries)
        {
            var duration = e.DurationSeconds is { } d ? Fmt.Duration(TimeSpan.FromSeconds(d)) : "active";
            var result = e.DisconnectedAt is null ? "" : e.Error ?? "ended";
            var row = Row(e.ServerName, e.ServerIp, e.ConnectedAt.LocalDateTime.ToString("MMM d, HH:mm"), duration,
                $"↓ {Fmt.Bytes(e.BytesIn)}  ↑ {Fmt.Bytes(e.BytesOut)}", result, false);
            if (e.Error is not null && row.Children.Count == 6 && row.Children[5] is TextBlock t) t.Foreground = new SolidColorBrush(Colors.IndianRed);
            _rows.Children.Add(row);
        }
    }

    private static Grid Row(string a, string b, string c, string d, string e, string f, bool header)
    {
        var g = new Grid { ColumnSpacing = 8, Padding = new Thickness(8, 4, 8, 4) };
        foreach (var w in new[] { 2.0, 1.4, 1.4, 1.0, 2.0, 1.4 }) g.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(w, GridUnitType.Star) });
        var cells = new[] { a, b, c, d, e, f };
        for (var i = 0; i < cells.Length; i++)
        {
            var tb = new TextBlock
            {
                Text = cells[i],
                TextTrimming = TextTrimming.CharacterEllipsis,
                FontWeight = header ? Microsoft.UI.Text.FontWeights.SemiBold : Microsoft.UI.Text.FontWeights.Normal,
            };
            Grid.SetColumn(tb, i);
            g.Children.Add(tb);
        }
        return g;
    }
}
