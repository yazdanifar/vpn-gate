using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>The routing rules editor shared by Settings and the account editor (UI-SPEC 7).</summary>
internal sealed class RoutingEditor : UserControl
{
    private readonly RoutingConfig _config;
    private readonly Action _changed;
    private readonly Func<XamlRoot?> _root;
    private readonly ComboBox _default = new() { MinWidth = 260 };
    private readonly ToggleSwitch _bypass = new() { Header = "Bypass private networks (LAN, link-local, CGNAT)" };
    private readonly TextBlock _caption = Ui.Caption("");
    private readonly StackPanel _rules = new() { Spacing = 4 };
    private bool _loading;

    public RoutingEditor(RoutingConfig config, Action changed, Func<XamlRoot?> root)
    {
        _config = config;
        _changed = changed;
        _root = root;
        _default.Items.Add("Proxy (through the tunnel)");
        _default.Items.Add("Direct (bypass the tunnel)");
        _default.SelectionChanged += (_, _) =>
        {
            if (_loading) return;
            _config.DefaultAction = _default.SelectedIndex == 1 ? RoutingAction.Direct : RoutingAction.Proxy;
            Refresh();
            _changed();
        };
        _bypass.Toggled += (_, _) =>
        {
            if (_loading) return;
            _config.BypassPrivateNetworks = _bypass.IsOn;
            _changed();
        };
        var add = new Button { Content = "Add Rule…" };
        add.Click += async (_, _) => await EditAsync(null);
        var panel = new StackPanel { Spacing = 8 };
        panel.Children.Add(Ui.Header("Unmatched traffic"));
        var row = new StackPanel { Orientation = Orientation.Horizontal, Spacing = 8 };
        row.Children.Add(new TextBlock { Text = "By default", VerticalAlignment = VerticalAlignment.Center });
        row.Children.Add(_default);
        panel.Children.Add(row);
        panel.Children.Add(_bypass);
        panel.Children.Add(_caption);
        panel.Children.Add(Ui.Header("Rules"));
        panel.Children.Add(_rules);
        panel.Children.Add(add);
        panel.Children.Add(Ui.Caption(
            "Rules are checked in order from top to bottom; the first one that matches wins. Domain rules need the DNS proxy, which only runs " +
            "while one is configured. A domain marked “Direct” is looked up through your regular network connection, never through the VPN " +
            "or its DNS — everything else is resolved only through the tunnel."));
        Content = panel;
        Refresh();
    }

    private void Refresh()
    {
        _loading = true;
        _default.SelectedIndex = _config.DefaultAction == RoutingAction.Direct ? 1 : 0;
        _bypass.IsOn = _config.BypassPrivateNetworks;
        _loading = false;
        _caption.Text = _config.DefaultAction == RoutingAction.Direct
            ? "Everything bypasses the tunnel except what the rules below send into it. IPv6 keeps being captured and dropped regardless (see “Block IPv6” in General)."
            : "Everything goes through the tunnel except what the rules below send elsewhere.";
        _rules.Children.Clear();
        if (_config.Rules.Count == 0)
        {
            _rules.Children.Add(Ui.Text("No custom rules. Traffic follows the default action above.", opacity: 0.7));
            return;
        }
        for (var i = 0; i < _config.Rules.Count; i++) _rules.Children.Add(Row(i));
    }

    private UIElement Row(int index)
    {
        var rule = _config.Rules[index];
        var grid = new Grid { ColumnSpacing = 8, Padding = new Thickness(8, 4, 8, 4) };
        grid.ColumnDefinitions.Add(new ColumnDefinition { Width = new GridLength(1, GridUnitType.Star) });
        for (var i = 0; i < 5; i++) grid.ColumnDefinitions.Add(new ColumnDefinition { Width = GridLength.Auto });

        var label = RoutingRuleValidation.Types.First(t => t.Type == rule.Type).Label;
        var text = new StackPanel();
        text.Children.Add(new TextBlock { Text = rule.Value, FontFamily = new FontFamily("Consolas"), TextTrimming = TextTrimming.CharacterEllipsis });
        text.Children.Add(Ui.Caption(label));
        grid.Children.Add(text);

        var pill = new Border
        {
            Background = Ui.PillBrush(rule.Action),
            CornerRadius = new CornerRadius(10),
            Padding = new Thickness(8, 2, 8, 2),
            VerticalAlignment = VerticalAlignment.Center,
            Child = new TextBlock { Text = rule.Action.ToString(), Foreground = new SolidColorBrush(Microsoft.UI.Colors.White), FontSize = 12 },
        };
        Grid.SetColumn(pill, 1);
        grid.Children.Add(pill);
        if (!rule.Enabled)
        {
            var off = Ui.Caption("Off");
            off.VerticalAlignment = VerticalAlignment.Center;
            Grid.SetColumn(off, 2);
            grid.Children.Add(off);
        }

        var up = Small("\uE70E", "Move up", index > 0, () => Move(index, -1));
        var down = Small("\uE70D", "Move down", index < _config.Rules.Count - 1, () => Move(index, 1));
        var del = Small("\uE74D", "Delete", true, () => { _config.Rules.RemoveAt(index); Refresh(); _changed(); });
        Grid.SetColumn(up, 3);
        Grid.SetColumn(down, 4);
        Grid.SetColumn(del, 5);
        grid.Children.Add(up);
        grid.Children.Add(down);
        grid.Children.Add(del);
        grid.Tapped += async (_, e) =>
        {
            if (e.OriginalSource is FrameworkElement { } fe && IsInsideButton(fe)) return;
            await EditAsync(rule);
        };
        return new Border
        {
            CornerRadius = new CornerRadius(4),
            Background = (Brush)Application.Current.Resources["CardBackgroundFillColorDefaultBrush"],
            Child = grid,
        };
    }

    private static bool IsInsideButton(DependencyObject o)
    {
        for (var p = o; p is not null; p = VisualTreeHelper.GetParent(p)) if (p is Button) return true;
        return false;
    }

    private static Button Small(string glyph, string tip, bool enabled, Action click)
    {
        var b = new Button
        {
            Content = new FontIcon { Glyph = glyph, FontFamily = new FontFamily("Segoe Fluent Icons, Segoe MDL2 Assets"), FontSize = 12 },
            IsEnabled = enabled,
            Padding = new Thickness(6),
        };
        ToolTipService.SetToolTip(b, tip);
        b.Click += (_, _) => click();
        return b;
    }

    private void Move(int index, int delta)
    {
        var rule = _config.Rules[index];
        _config.Rules.RemoveAt(index);
        _config.Rules.Insert(index + delta, rule);
        Refresh();
        _changed();
    }

    /// <summary>The rule sheet (UI-SPEC 7): add when <paramref name="existing"/> is null, otherwise edit or delete it.</summary>
    private async Task EditAsync(RoutingRule? existing)
    {
        var type = new ComboBox { MinWidth = 220 };
        foreach (var t in RoutingRuleValidation.Types) type.Items.Add(t.Label);
        type.SelectedIndex = Array.FindIndex(RoutingRuleValidation.Types, t => t.Type == (existing?.Type ?? RoutingRuleType.DomainSuffix));
        var value = new TextBox { Text = existing?.Value ?? "", MinWidth = 320 };
        var error = Ui.Error(null);
        var action = new ComboBox { MinWidth = 220 };
        foreach (var a in new[] { "Proxy", "Direct", "Block" }) action.Items.Add(a);
        action.SelectedIndex = (int)(existing?.Action ?? RoutingAction.Proxy);
        var enabled = new ToggleSwitch { Header = "Enabled", IsOn = existing?.Enabled ?? true };

        var dialog = new ContentDialog
        {
            XamlRoot = _root(),
            Title = existing is null ? "Add Rule" : "Edit Rule",
            PrimaryButtonText = existing is null ? "Add" : "Save",
            CloseButtonText = "Cancel",
            DefaultButton = ContentDialogButton.Primary,
        };
        if (existing is not null) dialog.SecondaryButtonText = "Delete";

        void Validate()
        {
            var t = RoutingRuleValidation.Types[Math.Max(0, type.SelectedIndex)];
            value.PlaceholderText = t.Placeholder;
            var msg = RoutingRuleValidation.Error(t.Type, value.Text);
            // Shown only for a non-empty value; the button stays disabled either way.
            Ui.SetError(error, value.Text.Trim().Length == 0 ? null : msg);
            dialog.IsPrimaryButtonEnabled = msg is null;
        }
        type.SelectionChanged += (_, _) => Validate();
        value.TextChanged += (_, _) => Validate();

        var body = new StackPanel { Spacing = 8 };
        body.Children.Add(new TextBlock { Text = "Match" });
        body.Children.Add(type);
        body.Children.Add(value);
        body.Children.Add(error);
        body.Children.Add(new TextBlock { Text = "Action" });
        body.Children.Add(action);
        body.Children.Add(enabled);
        dialog.Content = body;
        Validate();

        var result = await dialog.ShowAsync();
        if (result == ContentDialogResult.Secondary && existing is not null)
        {
            _config.Rules.Remove(existing);
        }
        else if (result == ContentDialogResult.Primary)
        {
            var r = existing ?? new RoutingRule();
            r.Type = RoutingRuleValidation.Types[type.SelectedIndex].Type;
            r.Value = value.Text.Trim();
            r.Action = (RoutingAction)action.SelectedIndex;
            r.Enabled = enabled.IsOn;
            if (existing is null) _config.Rules.Add(r);
        }
        else return;
        Refresh();
        _changed();
    }
}
