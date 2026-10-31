using Microsoft.UI;
using Microsoft.UI.Text;
using Microsoft.UI.Windowing;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Windows.Graphics;
using Windows.Storage.Pickers;
using WinRT.Interop;

namespace VPNGate.App;

/// <summary>Small helpers for the windows that are built in code (accounts, settings, history, editors).</summary>
internal static class Ui
{
    public static TextBlock Text(string text, bool wrap = true, double opacity = 1) =>
        new() { Text = text, TextWrapping = wrap ? TextWrapping.Wrap : TextWrapping.NoWrap, Opacity = opacity };

    public static TextBlock Caption(string text) => new() { Text = text, TextWrapping = TextWrapping.Wrap, Opacity = 0.7, FontSize = 12 };

    public static TextBlock Header(string text) =>
        new() { Text = text, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 12, 0, 0) };

    public static TextBlock Error(string? text) => new()
    {
        Text = text ?? "",
        TextWrapping = TextWrapping.Wrap,
        FontSize = 12,
        Foreground = new SolidColorBrush(Colors.IndianRed),
        Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible,
    };

    public static void SetError(TextBlock t, string? text)
    {
        t.Text = text ?? "";
        t.Visibility = string.IsNullOrEmpty(text) ? Visibility.Collapsed : Visibility.Visible;
    }

    /// <summary>Sizes the window in physical pixels, never larger than the work area of its display (the 1100 px main
    /// window used to run off a 1024×768 screen).</summary>
    public static void Size(Window w, int width, int height)
    {
        var work = DisplayArea.GetFromWindowId(w.AppWindow.Id, DisplayAreaFallback.Primary).WorkArea;
        w.AppWindow.Resize(new SizeInt32(Math.Min(width, work.Width), Math.Min(height, work.Height)));
        var icon = Path.Combine(AppContext.BaseDirectory, "Assets", "AppIcon.ico");
        if (File.Exists(icon)) w.AppWindow.SetIcon(icon);
    }

    /// <summary>Shows a file picker on <paramref name="window"/> and returns the file's bytes, or null if cancelled.</summary>
    public static async Task<byte[]?> PickFileAsync(Window window, string title, params string[] extensions)
    {
        var picker = new FileOpenPicker { SuggestedStartLocation = PickerLocationId.DocumentsLibrary };
        InitializeWithWindow.Initialize(picker, WindowNative.GetWindowHandle(window));
        foreach (var e in extensions.Length == 0 ? new[] { "*" } : extensions) picker.FileTypeFilter.Add(e);
        var file = await picker.PickSingleFileAsync();
        if (file is null) return null;
        return await File.ReadAllBytesAsync(file.Path);
    }

    public static Brush PillBrush(VPNGate.Core.RoutingAction a) => new SolidColorBrush(a switch
    {
        VPNGate.Core.RoutingAction.Proxy => Windows.UI.Color.FromArgb(0xFF, 0x25, 0x63, 0xEB),
        VPNGate.Core.RoutingAction.Direct => Windows.UI.Color.FromArgb(0xFF, 0x2E, 0xA0, 0x43),
        _ => Windows.UI.Color.FromArgb(0xFF, 0xD1, 0x3A, 0x3A),
    });
}
