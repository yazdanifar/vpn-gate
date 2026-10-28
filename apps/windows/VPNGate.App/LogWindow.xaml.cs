using Microsoft.UI.Xaml;
using VPNGate.Core;
using Windows.ApplicationModel.DataTransfer;
using Windows.Graphics;

namespace VPNGate.App;

/// <summary>"Connection Log": the last 300 lines, auto-scrolling, with a Copy button (UI-SPEC 10).</summary>
public sealed partial class LogWindow : Window
{
    private readonly MainViewModel _vm;

    public LogWindow(MainViewModel vm)
    {
        _vm = vm;
        InitializeComponent();
        AppWindow.Resize(new SizeInt32(900, 560));
        Refresh();
        _vm.PropertyChanged += OnChanged;
        Closed += (_, _) => _vm.PropertyChanged -= OnChanged;
    }

    private void OnChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.LogLines)) Refresh();
    }

    private void Refresh()
    {
        LogBox.Text = _vm.LogText;
        CopyButton.IsEnabled = LogBox.Text.Length > 0;
        LogBox.Select(LogBox.Text.Length, 0);
    }

    private void OnCopy(object sender, RoutedEventArgs e)
    {
        var data = new DataPackage();
        data.SetText(_vm.LogText);
        Clipboard.SetContent(data);
    }
}
