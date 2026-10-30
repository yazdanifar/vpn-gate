using Microsoft.UI.Xaml;

namespace VPNGate.App;

public partial class App : Application
{
    private Window? _window;

    public App() => InitializeComponent();

    protected override void OnLaunched(LaunchActivatedEventArgs args)
    {
        // The in-process UI tests (VPNGate.UiTests) host this class and create the windows themselves.
        if (Environment.GetEnvironmentVariable("VPNGATE_UITEST") == "1") return;
        _window = new MainWindow();
        _window.Activate();
    }
}
