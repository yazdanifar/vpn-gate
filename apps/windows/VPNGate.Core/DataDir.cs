namespace VPNGate.Core;

/// <summary>Where the app keeps settings, accounts and history: %LocalAppData%\VPNGate, or VPNGATE_DATA_DIR (CI UI tests).</summary>
public static class DataDir
{
    public static string Path =>
        Environment.GetEnvironmentVariable("VPNGATE_DATA_DIR") is { Length: > 0 } d
            ? d
            : System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "VPNGate");
}
