using Microsoft.Win32;

namespace VPNGate.App;

/// <summary>"Launch at login": a value under HKCU\...\Run. The app is unpackaged, so there is no MSIX startup task to use.</summary>
internal static class StartupRegistration
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";
    private const string ValueName = "VPNGate";

    public static bool IsEnabled
    {
        get
        {
            try
            {
                using var k = Registry.CurrentUser.OpenSubKey(RunKey);
                return k?.GetValue(ValueName) is string;
            }
            catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
            {
                return false;
            }
        }
    }

    /// <summary>Returns false when Windows refuses (group policy, locked registry).</summary>
    public static bool Set(bool enabled)
    {
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
            if (enabled) k.SetValue(ValueName, $"\"{Environment.ProcessPath}\"");
            else k.DeleteValue(ValueName, throwOnMissingValue: false);
            return true;
        }
        catch (Exception e) when (e is System.Security.SecurityException or UnauthorizedAccessException or IOException)
        {
            return false;
        }
    }
}
