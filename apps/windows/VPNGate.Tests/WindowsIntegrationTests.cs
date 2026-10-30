using System.Diagnostics;
using Microsoft.Win32;
using VPNGate.App;
using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

// Compiled on Windows only (see the csproj): they use the real Credential Manager and the HKCU Run key, with their own keys.

public class CredentialManagerTests
{
    private static string Key() => "test-" + Guid.NewGuid().ToString("N");

    private static string CmdkeyList() =>
        RunProcess("cmdkey", "/list");

    internal static string RunProcess(string file, string args)
    {
        var psi = new ProcessStartInfo(file, args) { RedirectStandardOutput = true, UseShellExecute = false };
        using var p = Process.Start(psi)!;
        var text = p.StandardOutput.ReadToEnd();
        p.WaitForExit();
        return text;
    }

    [Fact]
    public void Small_secret_round_trips_and_deletes()
    {
        var store = CredentialStore.Create();
        var key = Key();
        try
        {
            Assert.Null(store.Get(key));
            store.Set(key, "hunter2 ünï©ode ✓");
            Assert.Equal("hunter2 ünï©ode ✓", store.Get(key));
            store.Set(key, "second");
            Assert.Equal("second", store.Get(key));
            store.Delete(key);
            Assert.Null(store.Get(key));
        }
        finally { store.Delete(key); }
    }

    [Fact]
    public void Empty_secret_is_kept_as_empty_not_missing()
    {
        var store = CredentialStore.Create();
        var key = Key();
        try
        {
            store.Set(key, "");
            Assert.Equal("", store.Get(key));
        }
        finally { store.Delete(key); }
    }

    [Fact]
    public void Secret_beyond_one_credential_is_chunked_and_fully_removed()
    {
        var store = CredentialStore.Create();
        var key = Key();
        // A 4096-bit RSA key in PEM is about 3.2 kB (6.4 kB as UTF-16): over the 2560-byte limit of one credential.
        var big = string.Concat(Enumerable.Range(0, 400).Select(i => $"MIIEvQIBADANBgkqhkiG9w0BAQEFAASC{i:D4}\n"));
        Assert.True(big.Length * 2 > 2560);
        try
        {
            store.Set(key, big);
            Assert.Equal(big, store.Get(key));
            Assert.Contains(key, CmdkeyList());
            // Shrinking must not leave the old chunks behind.
            store.Set(key, "short");
            Assert.Equal("short", store.Get(key));
            store.Delete(key);
            Assert.Null(store.Get(key));
            Assert.DoesNotContain(key, CmdkeyList());
        }
        finally { store.Delete(key); }
    }
}

public class RunAtLoginTests
{
    private const string RunKey = @"Software\Microsoft\Windows\CurrentVersion\Run";

    [Fact]
    public void Toggling_writes_and_removes_the_Run_value()
    {
        using var k = Registry.CurrentUser.CreateSubKey(RunKey, writable: true);
        var original = k.GetValue("VPNGate");
        try
        {
            Assert.True(StartupRegistration.Set(false));
            Assert.False(StartupRegistration.IsEnabled);
            Assert.Null(k.GetValue("VPNGate"));

            Assert.True(StartupRegistration.Set(true));
            Assert.True(StartupRegistration.IsEnabled);
            Assert.Equal($"\"{Environment.ProcessPath}\"", k.GetValue("VPNGate"));

            Assert.True(StartupRegistration.Set(false));
            Assert.False(StartupRegistration.IsEnabled);
        }
        finally
        {
            if (original is string s) k.SetValue("VPNGate", s);
            else k.DeleteValue("VPNGate", throwOnMissingValue: false);
        }
    }
}
