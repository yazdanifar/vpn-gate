using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using VPNGate.Core;
using Xunit;

namespace VPNGate.Tests;

public class AccountTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "vg-acc-" + Guid.NewGuid().ToString("N")[..8]);
    private string File_ => Path.Combine(_dir, "accounts.json");

    public AccountTests() => Directory.CreateDirectory(_dir);
    public void Dispose() { try { Directory.Delete(_dir, true); } catch (IOException) { } }

    private static AccountEditorState Valid() => new() { Name = "Home", Host = "vpn.example.com", Username = "bob", Password = "pw" };

    [Fact]
    public void CanSaveNeedsNameHostAndValidFields()
    {
        Assert.True(Valid().CanSave);
        Assert.False(new AccountEditorState { Name = "x", Host = "" }.CanSave);
        Assert.False(new AccountEditorState { Name = " ", Host = "a.com" }.CanSave);
        var s = Valid(); s.Host = "-bad"; Assert.False(s.CanSave);
        s = Valid(); s.MtuString = "100"; Assert.Equal("MTU must be 576–1500, or blank for automatic.", s.MtuError); Assert.False(s.CanSave);
        s = Valid(); s.MacString = "zz"; Assert.NotNull(s.MacError); Assert.True(s.AdvancedInvalid);
        s = Valid(); s.Fingerprint = "abc"; Assert.NotNull(s.FingerprintError);
        s = Valid(); s.Hub = new string('x', 256); Assert.False(s.CanSave);
    }

    [Fact]
    public void CertificateAccountNeedsAnIdentity()
    {
        var s = Valid(); s.AuthType = AuthTypes.Certificate;
        Assert.False(s.CanSave);
        s.HasStoredIdentity = true;
        Assert.True(s.CanSave);
    }

    [Fact]
    public void MakeAccountNormalises()
    {
        var s = Valid();
        s.PortString = "443, x, 0, 70000, 992";
        s.Hub = " ";
        s.MaxConnection = 99;
        s.ReconnectIntervalSeconds = 0;
        s.Fingerprint = "AB:" + new string('c', 38);
        s.UseQoS = false;
        var a = s.MakeAccount(null);
        Assert.Equal(new[] { 443, 992 }, a.PortList);
        Assert.Equal("DEFAULT", a.Hub);
        Assert.Equal(32, a.MaxConnection);
        Assert.Equal(1, a.ReconnectInterval);
        Assert.Equal("ab" + new string('c', 38), a.ServerCertFingerprint);
        Assert.True(a.DisableQoS);
        Assert.Null(a.Routing);
        s.PortString = "x";
        Assert.Equal(new[] { 443 }, s.MakeAccount(null).PortList);
    }

    [Fact]
    public void EditingKeepsFieldsTheFormDoesNotShow()
    {
        var b = new ClientAccount { Name = "n", Host = "h.com", Proxy = new ProxySettings { Kind = ProxyKind.Http, Host = "p", Port = 3128 } };
        var s = new AccountEditorState(b);
        s.Name = "renamed";
        var a = s.MakeAccount(b);
        Assert.Equal(ProxyKind.Http, a.Proxy.Kind);
        Assert.Equal(b.Id, a.Id);
    }

    [Fact]
    public void SecretsStayOutOfTheFile()
    {
        var secrets = new MemorySecretStore();
        var store = new AccountStore(File_, secrets);
        var a = Valid().MakeAccount(null);
        a.Proxy = new ProxySettings { Kind = ProxyKind.Socks5, Host = "p", Port = 1, Username = "u", Password = "proxy-secret" };
        store.Add(a, "hunter2");
        var text = File.ReadAllText(File_);
        Assert.DoesNotContain("hunter2", text);
        Assert.DoesNotContain("proxy-secret", text);
        Assert.Equal("hunter2", store.Password(a));
        Assert.Equal("proxy-secret", store.ProxyPassword(a));

        var again = new AccountStore(File_, secrets);
        Assert.Single(again.Accounts);
        Assert.Equal("Home", again.Accounts[0].Name);
        Assert.Null(again.Accounts[0].Proxy.Password);
    }

    [Fact]
    public void DuplicateCopiesSecretsAndDeleteClearsThem()
    {
        var secrets = new MemorySecretStore();
        var store = new AccountStore(File_, secrets);
        var a = Valid().MakeAccount(null);
        store.Add(a, "pw1");
        store.Duplicate(a);
        Assert.Equal(2, store.Accounts.Count);
        var copy = store.Accounts[1];
        Assert.Equal("Home (Copy)", copy.Name);
        Assert.NotEqual(a.Id, copy.Id);
        Assert.Equal("pw1", store.Password(copy));
        store.Delete(copy);
        Assert.Null(store.Password(copy));
        Assert.Equal("pw1", store.Password(a));
    }

    [Fact]
    public void SwitchingToPasswordlessDropsStaleSecrets()
    {
        var secrets = new MemorySecretStore();
        var store = new AccountStore(File_, secrets);
        var a = Valid().MakeAccount(null);
        a.AuthType = AuthTypes.Certificate;
        store.Add(a, null, new byte[] { 1 }, new byte[] { 2 });
        Assert.True(store.HasCertificateIdentity(a));
        a.AuthType = AuthTypes.Anonymous;
        store.Update(a);
        Assert.False(store.HasCertificateIdentity(a));
    }

    [Fact]
    public void UnreadableRecordsAreSkippedAndTheOriginalKept()
    {
        var good = new AccountStore(File_, new MemorySecretStore());
        good.Add(Valid().MakeAccount(null));
        var json = File.ReadAllText(File_).TrimEnd();
        File.WriteAllText(File_, json[..^1] + ",{\"id\":\"nope\"}]");
        var store = new AccountStore(File_, new MemorySecretStore());
        Assert.Single(store.Accounts);
        Assert.Contains("could not be read and were skipped", store.LoadNotice);
        Assert.Contains(Directory.GetFiles(_dir), f => f.Contains(".corrupt-"));
    }

    [Fact]
    public void GarbageFileIsMovedAside()
    {
        File.WriteAllText(File_, "not json");
        var store = new AccountStore(File_, new MemorySecretStore());
        Assert.Empty(store.Accounts);
        Assert.StartsWith("The saved connection settings could not be read", store.LoadNotice);
        Assert.False(File.Exists(File_));
    }

    [Fact]
    public void ToConnectConfigPrefersTheAccountsOwnRouting()
    {
        var global = new RoutingConfig { BypassPrivateNetworks = true };
        var a = Valid().MakeAccount(null);
        Assert.Same(global, a.ToConnectConfig("p", null, null, true, global, TunnelMode.FullTunnel, 1080).Routing);
        a.Routing = new RoutingConfig { DefaultAction = RoutingAction.Direct };
        Assert.Same(a.Routing, a.ToConnectConfig("p", null, null, true, global, TunnelMode.FullTunnel, 1080).Routing);
        Assert.Equal("Standard Password (SHA-0)", a.ToConnectConfig("p", null, null, true, null, TunnelMode.FullTunnel, 1080).AuthType);
    }

    // MARK: certificates

    private static (X509Certificate2 cert, RSA rsa) MakeCert()
    {
        var rsa = RSA.Create(2048);
        var req = new CertificateRequest("CN=test", rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return (req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30)), rsa);
    }

    [Fact]
    public void ImportsPemCertificateAndPkcs8Key()
    {
        var (cert, rsa) = MakeCert();
        var certDer = CertImport.ParseCertificate(System.Text.Encoding.ASCII.GetBytes(cert.ExportCertificatePem()));
        Assert.Equal(cert.RawData, certDer);
        var keyDer = CertImport.ParsePrivateKey(System.Text.Encoding.ASCII.GetBytes(rsa.ExportPkcs8PrivateKeyPem()));
        Assert.Equal(rsa.ExportRSAPrivateKey(), keyDer);
        Assert.Equal(rsa.ExportRSAPrivateKey(), CertImport.ParsePrivateKey(System.Text.Encoding.ASCII.GetBytes(rsa.ExportRSAPrivateKeyPem())));
        Assert.Equal(rsa.ExportRSAPrivateKey(), CertImport.ParsePrivateKey(rsa.ExportPkcs8PrivateKey()));
        Assert.Equal(cert.RawData, CertImport.ParseCertificate(cert.RawData));
        CertImport.Pair(certDer, keyDer);
    }

    [Fact]
    public void RejectsMismatchedEncryptedAndEcKeys()
    {
        var (cert, rsa) = MakeCert();
        using var other = RSA.Create(2048);
        Assert.Equal("The private key does not belong to the certificate.",
            Assert.Throws<CertImportException>(() => CertImport.Pair(cert.RawData, other.ExportRSAPrivateKey())).Message);
        var enc = System.Text.Encoding.ASCII.GetBytes(rsa.ExportEncryptedPkcs8PrivateKeyPem("pw", new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000)));
        Assert.Contains("passphrase-protected", Assert.Throws<CertImportException>(() => CertImport.ParsePrivateKey(enc)).Message);
        using var ec = ECDsa.Create();
        Assert.Contains("EC", Assert.Throws<CertImportException>(() => CertImport.ParsePrivateKey(ec.ExportPkcs8PrivateKey())).Message);
        Assert.Contains("EC", Assert.Throws<CertImportException>(() => CertImport.ParsePrivateKey(System.Text.Encoding.ASCII.GetBytes(ec.ExportECPrivateKeyPem()))).Message);
        Assert.Contains("not an RSA private key", Assert.Throws<CertImportException>(() => CertImport.ParsePrivateKey(new byte[] { 1, 2, 3 })).Message);
        Assert.Contains("not an X.509", Assert.Throws<CertImportException>(() => CertImport.ParseCertificate(new byte[] { 1, 2, 3 })).Message);
    }

    [Fact]
    public void ImportsPkcs12AndRejectsAWrongPassphrase()
    {
        var (cert, rsa) = MakeCert();
        using var withKey = new X509Certificate2(cert.Export(X509ContentType.Pfx, "secret"), "secret", X509KeyStorageFlags.Exportable);
        var pfx = withKey.Export(X509ContentType.Pfx, "secret");
        var id = CertImport.ParsePkcs12(pfx, "secret");
        Assert.Equal(cert.RawData, id.CertDer);
        Assert.Equal(rsa.ExportRSAPrivateKey(), id.PrivateKeyDer);
        Assert.Equal("Wrong passphrase for the .p12 file.", Assert.Throws<CertImportException>(() => CertImport.ParsePkcs12(pfx, "nope")).Message);
    }
}

public class ChunkedSecretStoreTests
{
    [Fact]
    public void LongValuesRoundTripAndShortOnesToo()
    {
        var raw = new MemorySecretStore();
        var s = new ChunkedSecretStore(raw, 10);
        var long_ = new string('a', 25) + "XYZ";
        s.Set("k", long_);
        Assert.Equal(long_, s.Get("k"));
        Assert.All(raw.Items.Values, v => Assert.True(v.Length <= 10));
        s.Set("short", "abc");
        Assert.Equal("abc", s.Get("short"));
        s.Set("k", "tiny");
        Assert.Equal("tiny", s.Get("k"));
        Assert.DoesNotContain(raw.Items.Keys, k => k.StartsWith("k#") && k != "k#0");
        s.Delete("k");
        Assert.Null(s.Get("k"));
        Assert.DoesNotContain(raw.Items.Keys, k => k.StartsWith("k"));
        Assert.Null(s.Get("missing"));
    }
}

public class EditorCopyTests
{
    [Fact]
    public void EditingRoutingDoesNotTouchTheAccountUntilSaved()
    {
        var acc = new ClientAccount { Name = "n", Host = "h.com", Routing = new RoutingConfig { Rules = { new RoutingRule { Type = RoutingRuleType.Ip, Value = "1.1.1.1" } } } };
        var s = new AccountEditorState(acc);
        s.Routing.Rules.Clear();
        Assert.Single(acc.Routing!.Rules);
        Assert.True(s.UseCustomRouting);
    }
}
