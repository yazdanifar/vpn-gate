using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace VPNGate.Core;

public sealed class CertImportException : Exception
{
    public CertImportException(string message) : base(message) { }
}

/// <summary>
/// Turns user-supplied certificate / key files into the DER blobs the daemon needs: the certificate (X.509 DER) and an RSA
/// private key as PKCS#1 <c>RSAPrivateKey</c> DER (CertImport.swift). Only RSA is supported; nothing here touches disk.
/// </summary>
public static class CertImport
{
    public sealed record Identity(byte[] CertDer, byte[] PrivateKeyDer);

    public static byte[] ParseCertificate(byte[] data)
    {
        byte[] der;
        if (PemBlocks(data).FirstOrDefault(b => b.Label is "CERTIFICATE" or "X509 CERTIFICATE") is { } block) der = block.Der;
        else if (data.Length > 0 && data[0] == 0x30) der = data;
        else throw new CertImportException("That file is not an X.509 certificate (PEM or DER expected).");
        try
        {
            using var cert = new X509Certificate2(der);
            return der;
        }
        catch (CryptographicException)
        {
            throw new CertImportException("That file is not an X.509 certificate (PEM or DER expected).");
        }
    }

    /// <summary>Accepts PKCS#1 (<c>RSA PRIVATE KEY</c>), PKCS#8 (<c>PRIVATE KEY</c>) or raw DER of either; returns PKCS#1 DER.</summary>
    public static byte[] ParsePrivateKey(byte[] data)
    {
        byte[]? der = null;
        foreach (var b in PemBlocks(data))
        {
            switch (b.Label)
            {
                case "ENCRYPTED PRIVATE KEY": throw Encrypted();
                case "EC PRIVATE KEY": throw Unsupported("EC");
                case "DSA PRIVATE KEY": throw Unsupported("DSA");
                case "RSA PRIVATE KEY":
                    if (b.Headers.Any(h => h.Contains("encrypted", StringComparison.OrdinalIgnoreCase))) throw Encrypted();
                    der = b.Der;
                    break;
                case "PRIVATE KEY":
                    der = b.Der;
                    break;
            }
            if (der is not null) break;
        }
        der ??= data.Length > 0 && data[0] == 0x30 ? data : throw NotKey();

        using var rsa = RSA.Create();
        try { rsa.ImportRSAPrivateKey(der, out _); return rsa.ExportRSAPrivateKey(); }
        catch (CryptographicException) { }
        try { rsa.ImportPkcs8PrivateKey(der, out _); return rsa.ExportRSAPrivateKey(); }
        catch (CryptographicException) { }
        // A PKCS#8 wrapper around a non-RSA key (EC) is recognised by its algorithm OID.
        if (LooksLikeEc(der)) throw Unsupported("EC");
        throw NotKey();
    }

    private static bool LooksLikeEc(byte[] der) =>
        // id-ecPublicKey 1.2.840.10045.2.1
        der.AsSpan().IndexOf(new byte[] { 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01 }) >= 0;

    /// <summary>A PKCS#12 / PFX file; the key must be RSA and belong to the certificate.</summary>
    public static Identity ParsePkcs12(byte[] data, string passphrase)
    {
        X509Certificate2 cert;
        try
        {
            cert = new X509Certificate2(data, passphrase, X509KeyStorageFlags.Exportable);
        }
        catch (CryptographicException e) when (e.Message.Contains("password", StringComparison.OrdinalIgnoreCase)
                                                || e.HResult == unchecked((int)0x80070056))
        {
            throw new CertImportException("Wrong passphrase for the .p12 file.");
        }
        catch (CryptographicException e)
        {
            throw new CertImportException($"Could not read the .p12 file: {e.Message}");
        }
        using (cert)
        {
            if (!cert.HasPrivateKey) throw new CertImportException("Could not read the .p12 file: it holds no private key.");
            using var rsa = cert.GetRSAPrivateKey();
            if (rsa is null) throw Unsupported("not RSA");
            // Windows CNG keys loaded from a PFX allow only an encrypted export, so go through that.
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1);
            var enc = rsa.ExportEncryptedPkcs8PrivateKey("x", pbe);
            using var plain = RSA.Create();
            plain.ImportEncryptedPkcs8PrivateKey("x", enc, out _);
            return new Identity(cert.RawData, plain.ExportRSAPrivateKey());
        }
    }

    /// <summary>Checks that <paramref name="keyDer"/> (PKCS#1) is the private half of <paramref name="certDer"/>.</summary>
    public static Identity Pair(byte[] certDer, byte[] keyDer)
    {
        using var cert = new X509Certificate2(certDer);
        using var pub = cert.GetRSAPublicKey() ?? throw Unsupported("not RSA");
        using var priv = RSA.Create();
        priv.ImportRSAPrivateKey(keyDer, out _);
        var a = pub.ExportParameters(false);
        var b = priv.ExportParameters(false);
        if (!a.Modulus!.AsSpan().SequenceEqual(b.Modulus) || !a.Exponent!.AsSpan().SequenceEqual(b.Exponent))
            throw new CertImportException("The private key does not belong to the certificate.");
        return new Identity(certDer, keyDer);
    }

    private static CertImportException Encrypted() => new(
        "The private key is passphrase-protected. Remove the passphrase first (openssl rsa -in key.pem -out plain.pem) or import a .p12 file instead.");

    private static CertImportException Unsupported(string t) => new($"Only RSA keys are supported for certificate login (this key is {t}).");

    private static CertImportException NotKey() => new("That file is not an RSA private key (PEM or DER expected).");

    internal sealed record PemBlock(string Label, List<string> Headers, byte[] Der);

    internal static List<PemBlock> PemBlocks(byte[] data)
    {
        var blocks = new List<PemBlock>();
        string text;
        try { text = new UTF8Encoding(false, true).GetString(data); }
        catch (DecoderFallbackException) { return blocks; }
        var lines = text.Split('\n').Select(l => l.Trim()).ToList();
        for (var i = 0; i < lines.Count; i++)
        {
            if (!lines[i].StartsWith("-----BEGIN ") || !lines[i].EndsWith("-----")) continue;
            var label = lines[i][11..^5];
            var end = $"-----END {label}-----";
            var headers = new List<string>();
            var body = new StringBuilder();
            var j = i + 1;
            for (; j < lines.Count && lines[j] != end; j++)
            {
                if (lines[j].Contains(':')) headers.Add(lines[j]);
                else body.Append(lines[j]);
            }
            if (j == lines.Count) break;
            try { blocks.Add(new PemBlock(label, headers, Convert.FromBase64String(body.ToString()))); }
            catch (FormatException) { }
            i = j;
        }
        return blocks;
    }
}
