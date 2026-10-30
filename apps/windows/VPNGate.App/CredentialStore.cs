using System.Runtime.InteropServices;
using System.Text;
using VPNGate.Core;

namespace VPNGate.App;

/// <summary>
/// Secrets in Windows Credential Manager (generic credentials, target "VPNGate/&lt;key&gt;"). One credential holds at most 2560
/// bytes, so wrap it in a <see cref="ChunkedSecretStore"/> (see <see cref="Create"/>).
/// </summary>
internal sealed class CredentialStore : ISecretStore
{
    private const string Prefix = "VPNGate/";
    private const uint CredTypeGeneric = 1;
    private const uint PersistLocalMachine = 2;

    public static ISecretStore Create() => new ChunkedSecretStore(new CredentialStore(), 1000);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public uint Flags;
        public uint Type;
        public string TargetName;
        public string? Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist;
        public uint AttributeCount;
        public IntPtr Attributes;
        public string? TargetAlias;
        public string? UserName;
    }

    [DllImport("advapi32.dll", EntryPoint = "CredWriteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredWrite(ref Credential credential, uint flags);

    [DllImport("advapi32.dll", EntryPoint = "CredReadW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredRead(string target, uint type, uint flags, out IntPtr credential);

    [DllImport("advapi32.dll", EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CredDelete(string target, uint type, uint flags);

    [DllImport("advapi32.dll")]
    private static extern void CredFree(IntPtr buffer);

    public string? Get(string key)
    {
        if (!CredRead(Prefix + key, CredTypeGeneric, 0, out var p)) return null;
        try
        {
            var c = Marshal.PtrToStructure<Credential>(p);
            return c.CredentialBlobSize == 0 ? "" : Marshal.PtrToStringUni(c.CredentialBlob, (int)c.CredentialBlobSize / 2);
        }
        finally
        {
            CredFree(p);
        }
    }

    public void Set(string key, string value)
    {
        var bytes = Encoding.Unicode.GetBytes(value);
        var blob = Marshal.AllocHGlobal(Math.Max(bytes.Length, 1));
        try
        {
            Marshal.Copy(bytes, 0, blob, bytes.Length);
            var c = new Credential
            {
                Type = CredTypeGeneric,
                TargetName = Prefix + key,
                CredentialBlobSize = (uint)bytes.Length,
                CredentialBlob = blob,
                Persist = PersistLocalMachine,
                UserName = "VPNGate",
            };
            CredWrite(ref c, 0);
        }
        finally
        {
            Marshal.FreeHGlobal(blob);
        }
    }

    public void Delete(string key) => CredDelete(Prefix + key, CredTypeGeneric, 0);
}
