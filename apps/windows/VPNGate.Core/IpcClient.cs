using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace VPNGate.Core;

/// <summary>Opens the byte stream to the daemon. The default is the named pipe; tests pass their own.</summary>
public delegate Task<Stream> IpcConnector(CancellationToken ct);

/// <summary>
/// Talks to the daemon (docs/cross-platform/IPC.md): newline-delimited JSON, one reader, lazy connect, and v9 requests
/// matched to replies by id. Events and drops are raised on the reader thread.
/// </summary>
public sealed class IpcClient : IAsyncDisposable
{
    private const int MaxLine = 1 << 20;

    private readonly IpcConnector _connector;
    private readonly object _lock = new();
    private readonly Dictionary<int, TaskCompletionSource<HelperReply>> _pending = new();
    private readonly SemaphoreSlim _writeGate = new(1, 1);
    private Stream? _stream;
    private int _nextId = 1;

    public IpcClient(IpcConnector connector) => _connector = connector;

    public event Action<HelperEvent>? EventReceived;
    public event Action? Disconnected;

    /// <summary>The client for the production daemon: \\.\pipe\VPNGate, current user.</summary>
    public static IpcClient ForNamedPipe(string pipeName = Ipc.PipeName) => new(async ct =>
    {
        var pipe = new NamedPipeClientStream(".", pipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
        try
        {
            await pipe.ConnectAsync(2000, ct).ConfigureAwait(false);
        }
        catch
        {
            await pipe.DisposeAsync().ConfigureAwait(false);
            throw;
        }
        return pipe;
    });

    public bool IsConnected
    {
        get { lock (_lock) return _stream is not null; }
    }

    /// <summary>Connects if needed. False when the daemon is not there (not installed, stopped, or refused us).</summary>
    public async Task<bool> ConnectAsync(CancellationToken ct = default)
    {
        if (IsConnected) return true;
        Stream stream;
        try
        {
            stream = await _connector(ct).ConfigureAwait(false);
        }
        catch (Exception e) when (e is IOException or TimeoutException or UnauthorizedAccessException or OperationCanceledException or System.Net.Sockets.SocketException)
        {
            return false;
        }
        lock (_lock)
        {
            if (_stream is not null)
            {
                stream.Dispose();
                return true;
            }
            _stream = stream;
        }
        _ = Task.Run(() => ReadLoop(stream));
        return true;
    }

    private async Task ReadLoop(Stream stream)
    {
        var buf = new byte[4096];
        var line = new MemoryStream();
        try
        {
            while (true)
            {
                int n = await stream.ReadAsync(buf).ConfigureAwait(false);
                if (n <= 0) break;
                for (int i = 0; i < n; i++)
                {
                    if (buf[i] != (byte)'\n')
                    {
                        line.WriteByte(buf[i]);
                        if (line.Length > MaxLine) return;
                        continue;
                    }
                    Dispatch(line.GetBuffer().AsSpan(0, (int)line.Length));
                    line.SetLength(0);
                }
            }
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException or InvalidOperationException)
        {
        }
        finally
        {
            List<TaskCompletionSource<HelperReply>> waiting;
            bool wasCurrent;
            lock (_lock)
            {
                wasCurrent = ReferenceEquals(_stream, stream);
                if (wasCurrent) _stream = null;
                waiting = _pending.Values.ToList();
                if (wasCurrent) _pending.Clear();
            }
            try { stream.Dispose(); } catch (IOException) { }
            foreach (var w in waiting) w.TrySetException(new HelperRequestException(HelperRequestFailure.Disconnected));
            if (wasCurrent) Disconnected?.Invoke();
        }
    }

    private void Dispatch(ReadOnlySpan<byte> line)
    {
        if (line.IsEmpty) return;
        JsonObject? obj;
        try { obj = JsonNode.Parse(line) as JsonObject; }
        catch (JsonException) { return; }
        if (obj is null) return;
        // Replies have `reply`, events have `state`; a line is only ever one of them.
        if (obj.ContainsKey("reply"))
        {
            HelperReply? r;
            try { r = obj.Deserialize<HelperReply>(Ipc.Json); }
            catch (JsonException) { return; }
            if (r?.Id is not { } id) return;
            TaskCompletionSource<HelperReply>? waiter;
            lock (_lock) _pending.Remove(id, out waiter);
            waiter?.TrySetResult(r);
        }
        else if (obj.ContainsKey("state"))
        {
            HelperEvent? e;
            try { e = obj.Deserialize<HelperEvent>(Ipc.Json); }
            catch (JsonException) { return; }
            if (e is not null) EventReceived?.Invoke(e);
        }
    }

    /// <summary>Fire-and-forget (connect, disconnect, status). False if the daemon could not be reached.</summary>
    public async Task<bool> SendAsync(HelperRequest request, CancellationToken ct = default)
    {
        if (!await ConnectAsync(ct).ConfigureAwait(false)) return false;
        return await WriteAsync(request, ct).ConfigureAwait(false);
    }

    private async Task<bool> WriteAsync(HelperRequest request, CancellationToken ct)
    {
        Stream? stream;
        lock (_lock) stream = _stream;
        if (stream is null) return false;
        var bytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(request, Ipc.Json) + "\n");
        await _writeGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await stream.WriteAsync(bytes, ct).ConfigureAwait(false);
            await stream.FlushAsync(ct).ConfigureAwait(false);
            return true;
        }
        catch (Exception e) when (e is IOException or ObjectDisposedException)
        {
            return false;
        }
        finally
        {
            _writeGate.Release();
        }
    }

    /// <summary>
    /// Sends a v9 request and waits for the reply with the same id. Throws <see cref="HelperRequestException"/>:
    /// Failed for ok:false, Timeout when the daemon stays silent, Disconnected when the pipe drops first.
    /// </summary>
    public async Task<HelperReply> RequestAsync(HelperRequest request, TimeSpan? timeout = null, CancellationToken ct = default)
    {
        if (!await ConnectAsync(ct).ConfigureAwait(false)) throw new HelperRequestException(HelperRequestFailure.Disconnected);
        var tcs = new TaskCompletionSource<HelperReply>(TaskCreationOptions.RunContinuationsAsynchronously);
        int id;
        lock (_lock)
        {
            id = _nextId++;
            _pending[id] = tcs;
        }
        request.Id = id;
        void Forget() { lock (_lock) _pending.Remove(id); }

        if (!await WriteAsync(request, ct).ConfigureAwait(false))
        {
            Forget();
            throw new HelperRequestException(HelperRequestFailure.Disconnected);
        }
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        cts.CancelAfter(timeout ?? TimeSpan.FromSeconds(90));
        try
        {
            var reply = await tcs.Task.WaitAsync(cts.Token).ConfigureAwait(false);
            if (!reply.Ok) throw new HelperRequestException(HelperRequestFailure.Failed, reply.Error ?? "The helper refused the request");
            return reply;
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            Forget();
            throw new HelperRequestException(HelperRequestFailure.Timeout);
        }
        catch (OperationCanceledException)
        {
            Forget();
            throw;
        }
    }

    public async Task<ServerListResult> ListServersAsync(CancellationToken ct = default) =>
        (await RequestAsync(HelperRequest.Of("listServers"), TimeSpan.FromSeconds(30), ct).ConfigureAwait(false)).Decode<ServerListResult>();

    public async Task<ServerListResult> RefreshServersAsync(ProxySettings proxy, string? mirror, CancellationToken ct = default)
    {
        var r = HelperRequest.Of("refreshServers");
        r.Proxy = proxy;
        if (!string.IsNullOrEmpty(mirror)) r.Mirror = mirror;
        return (await RequestAsync(r, TimeSpan.FromSeconds(180), ct).ConfigureAwait(false)).Decode<ServerListResult>();
    }

    public async ValueTask DisposeAsync()
    {
        Stream? s;
        lock (_lock) s = _stream;
        if (s is not null) await s.DisposeAsync().ConfigureAwait(false);
    }
}
