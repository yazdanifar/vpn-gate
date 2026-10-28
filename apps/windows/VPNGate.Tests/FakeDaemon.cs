using System.Collections.Concurrent;
using System.IO.Pipes;
using System.Text;
using System.Text.Json.Nodes;
using VPNGate.Core;

namespace VPNGate.Tests;

/// <summary>A scriptable daemon on a real named pipe (a Unix socket on macOS/Linux): records requests, sends lines on demand.</summary>
public sealed class FakeDaemon : IAsyncDisposable
{
    public string PipeName { get; } = "vg" + Guid.NewGuid().ToString("N")[..10];
    public ConcurrentQueue<JsonObject> Requests { get; } = new();
    /// <summary>Called for each request; the lines it returns are sent back.</summary>
    public Func<JsonObject, IEnumerable<string>> Respond { get; set; } = _ => Array.Empty<string>();

    private readonly CancellationTokenSource _cts = new();
    private readonly object _gate = new();
    private NamedPipeServerStream? _current;
    private Task? _loop;
    private TaskCompletionSource _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);

    public FakeDaemon Start()
    {
        _loop = Task.Run(AcceptLoop);
        return this;
    }

    public IpcClient Client() => IpcClient.ForNamedPipe(PipeName);

    private async Task AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            var pipe = new NamedPipeServerStream(PipeName, PipeDirection.InOut, NamedPipeServerStream.MaxAllowedServerInstances,
                PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            try { await pipe.WaitForConnectionAsync(_cts.Token); }
            catch (OperationCanceledException) { pipe.Dispose(); return; }
            lock (_gate) _current = pipe;
            _connected.TrySetResult();
            _ = Task.Run(() => Serve(pipe));
        }
    }

    private async Task Serve(NamedPipeServerStream pipe)
    {
        var buf = new byte[4096];
        var line = new MemoryStream();
        try
        {
            while (true)
            {
                int n = await pipe.ReadAsync(buf, _cts.Token);
                if (n <= 0) return;
                for (int i = 0; i < n; i++)
                {
                    if (buf[i] != (byte)'\n') { line.WriteByte(buf[i]); continue; }
                    var req = (JsonObject)JsonNode.Parse(line.ToArray())!;
                    line.SetLength(0);
                    Requests.Enqueue(req);
                    foreach (var l in Respond(req)) await SendAsync(l);
                }
            }
        }
        catch (Exception e) when (e is IOException or OperationCanceledException or ObjectDisposedException) { }
    }

    public async Task WaitConnectedAsync() => await _connected.Task.WaitAsync(TimeSpan.FromSeconds(10));

    public async Task SendAsync(string line)
    {
        NamedPipeServerStream? p;
        lock (_gate) p = _current;
        if (p is null) throw new InvalidOperationException("no client");
        await p.WriteAsync(Encoding.UTF8.GetBytes(line + "\n"));
        await p.FlushAsync();
    }

    /// <summary>Closes the current client's pipe; the next connect gets a fresh one.</summary>
    public void Drop()
    {
        NamedPipeServerStream? p;
        lock (_gate) { p = _current; _current = null; }
        _connected = new(TaskCreationOptions.RunContinuationsAsynchronously);
        p?.Dispose();
    }

    public async Task<JsonObject> NextRequestAsync(string? cmd = null)
    {
        var until = DateTime.UtcNow.AddSeconds(10);
        while (DateTime.UtcNow < until)
        {
            while (Requests.TryDequeue(out var r))
                if (cmd is null || (string?)r["cmd"] == cmd) return r;
            await Task.Delay(10);
        }
        throw new TimeoutException($"no {cmd ?? "any"} request");
    }

    public static string Snapshot(string state, string extra = "") =>
        $"{{\"state\":\"{state}\",\"bytesIn\":0,\"bytesOut\":0,\"helperVersion\":8,\"ipcVersion\":9{extra}}}";

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        Drop();
        if (_loop is not null) await Task.WhenAny(_loop, Task.Delay(1000));
    }
}
