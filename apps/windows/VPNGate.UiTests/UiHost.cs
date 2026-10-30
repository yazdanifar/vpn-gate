using System.Runtime.InteropServices.WindowsRuntime;
using Microsoft.UI.Dispatching;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Automation.Peers;
using Microsoft.UI.Xaml.Automation.Provider;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Media.Imaging;
using Windows.Graphics.Imaging;
using Windows.Storage.Streams;
using Xunit;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace VPNGate.UiTests;

/// <summary>
/// One XAML <see cref="Application"/> on a dedicated STA thread for the whole test run (what the generated Main of a WinUI app does),
/// and a way to run a test body on that UI thread. The real <c>App.OnLaunched</c> is skipped by VPNGATE_UITEST.
/// </summary>
internal static class UiHost
{
    private static readonly object Gate = new();
    private static DispatcherQueue? _queue;
    private static Window? _anchor;
    private static Exception? _startFailure;

    /// <summary>Exceptions that XAML reported as unhandled while a test ran.</summary>
    public static readonly List<string> Unhandled = new();

    private static void EnsureStarted()
    {
        lock (Gate)
        {
            if (_queue is not null) return;
            Environment.SetEnvironmentVariable("VPNGATE_UITEST", "1");
            AppDomain.CurrentDomain.UnhandledException += (_, e) =>
            {
                Console.Error.WriteLine("UNHANDLED (terminating=" + e.IsTerminating + "): " + e.ExceptionObject);
                Console.Error.Flush();
            };
            using var ready = new ManualResetEventSlim();
            var t = new Thread(() =>
            {
                try
                {
                    WinRT.ComWrappersSupport.InitializeComWrappers();
                    Application.Start(_ =>
                    {
                        _queue = DispatcherQueue.GetForCurrentThread();
                        SynchronizationContext.SetSynchronizationContext(new DispatcherQueueSynchronizationContext(_queue));
                        var app = new VPNGate.App.App();
                        app.UnhandledException += (_, e) =>
                        {
                            lock (Unhandled) Unhandled.Add(e.Exception?.ToString() ?? e.Message);
                            e.Handled = true;
                        };
                        // WinUI exits the process when the last window closes: keep one (never shown) for the whole run.
                        _anchor = new Window();
                        ready.Set();
                    });
                }
                catch (Exception e)
                {
                    _startFailure = e;
                    ready.Set();
                }
            }) { IsBackground = true, Name = "xaml-ui" };
            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            if (!ready.Wait(TimeSpan.FromSeconds(60))) throw new TimeoutException("the XAML application did not start");
            if (_startFailure is not null) throw new InvalidOperationException("the XAML application failed to start", _startFailure);
        }
    }

    /// <summary>Runs <paramref name="body"/> on the UI thread; a failure inside it fails the awaiting test.</summary>
    public static Task Run(Func<Task> body)
    {
        EnsureStarted();
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_queue!.TryEnqueue(async () =>
            {
                try
                {
                    await body();
                    tcs.SetResult();
                }
                catch (Exception e)
                {
                    tcs.SetException(e);
                }
            }))
            throw new InvalidOperationException("the UI thread is gone");
        return tcs.Task.WaitAsync(TimeSpan.FromMinutes(2));
    }
}

/// <summary>Helpers to look into a window's visual tree, drive controls like UI Automation does, and take pictures.</summary>
internal static class Probe
{
    public static string ShotDir
    {
        get
        {
            var d = Environment.GetEnvironmentVariable("VPNGATE_SHOTS") is { Length: > 0 } e ? e : Path.Combine(AppContext.BaseDirectory, "shots");
            Directory.CreateDirectory(d);
            return d;
        }
    }

    /// <summary>Lets layout, bindings and pending dispatcher work finish.</summary>
    public static async Task Settle(int ms = 400) => await Task.Delay(ms);

    public static async Task Until(Func<bool> cond, string what, int seconds = 15)
    {
        var until = DateTime.UtcNow.AddSeconds(seconds);
        while (!cond())
        {
            Assert.True(DateTime.UtcNow < until, "timed out waiting for: " + what);
            await Task.Delay(25);
        }
    }

    public static IEnumerable<DependencyObject> Descendants(DependencyObject root)
    {
        var n = VisualTreeHelper.GetChildrenCount(root);
        for (var i = 0; i < n; i++)
        {
            var c = VisualTreeHelper.GetChild(root, i);
            yield return c;
            foreach (var d in Descendants(c)) yield return d;
        }
    }

    public static IEnumerable<T> All<T>(DependencyObject root) where T : DependencyObject => Descendants(root).OfType<T>();

    public static IEnumerable<string> Texts(DependencyObject root) => All<TextBlock>(root).Select(t => t.Text);

    public static bool HasText(DependencyObject root, string text) => Texts(root).Any(t => t == text);

    public static T Find<T>(DependencyObject root, Func<T, bool> pred, string what) where T : DependencyObject =>
        All<T>(root).FirstOrDefault(pred) ?? throw new Xunit.Sdk.XunitException(
            $"no {typeof(T).Name} {what}. Texts in the tree: " + string.Join(" | ", Texts(root).Take(60)));

    public static Button ButtonNamed(DependencyObject root, string content) =>
        Find<Button>(root, b => b.Content as string == content, $"with content '{content}'");

    public static T? Ancestor<T>(DependencyObject d) where T : DependencyObject
    {
        for (var p = VisualTreeHelper.GetParent(d); p is not null; p = VisualTreeHelper.GetParent(p))
            if (p is T t) return t;
        return null;
    }

    /// <summary>Invoke through UI Automation, like a screen reader or FlaUI does.</summary>
    public static void Invoke(UIElement e)
    {
        var peer = FrameworkElementAutomationPeer.CreatePeerForElement(e);
        var p = peer.GetPattern(PatternInterface.Invoke) as IInvokeProvider
                ?? throw new Xunit.Sdk.XunitException($"{e.GetType().Name} has no Invoke pattern");
        p.Invoke();
    }

    /// <summary>The content of the first open popup (a ContentDialog) of the window, once it is there.</summary>
    public static async Task<ContentDialog> OpenDialog(XamlRoot root)
    {
        ContentDialog? found = null;
        await Until(() =>
        {
            foreach (var popup in VisualTreeHelper.GetOpenPopupsForXamlRoot(root))
            {
                if (popup.Child is ContentDialog d) { found = d; return true; }
                if (popup.Child is not null && All<ContentDialog>(popup.Child).FirstOrDefault() is { } inner) { found = inner; return true; }
            }
            // ContentDialog's own template sits in a popup whose child is the dialog's layout root: climb from a known part.
            foreach (var popup in VisualTreeHelper.GetOpenPopupsForXamlRoot(root))
            {
                if (popup.Child is null) continue;
                var any = All<Button>(popup.Child).FirstOrDefault();
                if (any is not null && Ancestor<ContentDialog>(any) is { } up) { found = up; return true; }
            }
            return false;
        }, "a dialog to open");
        await Settle(300);
        return found!;
    }

    /// <summary>Renders <paramref name="element"/> to shots/name.png and returns the number of distinct colours sampled (0 means a blank frame).</summary>
    public static async Task<int> Snap(FrameworkElement element, string name)
    {
        var rtb = new RenderTargetBitmap();
        await rtb.RenderAsync(element);
        var pixels = (await rtb.GetPixelsAsync()).ToArray();
        var path = Path.Combine(ShotDir, name + ".png");
        using (var stream = new InMemoryRandomAccessStream())
        {
            var enc = await BitmapEncoder.CreateAsync(BitmapEncoder.PngEncoderId, stream);
            enc.SetPixelData(BitmapPixelFormat.Bgra8, BitmapAlphaMode.Premultiplied, (uint)rtb.PixelWidth, (uint)rtb.PixelHeight, 96, 96, pixels);
            await enc.FlushAsync();
            stream.Seek(0);
            var bytes = new byte[stream.Size];
            await stream.AsStreamForRead().ReadExactlyAsync(bytes);
            await File.WriteAllBytesAsync(path, bytes);
        }
        var colors = new HashSet<uint>();
        for (var i = 0; i + 3 < pixels.Length; i += 4 * 7) colors.Add(BitConverter.ToUInt32(pixels, i));
        return colors.Count;
    }

    /// <summary>Takes the picture and fails if it is blank or tiny (a missing render is a real failure).</summary>
    public static async Task Shot(FrameworkElement element, string name)
    {
        var distinct = await Snap(element, name);
        Assert.True(element.ActualWidth > 100 && element.ActualHeight > 50, $"{name}: rendered at {element.ActualWidth}x{element.ActualHeight}");
        Assert.True(distinct > 3, $"{name}: the picture is blank ({distinct} colours)");
    }

    /// <summary>The window's root content, laid out and loaded.</summary>
    public static async Task<FrameworkElement> Show(Window w)
    {
        w.Activate();
        var root = (FrameworkElement)w.Content;
        await Until(() => root.IsLoaded && root.XamlRoot is not null, "the window to load");
        await Settle();
        return root;
    }
}
