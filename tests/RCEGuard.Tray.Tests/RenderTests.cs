using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using RCEGuard.Core.Rules;
using RCEGuard.Tray.Model;
using Drawing = System.Drawing;

namespace RCEGuard.Tray.Tests;

/// <summary>
/// Draws the window and the icons into picture files, without showing anything on the screen.
/// The tests only check that drawing works and gives a picture of the expected size; what the
/// pictures look like is for a person to judge. They are written to the folder
/// %TEMP%\rceguard-tray-pictures.
/// </summary>
public sealed class RenderTests
{
    private static readonly string Pictures = Path.Combine(Path.GetTempPath(), "rceguard-tray-pictures");

    /// <summary>WPF needs a thread of its own kind (single-threaded apartment).</summary>
    private static void OnUiThread(Action action)
    {
        Exception? failure = null;
        var thread = new Thread(() =>
        {
            try
            {
                action();
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                Dispatcher.CurrentDispatcher.InvokeShutdown();
            }
        });
        thread.SetApartmentState(ApartmentState.STA);
        thread.Start();
        thread.Join();
        if (failure is not null)
        {
            throw new InvalidOperationException($"Drawing failed: {failure}", failure);
        }
    }

    private static void Render(MainViewModel viewModel, string fileName)
    {
        var window = new MainWindow(viewModel);
        var root = (FrameworkElement)window.Content;
        var size = new Size(1024, 560);
        root.Measure(size);
        root.Arrange(new Rect(size));
        // Bindings and the rows of the list are filled in by the dispatcher.
        Dispatcher.CurrentDispatcher.Invoke(() => { }, DispatcherPriority.ApplicationIdle);
        root.UpdateLayout();

        var picture = new RenderTargetBitmap((int)size.Width, (int)size.Height, 96, 96, PixelFormats.Pbgra32);
        var background = new DrawingVisual();
        using (var context = background.RenderOpen())
        {
            context.DrawRectangle(Brushes.White, null, new Rect(size));
        }

        picture.Render(background);
        picture.Render(root);
        Directory.CreateDirectory(Pictures);
        var encoder = new PngBitmapEncoder();
        encoder.Frames.Add(BitmapFrame.Create(picture));
        using var file = File.Create(Path.Combine(Pictures, fileName));
        encoder.Save(file);
    }

    [Fact]
    public void The_window_draws_with_findings_and_a_lockdown()
    {
        OnUiThread(() =>
        {
            using var data = new DataFolder();
            data.Add("R3", Severity.Medium, FindingAction.Log, @"The game client created a file outside the game folder: C:\Users\player\Documents\notes.txt");
            data.Add("R1", Severity.Medium, FindingAction.Log, "Windows attached a console to the game client (conhost.exe)");
            data.Add("R2", Severity.Critical, FindingAction.Alert, "The game client connected to an address that is not on the allowlist: 203.0.113.9:443");
            data.Add("R5", Severity.High, FindingAction.Alert, @"The game client loaded an unsigned module from a user folder: C:\Users\player\AppData\Local\Temp\helper.dll");
            var repeated = data.Add("R2", Severity.Critical, FindingAction.Alert, "The game client connected to an address that is not on the allowlist: 198.51.100.20:8085");
            using (var store = new RCEGuard.Service.FindingStore(data.Database))
            {
                store.AddRepeat(repeated, DateTimeOffset.UtcNow);
                store.AddRepeat(repeated, DateTimeOffset.UtcNow);
            }

            data.Add(
                "R1", Severity.Critical, FindingAction.Kill, @"The game client started another program: C:\Windows\System32\cmd.exe",
                "cmd.exe (13868): terminated; Wow.exe (22672): terminated; locked down: the firewall blocks every outbound connection of the client until the lockdown is released");
            data.Lock("Default");
            var viewModel = data.ViewModel();
            viewModel.Refresh();

            Render(viewModel, "window-locked.png");

            Assert.Equal(6, viewModel.Findings.Count);
        });

        Assert.True(new FileInfo(Path.Combine(Pictures, "window-locked.png")).Length > 10_000);
    }

    [Fact]
    public void The_window_draws_when_nothing_is_installed()
    {
        OnUiThread(() =>
        {
            var nowhere = Path.Combine(Path.GetTempPath(), "rceguard-tray-no-such-folder");
            var viewModel = new MainViewModel(nowhere, new StatusReader(nowhere, () => ServiceState.NotInstalled), new SeenFile(Path.Combine(nowhere, "seen.txt")));
            viewModel.Refresh();

            Render(viewModel, "window-not-installed.png");

            Assert.Equal(TrayKind.NotWatching, viewModel.State.Kind);
            Assert.Empty(viewModel.Findings);
        });

        Assert.True(new FileInfo(Path.Combine(Pictures, "window-not-installed.png")).Length > 3_000);
    }

    [Fact]
    public void Every_state_has_an_icon_that_differs_from_the_others()
    {
        var kinds = Enum.GetValues<TrayKind>();
        var pixels = new List<string>();
        Directory.CreateDirectory(Pictures);
        using var sheet = new Drawing.Bitmap(kinds.Length * 140, 140);
        using (var graphics = Drawing.Graphics.FromImage(sheet))
        {
            graphics.Clear(Drawing.Color.FromArgb(32, 32, 32));
            graphics.InterpolationMode = Drawing.Drawing2D.InterpolationMode.NearestNeighbor;
            for (var i = 0; i < kinds.Length; i++)
            {
                using var icon = TrayIcon.Draw(kinds[i]);
                using var bitmap = icon.ToBitmap();
                Assert.Equal((32, 32), (bitmap.Width, bitmap.Height));
                pixels.Add(string.Join(",", Enumerable.Range(0, 32).Select(n => bitmap.GetPixel(n, 15).ToArgb())));
                // Once at four times the size to look at, once as large as Windows shows it.
                graphics.DrawImage(bitmap, (i * 140) + 6, 6, 128, 128);
                graphics.DrawImage(bitmap, (i * 140) + 104, 104, 32, 32);
            }
        }

        sheet.Save(Path.Combine(Pictures, "icons.png"), Drawing.Imaging.ImageFormat.Png);

        Assert.Equal(kinds.Length, pixels.Distinct().Count());
    }
}
