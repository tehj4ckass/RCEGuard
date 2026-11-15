using System.Diagnostics;
using System.Windows;
using System.Windows.Threading;
using RCEGuard.Tray.Model;

namespace RCEGuard.Tray;

/// <summary>Entry point of the tray application.</summary>
internal static class Program
{
    private const string Usage =
        """
        RCEGuard tray application. Shows what the guard service found and whether it is running.
        It only reads; it does not watch anything itself.

          --show               open the window at the start (otherwise only the icon appears)
          --data-dir <folder>  data folder of the service (default: C:\ProgramData\RCEGuard)
        """;

    [STAThread]
    private static int Main(string[] args)
    {
        var show = false;
        var dataDirectory = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "RCEGuard");
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--show":
                    show = true;
                    break;
                case "--data-dir" when i + 1 < args.Length:
                    dataDirectory = Path.GetFullPath(args[++i]);
                    break;
                default:
                    MessageBox.Show($"Unknown or incomplete argument '{args[i]}'.\n\n{Usage}", "RCEGuard", MessageBoxButton.OK, MessageBoxImage.Information);
                    return 2;
            }
        }

        // One icon per logged-on user: a second start only asks for the window of the first.
        using var single = new Mutex(initiallyOwned: true, @"Local\RCEGuard.Tray", out var first);
        if (!first)
        {
            MessageBox.Show("RCEGuard is already running. Its icon is in the notification area, next to the clock.", "RCEGuard", MessageBoxButton.OK, MessageBoxImage.Information);
            return 0;
        }

        var application = new Application { ShutdownMode = ShutdownMode.OnExplicitShutdown };
        var viewModel = new MainViewModel(dataDirectory, new StatusReader(dataDirectory), new SeenFile(SeenFile.PathFor(dataDirectory)));
        var window = new MainWindow(viewModel);

        void Open()
        {
            window.Show();
            if (window.WindowState == WindowState.Minimized)
            {
                window.WindowState = WindowState.Normal;
            }

            window.Activate();
        }

        void OpenFolder()
        {
            if (Directory.Exists(dataDirectory))
            {
                Process.Start(new ProcessStartInfo("explorer.exe", $"\"{dataDirectory}\"") { UseShellExecute = false });
            }
        }

        using var tray = new TrayIcon(Open, OpenFolder, () =>
        {
            window.Exiting = true;
            window.Close();
            application.Shutdown();
        });
        viewModel.ToastRequested += tray.Toast;
        viewModel.PropertyChanged += (_, e) =>
        {
            if (e.PropertyName == nameof(MainViewModel.State))
            {
                tray.Show(viewModel.State);
            }
        };

        void Refresh() => viewModel.Refresh(windowIsOpen: window.IsVisible && window.IsActive);

        Refresh();
        tray.Show(viewModel.State);
        var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        timer.Tick += (_, _) => Refresh();
        timer.Start();

        if (show)
        {
            Open();
        }

        return application.Run();
    }
}
