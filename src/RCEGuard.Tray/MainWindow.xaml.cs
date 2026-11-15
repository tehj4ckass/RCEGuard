using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using RCEGuard.Tray.Model;

namespace RCEGuard.Tray;

/// <summary>The window behind the icon: state, lockdowns and the list of findings.</summary>
internal partial class MainWindow : Window
{
    private readonly MainViewModel viewModel;

    /// <summary>Creates the window for a view model.</summary>
    public MainWindow(MainViewModel viewModel)
    {
        this.viewModel = viewModel;
        InitializeComponent();
        DataContext = viewModel;
        viewModel.PropertyChanged += OnViewModelChanged;
        ApplyState();
    }

    /// <summary>Set by the application when it really ends; otherwise closing the window only hides it.</summary>
    public bool Exiting { get; set; }

    /// <summary>The colour of a state, shared with the icon in the notification area.</summary>
    public static (byte R, byte G, byte B) ColorOf(TrayKind kind) => kind switch
    {
        TrayKind.Watching => (0x2E, 0x7D, 0x32),
        TrayKind.Alert => (0xEF, 0x6C, 0x00),
        TrayKind.Locked => (0xC6, 0x28, 0x28),
        _ => (0x75, 0x75, 0x75),
    };

    /// <inheritdoc />
    protected override void OnClosing(CancelEventArgs e)
    {
        if (!Exiting)
        {
            // The application lives in the notification area: the window is only a view of it.
            e.Cancel = true;
            Hide();
        }

        base.OnClosing(e);
    }

    /// <inheritdoc />
    protected override void OnActivated(EventArgs e)
    {
        base.OnActivated(e);
        viewModel.MarkSeen();
    }

    private void OnViewModelChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MainViewModel.State))
        {
            ApplyState();
        }
    }

    private void ApplyState()
    {
        var (r, g, b) = ColorOf(viewModel.State.Kind);
        StateBar.Background = new SolidColorBrush(Color.FromRgb(r, g, b));
    }

    private void OnOpenFolderClick(object sender, RoutedEventArgs e)
    {
        if (Directory.Exists(viewModel.DataDirectory))
        {
            Process.Start(new ProcessStartInfo("explorer.exe", $"\"{viewModel.DataDirectory}\"") { UseShellExecute = false });
        }
        else
        {
            MessageBox.Show(this, $"The folder '{viewModel.DataDirectory}' does not exist. RCEGuard is not installed.", "RCEGuard", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }

    private void OnReleaseClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string profile })
        {
            return;
        }

        var line = viewModel.Lockdowns.FirstOrDefault(lockdown => lockdown.Profile == profile);
        var question =
            $"End the lockdown of {line?.Text ?? $"'{profile}'"}?\n\n" +
            "The lockdown is there because the client did something it never does. Look at the finding first.\n\n" +
            "Windows will ask for an administrator.";
        if (MessageBox.Show(this, question, "RCEGuard: release the lockdown", MessageBoxButton.OKCancel, MessageBoxImage.Warning, MessageBoxResult.Cancel) != MessageBoxResult.OK)
        {
            return;
        }

        var problem = ReleaseAction.Run(profile);
        viewModel.Refresh(windowIsOpen: true);
        if (problem is not null)
        {
            MessageBox.Show(this, problem, "RCEGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        else if (viewModel.Lockdowns.Any(lockdown => lockdown.Profile == profile))
        {
            MessageBox.Show(this, $"'{profile}' is still in lockdown. The log of the guard service in '{viewModel.DataDirectory}' says why.", "RCEGuard", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }
}
