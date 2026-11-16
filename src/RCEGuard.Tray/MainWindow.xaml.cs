using System.ComponentModel;
using System.Diagnostics;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using RCEGuard.Core.Configuration;
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
        ApplyMode();
    }

    /// <summary>Set by the application when it really ends; otherwise closing the window only hides it.</summary>
    public bool Exiting { get; set; }

    /// <summary>The colour of a state, shared with the icon in the notification area.</summary>
    public static (byte R, byte G, byte B) ColorOf(TrayKind kind) => kind switch
    {
        TrayKind.Watching => (0x2E, 0x7D, 0x32),
        TrayKind.Alert => (0xEF, 0x6C, 0x00),
        TrayKind.Locked => (0xC6, 0x28, 0x28),
        TrayKind.Learning => (0x15, 0x65, 0xC0),
        TrayKind.ReportOnly => (0x15, 0x65, 0xC0),
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
        else if (e.PropertyName == nameof(MainViewModel.Mode))
        {
            ApplyMode();
        }
    }

    /// <summary>Presses the button of the mode that is set; none if the configuration is none of the three.</summary>
    private void ApplyMode()
    {
        ModeProtect.IsChecked = viewModel.Mode == GuardMode.Protect;
        ModeReportOnly.IsChecked = viewModel.Mode == GuardMode.ReportOnly;
        ModeLearning.IsChecked = viewModel.Mode == GuardMode.Learning;
    }

    private void OnModeClick(object sender, RoutedEventArgs e)
    {
        var mode = ReferenceEquals(sender, ModeProtect) ? GuardMode.Protect : ReferenceEquals(sender, ModeReportOnly) ? GuardMode.ReportOnly : GuardMode.Learning;
        RequestMode(mode);
    }

    /// <summary>
    /// Asks whether the guard is to be switched to a mode and, on a yes, starts the command of the
    /// service that does it; Windows asks for an administrator. Also called from the menu of the icon.
    /// </summary>
    public void RequestMode(GuardMode mode)
    {
        viewModel.Refresh(windowIsOpen: IsVisible && IsActive);
        if (viewModel.Mode != mode && viewModel.CanSetMode)
        {
            var question =
                $"Switch the guard to \"{GuardModes.Name(mode)}\"?\n\n{GuardModes.Describe(mode)}\n\n" +
                "The guard service is restarted for this. Windows will ask for an administrator.";
            // Protect is the strict mode; the other two take protection away and are asked about as a warning.
            var icon = mode == GuardMode.Protect ? MessageBoxImage.Question : MessageBoxImage.Warning;
            if (Ask(question, $"RCEGuard: switch to \"{GuardModes.Name(mode)}\"", icon))
            {
                var problem = RunElevated(
                    GuardCommand.ModeArguments(mode),
                    "The command that sets the mode",
                    "The mode was not changed: the administrator question of Windows was declined.");
                viewModel.Refresh(windowIsOpen: IsVisible && IsActive);
                if (problem is not null)
                {
                    Tell(problem, MessageBoxImage.Warning);
                }
            }
        }

        // A click presses the button at once: put it back to what is really set.
        ApplyMode();
    }

    private static string? RunElevated(string arguments, string name, string declined)
    {
        var cursor = Mouse.OverrideCursor;
        Mouse.OverrideCursor = Cursors.Wait;
        try
        {
            // Stopping and starting the service can take a while: up to two minutes.
            return GuardCommand.Run(arguments, name, declined, GuardCommand.ConfigHint, timeoutMs: 120_000);
        }
        finally
        {
            Mouse.OverrideCursor = cursor;
        }
    }

    private bool Ask(string question, string title, MessageBoxImage icon, Window? owner = null)
    {
        owner ??= IsVisible ? this : null;
        var answer = owner is null
            ? MessageBox.Show(question, title, MessageBoxButton.OKCancel, icon, MessageBoxResult.Cancel)
            : MessageBox.Show(owner, question, title, MessageBoxButton.OKCancel, icon, MessageBoxResult.Cancel);
        return answer == MessageBoxResult.OK;
    }

    private void Tell(string text, MessageBoxImage icon, Window? owner = null)
    {
        owner ??= IsVisible ? this : null;
        if (owner is null)
        {
            MessageBox.Show(text, "RCEGuard", MessageBoxButton.OK, icon);
        }
        else
        {
            MessageBox.Show(owner, text, "RCEGuard", MessageBoxButton.OK, icon);
        }
    }

    private void OnFindingDoubleClick(object sender, MouseButtonEventArgs e)
    {
        // Only a double click on a row, not on the header or the empty part of the list.
        if (e.OriginalSource is DependencyObject source
            && ItemsControl.ContainerFromElement(FindingList, source) is ListViewItem { DataContext: FindingRow row })
        {
            FindingView(row).ShowDialog();
        }
    }

    /// <summary>A window with one finding in full, to read and to copy; for a connection with a way to allow the address.</summary>
    internal Window FindingView(FindingRow row)
    {
        var text = new TextBox
        {
            Text = row.DetailText,
            IsReadOnly = true,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            TextWrapping = TextWrapping.Wrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(12),
        };
        var window = new Window
        {
            Title = $"RCEGuard: finding {row.Rule} of {row.TimeText}",
            Width = 760,
            Height = 380,
            MinWidth = 480,
            MinHeight = 240,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            FontSize = 13,
            UseLayoutRounding = true,
        };
        var buttons = new DockPanel { Margin = new Thickness(12, 8, 12, 10) };
        var close = new Button { Content = "Close", Padding = new Thickness(16, 3, 16, 3), IsCancel = true, IsDefault = true };
        var copy = new Button { Content = "Copy", Padding = new Thickness(16, 3, 16, 3), Margin = new Thickness(0, 0, 8, 0) };
        copy.Click += (_, _) => Clipboard.SetText(row.DetailText);
        DockPanel.SetDock(close, Dock.Right);
        DockPanel.SetDock(copy, Dock.Right);
        buttons.Children.Add(close);
        buttons.Children.Add(copy);
        var note = new TextBlock
        {
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = new SolidColorBrush(Color.FromRgb(0x55, 0x55, 0x55)),
            TextTrimming = TextTrimming.CharacterEllipsis,
        };
        if (row.AllowableAddress is { } address)
        {
            var allow = new Button
            {
                Content = "Allow this address ...",
                Padding = new Thickness(16, 3, 16, 3),
                Margin = new Thickness(0, 0, 12, 0),
                ToolTip = $"Puts {address} on the allowlist of '{row.Profile}'. Windows asks for an administrator.",
            };
            allow.Click += (_, _) => RequestAllow(row, address, window);
            DockPanel.SetDock(allow, Dock.Left);
            buttons.Children.Add(allow);
            note.Text = "Only for an address you recognise as a server of your game.";
        }

        buttons.Children.Add(note);
        var layout = new DockPanel();
        DockPanel.SetDock(buttons, Dock.Bottom);
        layout.Children.Add(buttons);
        layout.Children.Add(text);
        window.Content = layout;
        if (IsVisible)
        {
            window.Owner = this;
        }

        return window;
    }

    private void RequestAllow(FindingRow row, string address, Window owner)
    {
        if (GuardCommand.AllowArguments(row.Profile, address) is not { } arguments)
        {
            return;
        }

        var question =
            $"Allow '{row.Profile}' to connect to {address}?\n\n" +
            "Only do this for an address you recognise as a server of your game: connections to it are not reported any more.\n\n" +
            "The address is added to the allowlist in appsettings.json and the guard service is restarted. Windows will ask for an administrator.";
        if (!Ask(question, "RCEGuard: allow an address", MessageBoxImage.Warning, owner))
        {
            return;
        }

        var problem = RunElevated(
            arguments,
            "The command that allows the address",
            "The address was not allowed: the administrator question of Windows was declined.");
        viewModel.Refresh(windowIsOpen: true);
        Tell(problem ?? $"{address} is on the allowlist of '{row.Profile}' now.", problem is null ? MessageBoxImage.Information : MessageBoxImage.Warning, owner);
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

    private void OnLearnedClick(object sender, RoutedEventArgs e)
    {
        if (sender is not Button { Tag: string profile })
        {
            return;
        }

        viewModel.Refresh(windowIsOpen: true);
        var line = viewModel.Learning.FirstOrDefault(learning => learning.Profile == profile);
        if (line is not null)
        {
            LearnedView(line).ShowDialog();
        }
    }

    /// <summary>A window with the notes of one profile as text, to read and to copy.</summary>
    internal Window LearnedView(LearningLine line)
    {
        var text = new TextBox
        {
            Text = line.Report,
            IsReadOnly = true,
            FontFamily = new FontFamily("Consolas"),
            FontSize = 13,
            TextWrapping = TextWrapping.NoWrap,
            VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto,
            BorderThickness = new Thickness(0),
            Padding = new Thickness(12),
        };
        var copy = new Button { Content = "Copy", Padding = new Thickness(16, 3, 16, 3), Margin = new Thickness(0, 0, 8, 0) };
        copy.Click += (_, _) => Clipboard.SetText(line.Report);
        var close = new Button { Content = "Close", Padding = new Thickness(16, 3, 16, 3), IsCancel = true, IsDefault = true };
        var note = new TextBlock
        {
            Text = "Nothing here is taken over by itself. Put what you recognise into appsettings.json as administrator.",
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = new SolidColorBrush(Color.FromRgb(0x55, 0x55, 0x55)),
            TextTrimming = TextTrimming.CharacterEllipsis,
        };
        var buttons = new DockPanel { Margin = new Thickness(12, 8, 12, 10) };
        DockPanel.SetDock(close, Dock.Right);
        DockPanel.SetDock(copy, Dock.Right);
        buttons.Children.Add(close);
        buttons.Children.Add(copy);
        buttons.Children.Add(note);
        var layout = new DockPanel();
        DockPanel.SetDock(buttons, Dock.Bottom);
        layout.Children.Add(buttons);
        layout.Children.Add(text);
        var window = new Window
        {
            Title = $"RCEGuard: what '{line.Profile}' did while learning",
            Width = 900,
            Height = 560,
            MinWidth = 480,
            MinHeight = 240,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Content = layout,
            FontSize = 13,
            UseLayoutRounding = true,
        };
        if (IsVisible)
        {
            window.Owner = this;
        }

        return window;
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
