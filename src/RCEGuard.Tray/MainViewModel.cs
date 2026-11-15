using System.Collections.ObjectModel;
using System.ComponentModel;
using Microsoft.Data.Sqlite;
using RCEGuard.Core.State;
using RCEGuard.Tray.Model;

namespace RCEGuard.Tray;

/// <summary>A profile in lockdown, as shown in the window.</summary>
internal sealed record LockdownLine(string Profile, string Text);

/// <summary>
/// What the window and the icon show. <see cref="Refresh"/> reads everything anew; it is called by
/// a timer. Nothing here touches the user interface directly, so it is tested without a window.
/// </summary>
internal sealed class MainViewModel : INotifyPropertyChanged
{
    private const int ListLength = 200;

    private readonly StatusReader statusReader;
    private readonly SeenFile seenFile;
    private readonly string databasePath;
    private long? lastNotifiedId;
    private int unseen;
    private TrayState state = new(TrayKind.NotWatching, "RCEGuard", "RCEGuard", string.Empty);
    private string problem = string.Empty;

    /// <summary>Creates the view model for a data folder.</summary>
    public MainViewModel(string dataDirectory, StatusReader statusReader, SeenFile seenFile)
    {
        DataDirectory = dataDirectory;
        this.statusReader = statusReader;
        this.seenFile = seenFile;
        databasePath = Path.Combine(dataDirectory, "findings.db");
        lastNotifiedId = seenFile.Load();
    }

    /// <inheritdoc />
    public event PropertyChangedEventHandler? PropertyChanged;

    /// <summary>Raised when new findings should be shown as a pop-up: title and text.</summary>
    public event Action<string, string>? ToastRequested;

    /// <summary>Data folder of the service.</summary>
    public string DataDirectory { get; }

    /// <summary>The findings, newest first.</summary>
    public ObservableCollection<FindingRow> Findings { get; } = [];

    /// <summary>The profiles in lockdown.</summary>
    public ObservableCollection<LockdownLine> Lockdowns { get; } = [];

    /// <summary>Icon, tooltip and the two lines at the top.</summary>
    public TrayState State
    {
        get => state;
        private set
        {
            if (state != value)
            {
                state = value;
                Changed(nameof(State));
                Changed(nameof(HasLockdowns));
            }
        }
    }

    /// <summary>Why the findings could not be read, or empty.</summary>
    public string Problem
    {
        get => problem;
        private set
        {
            if (problem != value)
            {
                problem = value;
                Changed(nameof(Problem));
            }
        }
    }

    /// <summary>True if a profile is in lockdown.</summary>
    public bool HasLockdowns => Lockdowns.Count > 0;

    /// <summary>The user is looking at the list: what is in it counts as seen.</summary>
    public void MarkSeen()
    {
        if (unseen > 0)
        {
            unseen = 0;
            Refresh();
        }
    }

    /// <summary>Reads status and findings anew and announces findings that are new.</summary>
    /// <param name="windowIsOpen">The user has the list in front of them: new findings count as seen at once.</param>
    public void Refresh(bool windowIsOpen = false)
    {
        var status = statusReader.Read();
        try
        {
            Announce(status);
            Replace(Findings, FindingReader.ReadNewest(databasePath, ListLength));
            Problem = string.Empty;
        }
        catch (Exception ex) when (ex is SqliteException or IOException or UnauthorizedAccessException)
        {
            Problem = $"The findings cannot be read right now: {ex.Message}";
        }

        if (windowIsOpen)
        {
            unseen = 0;
        }

        // A lockdown state that cannot be read locks every profile; one release command clears it.
        IReadOnlyList<LockdownLine> lockdowns = status.LockdownProblem is not null
            ? [new LockdownLine(ReleaseAction.EveryProfile, "Every profile: the lockdown state cannot be read.")]
            : [.. status.Locked.Select(entry => new LockdownLine(entry.Profile, TrayState.Describe(entry)))];
        Replace(Lockdowns, lockdowns);
        Changed(nameof(HasLockdowns));
        State = TrayState.From(status, unseen);
    }

    private void Announce(GuardStatus status)
    {
        var newest = FindingReader.MaxId(databasePath);
        if (lastNotifiedId is null)
        {
            // The very first start for this user: what is already there is history, not news.
            lastNotifiedId = newest;
            seenFile.Save(newest);
            return;
        }

        if (newest < lastNotifiedId)
        {
            // A new database (RCEGuard was installed anew): everything in it is new.
            lastNotifiedId = 0;
        }

        if (newest == lastNotifiedId)
        {
            return;
        }

        var fresh = FindingReader.ReadAfter(databasePath, lastNotifiedId.Value).Where(finding => finding.Notifies).ToList();
        lastNotifiedId = newest;
        seenFile.Save(newest);
        if (fresh.Count == 0)
        {
            return;
        }

        unseen += fresh.Count;
        if (status.ToastEnabled)
        {
            var (title, text) = ToastText.For(fresh);
            ToastRequested?.Invoke(title, text);
        }
    }

    private static void Replace<T>(ObservableCollection<T> target, IReadOnlyList<T> items)
    {
        if (target.SequenceEqual(items))
        {
            return;
        }

        target.Clear();
        foreach (var item in items)
        {
            target.Add(item);
        }
    }

    private void Changed(string name) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));
}
