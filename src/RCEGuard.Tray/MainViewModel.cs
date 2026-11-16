using System.Collections.ObjectModel;
using System.ComponentModel;
using Microsoft.Data.Sqlite;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Learning;
using RCEGuard.Core.State;
using RCEGuard.Tray.Model;

namespace RCEGuard.Tray;

/// <summary>A profile in lockdown, as shown in the window.</summary>
internal sealed record LockdownLine(string Profile, string Text);

/// <summary>A profile in learning mode, as shown in the window.</summary>
/// <param name="Profile">Name of the profile.</param>
/// <param name="Text">One line: how much was noted so far.</param>
/// <param name="Report">Everything that was noted and what it suggests, as the service prints it with --learned.</param>
internal sealed record LearningLine(string Profile, string Text, string Report);

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
    private GuardMode? mode;
    private bool canSetMode;
    private readonly Func<DateTimeOffset> clock;
    private readonly List<FindingRow> heldBack = [];
    private DateTimeOffset lastToast = DateTimeOffset.MinValue;

    /// <summary>
    /// At most one pop-up in this time. Findings come in bursts (one thing the client does can set
    /// off several rules within seconds); a pop-up for each would cover the screen again and again.
    /// What arrives in the meantime is announced together afterwards.
    /// </summary>
    internal static readonly TimeSpan ToastPause = TimeSpan.FromSeconds(10);

    /// <summary>Creates the view model for a data folder.</summary>
    /// <param name="dataDirectory">Data folder of the service.</param>
    /// <param name="statusReader">Reads the status.</param>
    /// <param name="seenFile">Remembers which finding was announced last.</param>
    /// <param name="clock">The time; tests replace it.</param>
    public MainViewModel(string dataDirectory, StatusReader statusReader, SeenFile seenFile, Func<DateTimeOffset>? clock = null)
    {
        DataDirectory = dataDirectory;
        this.statusReader = statusReader;
        this.seenFile = seenFile;
        this.clock = clock ?? (() => DateTimeOffset.UtcNow);
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

    /// <summary>The profiles in learning mode.</summary>
    public ObservableCollection<LearningLine> Learning { get; } = [];

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

    /// <summary>The mode the configuration amounts to; null if it is none of the three or cannot be read.</summary>
    public GuardMode? Mode => mode;

    /// <summary>False if the configuration cannot be read: there is nothing a mode could be set in.</summary>
    public bool CanSetMode => canSetMode;

    /// <summary>One line next to the mode buttons: what the mode of now means.</summary>
    public string ModeHint => !canSetMode
        ? "The configuration cannot be read, so the mode is not known."
        : mode is { } current
            ? GuardModes.Describe(current)
            : "Mixed: learning is on for some profiles only, or together with \"killEnabled\": false. Choosing a mode sets it for every profile.";

    /// <summary>True if a profile is in lockdown.</summary>
    public bool HasLockdowns => Lockdowns.Count > 0;

    /// <summary>True if a profile is in learning mode.</summary>
    public bool HasLearning => Learning.Count > 0;

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
            Collect();
            ShowHeldBack(status);
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
        Replace(Learning, [.. status.Learning.Select(profile => Describe(profile, status))]);
        Changed(nameof(HasLearning));
        var readable = status.ConfigProblem is null;
        if (mode != status.Mode || canSetMode != readable)
        {
            mode = status.Mode;
            canSetMode = readable;
            Changed(nameof(Mode));
            Changed(nameof(CanSetMode));
            Changed(nameof(ModeHint));
        }

        State = TrayState.From(status, unseen);
    }

    /// <summary>The line and the full text for a profile in learning mode.</summary>
    private static LearningLine Describe(ClientProfile profile, GuardStatus status)
    {
        var notes = status.Learned?.FirstOrDefault(learned => string.Equals(learned.Profile, profile.Name, StringComparison.OrdinalIgnoreCase));
        if (notes is null)
        {
            return new LearningLine(
                profile.Name,
                $"'{profile.Name}': nothing noted yet.",
                $"Profile '{profile.Name}': learning mode is ON, nothing was noted yet. Play a session, then look again.");
        }

        var text =
            $"'{profile.Name}': {Count(notes.Sessions, "start")} of the client, {Count(notes.Remotes.Count, "connection target")}, " +
            $"{Count(notes.Programs.Count, "other program")} opened.";
        return new LearningLine(profile.Name, text, LearnedReport.Render(notes, profile, status.CpuAlertCores));
    }

    private static string Count(int number, string what) => number == 1 ? $"1 {what}" : $"{number} {what}s";

    /// <summary>Shows one pop-up for everything that is waiting, unless the last pop-up was a moment ago.</summary>
    private void ShowHeldBack(GuardStatus status)
    {
        if (heldBack.Count == 0)
        {
            return;
        }

        if (!status.ToastEnabled)
        {
            heldBack.Clear();
            return;
        }

        var now = clock();
        if (now - lastToast < ToastPause)
        {
            return;
        }

        lastToast = now;
        var (title, text) = ToastText.For(heldBack);
        heldBack.Clear();
        ToastRequested?.Invoke(title, text);
    }

    /// <summary>Takes in the findings that are new since the last look: they count as unseen and wait for their pop-up.</summary>
    private void Collect()
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
        heldBack.AddRange(fresh);
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
