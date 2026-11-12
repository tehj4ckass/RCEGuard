namespace RCEGuard.Core.Rules;

/// <summary>What the debouncer decided about one finding.</summary>
/// <param name="Report">True: report the finding. False: it repeats a reported one and was only counted.</param>
/// <param name="Entry">The entry of the report this finding belongs to; null if the finding is not tracked.</param>
/// <param name="RepeatsBefore">
/// For a reported finding: how often the same finding was held back during the previous window.
/// </param>
public readonly record struct DebounceDecision(bool Report, FindingDebouncer.Entry? Entry, int RepeatsBefore);

/// <summary>
/// Keeps repeated findings from flooding log and alerts: within a time window the same finding
/// (same rule, severity, action, client process and target) is reported once and counted after that.
/// Findings that terminate a process always pass: the action must be taken every time.
/// Time is the time of the events, so a replay behaves like the live run. Not thread-safe.
/// </summary>
public sealed class FindingDebouncer
{
    private readonly TimeSpan window;
    private readonly int capacity;
    private readonly Dictionary<Key, Entry> entries = [];

    /// <summary>Creates a debouncer. A window of zero lets everything pass.</summary>
    /// <param name="window">How long a repeated finding is only counted after its first report.</param>
    /// <param name="capacity">Upper limit of remembered findings.</param>
    public FindingDebouncer(TimeSpan window, int capacity = 2048)
    {
        this.window = window < TimeSpan.Zero ? TimeSpan.Zero : window;
        this.capacity = Math.Max(1, capacity);
    }

    /// <summary>Decides whether a finding is reported or counted as a repeat.</summary>
    public DebounceDecision Check(Finding finding)
    {
        if (window == TimeSpan.Zero || finding.Action == FindingAction.Kill)
        {
            return new DebounceDecision(Report: true, Entry: null, RepeatsBefore: 0);
        }

        var key = new Key(finding.RuleId, finding.Severity, finding.Action, finding.Profile, finding.ProcessId, finding.Target.ToUpperInvariant());
        var repeatsBefore = 0;
        if (entries.TryGetValue(key, out var known))
        {
            // An event that is older than the report (log order is not strictly time order) is a repeat too.
            if (finding.Time - known.First < window)
            {
                known.Repeats++;
                if (finding.Time > known.Last)
                {
                    known.Last = finding.Time;
                }

                return new DebounceDecision(Report: false, known, RepeatsBefore: 0);
            }

            repeatsBefore = known.Repeats;
        }
        else if (entries.Count >= capacity)
        {
            MakeRoom(finding.Time);
        }

        var entry = new Entry { First = finding.Time, Last = finding.Time };
        entries[key] = entry;
        return new DebounceDecision(Report: true, entry, repeatsBefore);
    }

    private void MakeRoom(DateTimeOffset now)
    {
        foreach (var expired in entries.Where(pair => now - pair.Value.First >= window).Select(pair => pair.Key).ToList())
        {
            entries.Remove(expired);
        }

        if (entries.Count >= capacity)
        {
            entries.Clear(); // Bounded on purpose; the cost is one extra report per finding.
        }
    }

    /// <summary>A reported finding and the repeats counted for it.</summary>
    public sealed class Entry
    {
        /// <summary>Time of the reported finding.</summary>
        public DateTimeOffset First { get; internal set; }

        /// <summary>Time of the latest repeat.</summary>
        public DateTimeOffset Last { get; internal set; }

        /// <summary>How often the finding repeated since the report.</summary>
        public int Repeats { get; internal set; }

        /// <summary>Free for the caller, e.g. the database row of the report.</summary>
        public long Tag { get; set; }
    }

    private readonly record struct Key(string RuleId, Severity Severity, FindingAction Action, string Profile, int? ProcessId, string Target);
}
