using System.Globalization;

namespace RCEGuard.Core.Rules;

/// <summary>
/// Turns a scan into one finding. Right after its start the real client opens every running
/// program to read its memory (seen 2026-11-15: 36 programs within a second, what the concept
/// expected of an anti-cheat scan). One log entry per program buries everything else, so the
/// entries of one burst are held back and reported together: how many programs, how many
/// accesses, and a few names.
/// Only R7 findings that are merely logged are bundled. A finding that alerts (the client opened
/// a program with rights to change it) passes at once and untouched.
/// Two times count. The times of the events tell two scans apart (also in a replayed file, and
/// when the guard reads up on what it missed). The times the findings arrived decide when a held
/// burst is reported: events read up on are old, but more of the same scan may still be on the way.
/// It keeps no clock of its own, so it can be tested. Not thread-safe.
/// </summary>
public sealed class ScanBundler
{
    /// <summary>How many program names a bundled finding lists before it says "and N more".</summary>
    public const int NamesShown = 5;

    private readonly TimeSpan quiet;
    private readonly TimeSpan longest;
    private readonly Dictionary<(string Profile, int? ProcessId), Burst> bursts = [];

    /// <summary>Creates the bundler.</summary>
    /// <param name="quiet">A burst is over when nothing was added to it for this long.</param>
    /// <param name="longest">A burst is reported after this long even if it has not ended.</param>
    public ScanBundler(TimeSpan quiet, TimeSpan longest)
    {
        this.quiet = quiet;
        this.longest = longest;
    }

    /// <summary>True while findings are held back: someone has to call <see cref="Flush"/> soon.</summary>
    public bool HasPending => bursts.Count > 0;

    /// <summary>
    /// Takes one finding. Returns what is to be reported now: the finding itself if it is not
    /// part of a scan, and before it a burst of the same client that ended earlier.
    /// </summary>
    /// <param name="finding">The finding.</param>
    /// <param name="arrived">When it arrived (the clock of <see cref="Flush"/>); without it, the time of the event.</param>
    public IReadOnlyList<Finding> Add(Finding finding, DateTimeOffset? arrived = null)
    {
        if (finding.RuleId != "R7" || finding.Action != FindingAction.Log)
        {
            return [finding];
        }

        var key = (finding.Profile, finding.ProcessId);
        List<Finding>? ended = null;
        if (bursts.TryGetValue(key, out var burst) && (finding.Time - burst.Last >= quiet || finding.Time - burst.First >= longest))
        {
            // By the times of the events: this is what keeps two scans in a replayed file apart.
            bursts.Remove(key);
            ended = [burst.ToFinding()];
            burst = null;
        }

        if (burst is null)
        {
            burst = new Burst(finding, arrived ?? finding.Time);
            bursts[key] = burst;
        }
        else
        {
            burst.Take(finding, arrived ?? finding.Time);
        }

        return ended ?? (IReadOnlyList<Finding>)[];
    }

    /// <summary>Returns the bursts nothing has arrived for by <paramref name="now"/>, as one finding each.</summary>
    public IReadOnlyList<Finding> Flush(DateTimeOffset now)
    {
        List<Finding>? ended = null;
        foreach (var (key, burst) in bursts.ToList())
        {
            if (now - burst.Touched >= quiet || now - burst.Arrived >= longest)
            {
                bursts.Remove(key);
                (ended ??= []).Add(burst.ToFinding());
            }
        }

        return ended ?? (IReadOnlyList<Finding>)[];
    }

    /// <summary>Returns everything that is held back, whether it has ended or not (end of a replay, the guard stops).</summary>
    public IReadOnlyList<Finding> FlushAll()
    {
        var all = bursts.Values.Select(burst => burst.ToFinding()).ToList();
        bursts.Clear();
        return all;
    }

    private sealed class Burst
    {
        private readonly Finding first;
        private readonly List<string> programs = [];
        private readonly HashSet<string> seen = new(StringComparer.OrdinalIgnoreCase);
        private readonly List<string> rights = [];
        private bool readsMemory;
        private int accesses;
        private long lastRecord;

        public Burst(Finding finding, DateTimeOffset arrived)
        {
            first = finding;
            First = finding.Time;
            Arrived = arrived;
            Take(finding, arrived);
        }

        /// <summary>Time of the first event.</summary>
        public DateTimeOffset First { get; }

        /// <summary>Time of the newest event.</summary>
        public DateTimeOffset Last { get; private set; }

        /// <summary>When the first finding arrived.</summary>
        public DateTimeOffset Arrived { get; }

        /// <summary>When the newest finding arrived.</summary>
        public DateTimeOffset Touched { get; private set; }

        public void Take(Finding finding, DateTimeOffset arrived)
        {
            accesses++;
            if (arrived > Touched)
            {
                Touched = arrived;
            }

            if (finding.Time > Last)
            {
                Last = finding.Time;
            }

            lastRecord = Math.Max(lastRecord, finding.RecordId);
            if (seen.Add(finding.Target))
            {
                programs.Add(finding.Target);
            }

            if (finding.Detail.Length > 0 && !rights.Contains(finding.Detail, StringComparer.OrdinalIgnoreCase) && rights.Count < 8)
            {
                rights.Add(finding.Detail);
            }

            readsMemory |= ProcessAccessRules.Classify(finding.Detail) == ProcessAccessKind.ReadsMemory;
        }

        public Finding ToFinding()
        {
            // One program opened once is no scan: it is reported as it came.
            if (accesses == 1)
            {
                return first;
            }

            var names = programs.Take(NamesShown).Select(FileName).ToList();
            var more = programs.Count - names.Count;
            var seconds = Math.Max(1, (int)Math.Ceiling((Last - First).TotalSeconds));
            var what = readsMemory ? "to read their memory" : "without reading or changing them";
            var which = programs.Count == 1 ? "another program" : $"{programs.Count} other programs";
            if (programs.Count == 1)
            {
                what = readsMemory ? "to read its memory" : "without reading or changing it";
            }

            var summary = string.Create(
                CultureInfo.InvariantCulture,
                $"The game client opened {which} {what} ({string.Join(", ", rights)}; {accesses} accesses within {seconds} s): {string.Join(", ", names)}{(more > 0 ? $" and {more} more" : string.Empty)}");
            return first with
            {
                Severity = readsMemory ? Severity.Medium : Severity.Info,
                Summary = summary,
                Target = programs.Count == 1 ? programs[0] : $"{programs.Count} programs",
                Detail = string.Join(", ", rights),
                RecordId = lastRecord,
            };
        }

        private static string FileName(string path)
        {
            var cut = path.LastIndexOf('\\');
            return cut < 0 || cut == path.Length - 1 ? path : path[(cut + 1)..];
        }
    }
}
