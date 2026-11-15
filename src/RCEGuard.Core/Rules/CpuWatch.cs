using System.Globalization;

namespace RCEGuard.Core.Rules;

/// <summary>What <see cref="CpuWatch"/> made of one sample.</summary>
/// <param name="Cores">
/// Processor cores the process used on average over the window (1.0 = one core fully busy), or
/// null while the process has not been watched for a whole window yet.
/// </param>
/// <param name="Alert">True when the load has just risen above the threshold: once per stretch of high load.</param>
public readonly record struct CpuVerdict(double? Cores, bool Alert);

/// <summary>
/// R8: a client that keeps several processor cores busy for minutes. The 3.3.5a client works
/// mostly on one core; code that mines in it takes all it can get. Fed with the processor time
/// of each client at intervals, it says when the average over a window is above the threshold.
/// It keeps no clock of its own, so it can be tested. Not thread-safe.
/// </summary>
public sealed class CpuWatch
{
    private readonly double thresholdCores;
    private readonly TimeSpan window;
    private readonly Dictionary<string, State> processes = new(StringComparer.Ordinal);

    /// <summary>Creates the watch.</summary>
    /// <param name="thresholdCores">Average number of busy cores above which the load is reported.</param>
    /// <param name="window">The time the average is taken over.</param>
    public CpuWatch(double thresholdCores, TimeSpan window)
    {
        this.thresholdCores = thresholdCores;
        this.window = window;
    }

    /// <summary>Takes one sample of a process.</summary>
    /// <param name="key">Identifies the process (not just its pid: pids are reused).</param>
    /// <param name="now">Time of the sample.</param>
    /// <param name="cpuTime">Processor time the process has used since it started.</param>
    public CpuVerdict Sample(string key, DateTimeOffset now, TimeSpan cpuTime)
    {
        if (!processes.TryGetValue(key, out var state))
        {
            state = new State();
            processes[key] = state;
        }

        // Processor time never goes back, and neither does the clock: if either does, start over.
        if (state.Samples.Count > 0 && (cpuTime < state.Samples[^1].Cpu || now <= state.Samples[^1].Time))
        {
            state.Samples.Clear();
            state.Reported = false;
        }

        state.Samples.Add((now, cpuTime));

        // Keep exactly one sample that is at least a window old: the one the average starts from.
        while (state.Samples.Count > 1 && now - state.Samples[1].Time >= window)
        {
            state.Samples.RemoveAt(0);
        }

        var (startTime, startCpu) = state.Samples[0];
        var elapsed = now - startTime;
        if (elapsed < window)
        {
            return new CpuVerdict(null, false);
        }

        var cores = (cpuTime - startCpu).TotalSeconds / elapsed.TotalSeconds;
        if (cores <= thresholdCores)
        {
            state.Reported = false;
            return new CpuVerdict(cores, false);
        }

        var alert = !state.Reported;
        state.Reported = true;
        return new CpuVerdict(cores, alert);
    }

    /// <summary>Forgets a process that has ended.</summary>
    public void Forget(string key) => processes.Remove(key);

    /// <summary>The finding for a client whose load has risen above the threshold.</summary>
    /// <param name="profile">Name of the profile of the client.</param>
    /// <param name="image">Full path of the client.</param>
    /// <param name="processId">Pid of the client.</param>
    /// <param name="cores">The average load in cores.</param>
    /// <param name="now">Time of the sample.</param>
    public Finding ToFinding(string profile, string image, int processId, double cores, DateTimeOffset now) => new()
    {
        RuleId = "R8",
        Severity = Severity.Medium,
        Action = FindingAction.Alert,
        Summary = string.Create(
            CultureInfo.InvariantCulture,
            $"The game client kept {cores:0.0} processor cores busy on average over the last {Describe(window)} (alert above {thresholdCores:0.0})"),
        Profile = profile,
        Image = image,
        ProcessId = processId,
        Target = "processor load",
        Time = now,
    };

    private static string Describe(TimeSpan time) => time.TotalSeconds >= 120 && time.TotalSeconds % 60 == 0
        ? string.Create(CultureInfo.InvariantCulture, $"{time.TotalMinutes:0} min")
        : string.Create(CultureInfo.InvariantCulture, $"{time.TotalSeconds:0} s");

    private sealed class State
    {
        public List<(DateTimeOffset Time, TimeSpan Cpu)> Samples { get; } = [];

        public bool Reported { get; set; }
    }
}
