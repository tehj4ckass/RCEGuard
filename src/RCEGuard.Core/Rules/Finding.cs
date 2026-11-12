namespace RCEGuard.Core.Rules;

/// <summary>How serious a finding is.</summary>
public enum Severity
{
    /// <summary>Recorded for later review, not suspicious on its own.</summary>
    Info,

    /// <summary>Unusual; recorded, no alert.</summary>
    Medium,

    /// <summary>Suspicious; the user is alerted.</summary>
    High,

    /// <summary>The client did something it never does; alert and, where configured, terminate.</summary>
    Critical,
}

/// <summary>What the service should do with a finding.</summary>
public enum FindingAction
{
    /// <summary>Write it to the log only.</summary>
    Log,

    /// <summary>Log it and alert the user.</summary>
    Alert,

    /// <summary>Log, alert and terminate the processes in <see cref="Finding.KillTargets"/>.</summary>
    Kill,
}

/// <summary>A process to terminate, identified by pid and the image it must still have.</summary>
/// <param name="ProcessId">Process id from the event.</param>
/// <param name="Image">Full image path from the event; the service only kills if the pid still runs this image.</param>
/// <param name="IncludeDescendants">Also terminate everything the process started.</param>
public sealed record KillTarget(int ProcessId, string Image, bool IncludeDescendants);

/// <summary>The result of a rule that matched an event.</summary>
public sealed record Finding
{
    /// <summary>Rule id from the concept: R1 ... R9.</summary>
    public required string RuleId { get; init; }

    /// <summary>Severity of the finding.</summary>
    public required Severity Severity { get; init; }

    /// <summary>What the service should do.</summary>
    public required FindingAction Action { get; init; }

    /// <summary>One English sentence for the user.</summary>
    public required string Summary { get; init; }

    /// <summary>Name of the client profile, empty if the event is not tied to a client.</summary>
    public string Profile { get; init; } = string.Empty;

    /// <summary>Image of the process that caused the event.</summary>
    public string Image { get; init; } = string.Empty;

    /// <summary>Pid of the process that caused the event, if known.</summary>
    public int? ProcessId { get; init; }

    /// <summary>What was touched: remote address, file, registry key, module or other process.</summary>
    public string Target { get; init; } = string.Empty;

    /// <summary>Command line, for process events.</summary>
    public string CommandLine { get; init; } = string.Empty;

    /// <summary>Processes to terminate when <see cref="Action"/> is <see cref="FindingAction.Kill"/>.</summary>
    public IReadOnlyList<KillTarget> KillTargets { get; init; } = [];

    /// <summary>Time of the event.</summary>
    public DateTimeOffset Time { get; init; }

    /// <summary>Event log record id of the event.</summary>
    public long RecordId { get; init; }
}
