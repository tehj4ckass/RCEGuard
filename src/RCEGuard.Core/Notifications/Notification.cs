using RCEGuard.Core.Rules;

namespace RCEGuard.Core.Notifications;

/// <summary>How urgent a notification is. The names are the priorities of ntfy.</summary>
public enum NotificationPriority
{
    /// <summary>For the record; no sound.</summary>
    Low,

    /// <summary>An ordinary notification.</summary>
    Default,

    /// <summary>Should be looked at soon.</summary>
    High,

    /// <summary>Needs attention now.</summary>
    Urgent,
}

/// <summary>A message for the owner, sent outside the machine (ntfy) or shown on it (tray).</summary>
/// <param name="Title">One short line.</param>
/// <param name="Body">What happened and what RCEGuard did.</param>
/// <param name="Priority">How urgent it is.</param>
public sealed record Notification(string Title, string Body, NotificationPriority Priority);

/// <summary>Writes the notifications of RCEGuard.</summary>
public static class NotificationText
{
    /// <summary>True for findings the owner is told about: everything that alerts or terminates.</summary>
    public static bool Notifies(Finding finding) => finding.Action != FindingAction.Log;

    /// <summary>The notification for a finding.</summary>
    /// <param name="finding">The finding.</param>
    /// <param name="taken">What the guard did, as in the log line of the finding.</param>
    /// <param name="late">The event was written while the guard was not running.</param>
    /// <param name="computer">Name of this machine.</param>
    public static Notification ForFinding(Finding finding, string taken, bool late, string computer)
    {
        var severity = finding.Severity.ToString().ToUpperInvariant();
        var profile = finding.Profile.Length > 0 ? $" [{finding.Profile}]" : string.Empty;
        var lines = new List<string> { finding.Summary };
        if (finding.Action == FindingAction.Kill)
        {
            lines.Add($"Action: {taken}");
        }

        if (late)
        {
            lines.Add("This happened while RCEGuard was not running and was found afterwards.");
        }

        lines.Add($"{computer}, {finding.Time.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        var priority = finding.Severity == Severity.Critical ? NotificationPriority.Urgent : NotificationPriority.High;
        return new Notification($"RCEGuard: {finding.RuleId} {severity}{profile}", string.Join("\n", lines), priority);
    }

    /// <summary>The guard cannot do its work and ends.</summary>
    public static Notification CannotRun(string reason, string computer) =>
        new("RCEGuard cannot run", $"{reason}\nThe client is not watched until this is fixed.\n{computer}", NotificationPriority.Urgent);

    /// <summary>The guard found that it was not stopped the regular way last time.</summary>
    /// <param name="lastSeen">The last time the previous run is known to have been alive, if known.</param>
    /// <param name="computer">Name of this machine.</param>
    public static Notification EndedUnexpectedly(DateTimeOffset? lastSeen, string computer)
    {
        var when = lastSeen is { } time ? $" It was last alive at {time.ToLocalTime():yyyy-MM-dd HH:mm:ss}." : string.Empty;
        return new Notification(
            "RCEGuard was ended unexpectedly",
            $"RCEGuard did not stop the regular way (ended from outside, crashed, or the machine lost power).{when} " +
            $"It is running again and reads what happened in between.\n{computer}",
            NotificationPriority.High);
    }

    /// <summary>The guard is being stopped while a watched client is running.</summary>
    public static Notification StoppedWhileClientRuns(IEnumerable<string> clients, string computer) =>
        new(
            "RCEGuard is stopping while the client runs",
            $"RCEGuard is being stopped while {string.Join(", ", clients)} is running. The client is not watched from now on.\n{computer}",
            NotificationPriority.Urgent);

    /// <summary>The configuration of the guard was changed through one of its own commands (the mode, the allowlist).</summary>
    /// <param name="what">What was changed, as the command printed it.</param>
    /// <param name="computer">Name of this machine.</param>
    public static Notification ConfigChanged(string what, string computer) =>
        new("RCEGuard: configuration changed", $"{what}\n{computer}", NotificationPriority.High);

    /// <summary>A notification the owner asked for, to see that notifications arrive.</summary>
    public static Notification Test(string computer) =>
        new("RCEGuard: test notification", $"If you can read this, notifications of RCEGuard reach you.\n{computer}", NotificationPriority.Default);
}
