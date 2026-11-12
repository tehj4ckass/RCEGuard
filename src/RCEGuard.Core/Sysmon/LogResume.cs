namespace RCEGuard.Core.Sysmon;

/// <summary>A place in the event log: the record id of an event and the time it was written.</summary>
/// <param name="RecordId">Record id of the event.</param>
/// <param name="TimeCreated">Time the event was written; tells a record apart from one with the same id in a replaced log.</param>
public sealed record LogPosition(long RecordId, DateTimeOffset TimeCreated);

/// <summary>How reading the log continues after a start of the guard.</summary>
public enum ResumeKind
{
    /// <summary>No saved position: only events written from now on are read.</summary>
    FirstStart,

    /// <summary>The saved position was found: everything written after it is read.</summary>
    Resume,

    /// <summary>The log was cleared or replaced since the position was saved: everything in it is read.</summary>
    LogReplaced,

    /// <summary>Events after the saved position were overwritten before they could be read: the rest is read.</summary>
    Overwritten,
}

/// <summary>Where to continue reading, and what that means for the events written in the meantime.</summary>
/// <param name="Kind">How the saved position relates to the log.</param>
/// <param name="StartAfterRecordId">Events with a higher record id are read.</param>
/// <param name="Pending">Events already in the log that will be read first.</param>
/// <param name="Lost">Events that were written after the saved position and are no longer in the log.</param>
public sealed record ResumePlan(ResumeKind Kind, long StartAfterRecordId, long Pending, long Lost);

/// <summary>Decides where the guard continues reading the event log.</summary>
public static class LogResume
{
    /// <summary>Two times this close are the same event (the saved time went through a text file).</summary>
    private static readonly TimeSpan SameEvent = TimeSpan.FromMilliseconds(1);

    /// <summary>
    /// Compares the saved position with the log as it is now.
    /// </summary>
    /// <param name="saved">Position of the last event the guard handled, or null if none was saved.</param>
    /// <param name="oldest">Oldest event in the log, or null if the log is empty.</param>
    /// <param name="newest">Newest event in the log, or null if the log is empty.</param>
    /// <param name="timeOfSavedRecord">
    /// Time of the event that has the saved record id now, or null if there is no such event.
    /// </param>
    public static ResumePlan Decide(LogPosition? saved, LogPosition? oldest, LogPosition? newest, DateTimeOffset? timeOfSavedRecord)
    {
        if (oldest is null || newest is null)
        {
            // An empty log: whatever comes is new. A saved position means the log was emptied.
            return new ResumePlan(saved is null ? ResumeKind.FirstStart : ResumeKind.LogReplaced, 0, 0, 0);
        }

        var inLog = newest.RecordId - oldest.RecordId + 1;
        if (saved is null)
        {
            // What happened before the guard was installed is not its business.
            return new ResumePlan(ResumeKind.FirstStart, newest.RecordId, 0, 0);
        }

        if (saved.RecordId > newest.RecordId)
        {
            // Record ids only grow: a log that ends before the saved one is another log.
            return new ResumePlan(ResumeKind.LogReplaced, oldest.RecordId - 1, inLog, 0);
        }

        if (saved.RecordId >= oldest.RecordId)
        {
            var same = timeOfSavedRecord is { } time && (time - saved.TimeCreated).Duration() <= SameEvent;
            return same
                ? new ResumePlan(ResumeKind.Resume, saved.RecordId, newest.RecordId - saved.RecordId, 0)
                : new ResumePlan(ResumeKind.LogReplaced, oldest.RecordId - 1, inLog, 0);
        }

        // The saved event itself is gone from the log. If the next one is still there, nothing was missed.
        var lost = oldest.RecordId - saved.RecordId - 1;
        return new ResumePlan(lost == 0 ? ResumeKind.Resume : ResumeKind.Overwritten, oldest.RecordId - 1, inLog, lost);
    }
}
