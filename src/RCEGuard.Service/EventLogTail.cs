using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.Text.Json;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service;

/// <summary>One event as delivered by the log: its XML and its place in the log.</summary>
/// <param name="Xml">The event as XML.</param>
/// <param name="Position">Record id and time of the event.</param>
public sealed record LogEntry(string Xml, LogPosition Position);

/// <summary>
/// Reads an event log from a given record on: first what is already in the log after that record,
/// in order, then every new event as it is written.
/// </summary>
public sealed class EventLogTail : IDisposable
{
    private readonly EventLogWatcher watcher;
    private readonly Action<LogEntry> onEntry;
    private readonly Action<Exception> onError;

    /// <summary>Prepares reading <paramref name="logName"/> after the record <paramref name="afterRecordId"/>.</summary>
    /// <param name="logName">Name of the log (channel).</param>
    /// <param name="afterRecordId">Only events with a higher record id are delivered.</param>
    /// <param name="onEntry">Called for every event, on a thread of the log subscription.</param>
    /// <param name="onError">Called when the subscription breaks (log removed, access lost).</param>
    public EventLogTail(string logName, long afterRecordId, Action<LogEntry> onEntry, Action<Exception> onError)
    {
        this.onEntry = onEntry;
        this.onError = onError;
        var query = new EventLogQuery(logName, PathType.LogName, RecordsAfter(afterRecordId));
        watcher = new EventLogWatcher(query, bookmark: null, readExistingEvents: true);
        watcher.EventRecordWritten += OnEventRecordWritten;
    }

    /// <summary>Starts delivering events.</summary>
    public void Start() => watcher.Enabled = true;

    /// <summary>
    /// Returns the oldest and the newest event of a log, or null if the log is empty. Throws if the
    /// log does not exist or cannot be read, which the watcher itself would accept silently.
    /// </summary>
    public static (LogPosition Oldest, LogPosition Newest)? Range(string logName)
    {
        var oldest = First(new EventLogQuery(logName, PathType.LogName, "*"));
        var newest = First(new EventLogQuery(logName, PathType.LogName, "*") { ReverseDirection = true });
        return oldest is null || newest is null ? null : (oldest, newest);
    }

    /// <summary>Returns the time of the event with this record id, or null if the log has no such event.</summary>
    public static DateTimeOffset? TimeOf(string logName, long recordId)
    {
        var query = new EventLogQuery(logName, PathType.LogName, $"*[System[EventRecordID={recordId.ToString(CultureInfo.InvariantCulture)}]]");
        return First(query)?.TimeCreated;
    }

    /// <inheritdoc />
    public void Dispose()
    {
        watcher.EventRecordWritten -= OnEventRecordWritten;
        watcher.Dispose();
    }

    private static string RecordsAfter(long recordId) =>
        $"*[System[EventRecordID > {recordId.ToString(CultureInfo.InvariantCulture)}]]";

    private static LogPosition? First(EventLogQuery query)
    {
        using var reader = new EventLogReader(query);
        using var record = reader.ReadEvent();
        return record is null ? null : PositionOf(record);
    }

    private static LogPosition PositionOf(EventRecord record) =>
        new(record.RecordId ?? 0, record.TimeCreated is { } time ? new DateTimeOffset(time.ToUniversalTime()) : DateTimeOffset.MinValue);

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null)
        {
            onError(args.EventException);
            return;
        }

        using var record = args.EventRecord;
        if (record is not null)
        {
            onEntry(new LogEntry(record.ToXml(), PositionOf(record)));
        }
    }
}

/// <summary>
/// Keeps the position of the last handled event in a small file, so that a restarted guard reads
/// what was written while it was not running.
/// </summary>
public sealed class LogPositionFile
{
    private readonly string path;

    /// <summary>Creates the store for the file at <paramref name="path"/>.</summary>
    public LogPositionFile(string path) => this.path = path;

    /// <summary>Path of the file.</summary>
    public string Path => path;

    /// <summary>
    /// Reads the saved position. Returns null if there is none; a file that cannot be understood
    /// counts as none and is reported through <paramref name="problem"/>.
    /// </summary>
    public LogPosition? Load(out string? problem)
    {
        problem = null;
        if (!File.Exists(path))
        {
            return null;
        }

        try
        {
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var recordId = document.RootElement.GetProperty("recordId").GetInt64();
            var time = DateTimeOffset.Parse(
                document.RootElement.GetProperty("timeCreatedUtc").GetString()!, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
            if (recordId < 0)
            {
                throw new FormatException("recordId is negative");
            }

            return new LogPosition(recordId, time);
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or FormatException or InvalidOperationException or ArgumentNullException or IOException or UnauthorizedAccessException)
        {
            problem = ex.Message;
            return null;
        }
    }

    /// <summary>Saves the position. The file is replaced in one step, so it is never half written.</summary>
    public void Save(LogPosition position)
    {
        var json = JsonSerializer.Serialize(new Dictionary<string, object>
        {
            ["recordId"] = position.RecordId,
            ["timeCreatedUtc"] = position.TimeCreated.UtcDateTime.ToString("O", CultureInfo.InvariantCulture),
        });
        var temporary = path + ".tmp";
        File.WriteAllText(temporary, json);
        File.Move(temporary, path, overwrite: true);
    }
}
