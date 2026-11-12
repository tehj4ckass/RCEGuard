using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// A log of the same kind as the one of Sysmon (written by a provider with a manifest) that a
/// normal user can read and add events to: every start of Windows PowerShell 5.1 writes a few
/// events to it. The Application log is of another kind and behaves differently: a subscription
/// that asks for <c>EventRecordID &gt; N</c> keeps delivering new events there, but not here.
/// </summary>
internal static class ManifestLog
{
    public const string Name = "Microsoft-Windows-PowerShell/Operational";

    /// <summary>Makes Windows write new events to the log and returns the newest event from before.</summary>
    public static LogPosition WriteEvents()
    {
        var before = EventLogTail.Newest(Name);
        Assert.True(before is not null, $"the log {Name} is empty or cannot be read");
        var powershell = Path.Combine(Environment.SystemDirectory, @"WindowsPowerShell\v1.0\powershell.exe");
        using var process = Process.Start(new ProcessStartInfo(powershell, "-NoProfile -NonInteractive -Command exit") { UseShellExecute = false, CreateNoWindow = true })!;
        Assert.True(process.WaitForExit(30_000), "Windows PowerShell did not end");

        var watch = Stopwatch.StartNew();
        while (EventLogTail.Newest(Name)!.RecordId == before.RecordId && watch.ElapsedMilliseconds < 5000)
        {
            Thread.Sleep(50);
        }

        Assert.True(EventLogTail.Newest(Name)!.RecordId > before.RecordId, $"starting Windows PowerShell wrote nothing to {Name}; this test needs that");
        return before;
    }

    /// <summary>The newest events of a log, oldest of them first.</summary>
    public static List<LogPosition> ReadNewest(string log, int count)
    {
        var positions = new List<LogPosition>();
        using var reader = new EventLogReader(new EventLogQuery(log, PathType.LogName, "*") { ReverseDirection = true });
        while (positions.Count < count && reader.ReadEvent() is { } record)
        {
            using (record)
            {
                positions.Add(new LogPosition(record.RecordId ?? 0, new DateTimeOffset(record.TimeCreated!.Value.ToUniversalTime())));
            }
        }

        positions.Reverse();
        return positions;
    }
}

/// <summary>
/// Events written after the subscription started. This is the case the Application log cannot
/// show (see <see cref="ManifestLog"/>): the first build with a saved position passed all tests
/// against the Application log and delivered no new event from the Sysmon log.
/// </summary>
public sealed class EventLogTailLiveTests
{
    [Theory]
    [InlineData(0)]
    [InlineData(5)]
    public void Events_written_after_the_start_are_delivered_after_the_ones_already_there(int alreadyThere)
    {
        var recent = ManifestLog.ReadNewest(ManifestLog.Name, alreadyThere + 1);
        Assert.True(recent.Count == alreadyThere + 1, $"the log {ManifestLog.Name} holds too few events");
        var saved = recent[0];
        var pending = recent.Skip(1).Select(p => p.RecordId).ToList();

        var received = new ConcurrentQueue<LogEntry>();
        using var tail = new EventLogTail(ManifestLog.Name, saved.RecordId, received.Enqueue, _ => { });
        tail.Start();
        Thread.Sleep(300);
        var before = ManifestLog.WriteEvents();
        var written = EventLogTail.Newest(ManifestLog.Name)!.RecordId;
        var watch = Stopwatch.StartNew();
        while (!received.Any(e => e.Position.RecordId >= written) && watch.ElapsedMilliseconds < 10_000)
        {
            Thread.Sleep(50);
        }

        var ids = received.Select(e => e.Position.RecordId).ToList();
        Assert.Equal(pending, ids.Take(pending.Count));
        Assert.Contains(ids, id => id > before.RecordId);
        Assert.Contains(written, ids);
        Assert.Equal(ids.OrderBy(id => id), ids);
        Assert.Equal(ids.Count, ids.Distinct().Count());
        Assert.All(ids, id => Assert.True(id > saved.RecordId));
    }

    [Fact]
    public void A_position_that_is_not_in_the_log_reads_the_log_from_its_oldest_event()
    {
        var range = EventLogTail.Range(ManifestLog.Name);
        Assert.NotNull(range);

        var received = new ConcurrentQueue<LogEntry>();
        using var tail = new EventLogTail(ManifestLog.Name, range.Value.Oldest.RecordId - 1, received.Enqueue, _ => { });
        tail.Start();
        var watch = Stopwatch.StartNew();
        while (received.IsEmpty && watch.ElapsedMilliseconds < 10_000)
        {
            Thread.Sleep(50);
        }

        // The log may drop its oldest events at any time; then the first one delivered is a little later.
        Assert.True(received.TryPeek(out var first), "nothing was delivered");
        Assert.InRange(first.Position.RecordId, range.Value.Oldest.RecordId, range.Value.Oldest.RecordId + 500);
    }
}

/// <summary>
/// Reading a log from a saved position on. The Sysmon log needs administrator rights, so these
/// tests read the Application log of this machine instead. They only read; nothing is written.
/// Events written after the start are covered by <see cref="EventLogTailLiveTests"/>.
/// </summary>
public sealed class EventLogTailTests
{
    private const string Log = "Application";

    [Fact]
    public void The_range_of_a_log_names_its_oldest_and_newest_event()
    {
        var range = EventLogTail.Range(Log);

        Assert.NotNull(range);
        Assert.True(range.Value.Oldest.RecordId > 0);
        Assert.True(range.Value.Newest.RecordId >= range.Value.Oldest.RecordId);
        Assert.True(range.Value.Newest.TimeCreated >= range.Value.Oldest.TimeCreated);
    }

    [Fact]
    public void A_log_that_does_not_exist_is_an_error_and_not_an_empty_log()
    {
        Assert.Throws<EventLogNotFoundException>(() => EventLogTail.Range("RCEGuard-No-Such-Log/Operational"));
    }

    [Fact]
    public void The_time_of_a_record_is_found_by_its_id()
    {
        var newest = EventLogTail.Range(Log)!.Value.Newest;

        Assert.Equal(newest.TimeCreated, EventLogTail.TimeOf(Log, newest.RecordId));
        Assert.Null(EventLogTail.TimeOf(Log, newest.RecordId + 1_000_000_000));
    }

    [Fact]
    public void Events_already_in_the_log_after_the_position_are_delivered_first_and_in_order()
    {
        // The position "five events ago": what a guard would have saved before it stopped.
        var expected = ReadNewest(6);
        Assert.True(expected.Count == 6, "the Application log holds fewer than six events");
        var saved = expected[0];
        var pending = expected.Skip(1).Select(p => p.RecordId).ToList();

        var received = new ConcurrentQueue<LogEntry>();
        using var tail = new EventLogTail(Log, saved.RecordId, received.Enqueue, _ => { });
        tail.Start();
        var watch = Stopwatch.StartNew();
        while (received.Count < pending.Count && watch.ElapsedMilliseconds < 10_000)
        {
            Thread.Sleep(50);
        }

        var first = received.Take(pending.Count).ToList();
        Assert.Equal(pending, first.Select(e => e.Position.RecordId));
        Assert.All(first, entry => Assert.StartsWith("<Event", entry.Xml));
        Assert.All(first, entry => Assert.True(SysmonEventParser.TryParse(entry.Xml, out var parsed, out _) && parsed!.RecordId == entry.Position.RecordId));
    }

    [Fact]
    public void Nothing_is_delivered_when_the_position_is_the_newest_event()
    {
        var newest = EventLogTail.Range(Log)!.Value.Newest;

        var received = new ConcurrentQueue<LogEntry>();
        using var tail = new EventLogTail(Log, newest.RecordId, received.Enqueue, _ => { });
        tail.Start();
        Thread.Sleep(500);

        // Another program may write to the Application log during the test; what was there before must not come.
        Assert.All(received, entry => Assert.True(entry.Position.RecordId > newest.RecordId));
    }

    /// <summary>The newest events of the log, oldest of them first.</summary>
    private static List<LogPosition> ReadNewest(int count)
    {
        var positions = new List<LogPosition>();
        using var reader = new EventLogReader(new EventLogQuery(Log, PathType.LogName, "*") { ReverseDirection = true });
        while (positions.Count < count && reader.ReadEvent() is { } record)
        {
            using (record)
            {
                positions.Add(new LogPosition(record.RecordId ?? 0, new DateTimeOffset(record.TimeCreated!.Value.ToUniversalTime())));
            }
        }

        positions.Reverse();
        return positions;
    }
}

public sealed class LogPositionFileTests : IDisposable
{
    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-position-").FullName;

    public void Dispose() => Directory.Delete(folder, recursive: true);

    private LogPositionFile File => new(Path.Combine(folder, "sysmon-position.json"));

    [Fact]
    public void A_saved_position_is_read_back_exactly()
    {
        var position = new LogPosition(4318, new DateTimeOffset(2026, 11, 12, 18, 10, 55, TimeSpan.Zero).AddTicks(1863421));

        File.Save(position);
        File.Save(position with { RecordId = 4319 });

        Assert.Equal(position with { RecordId = 4319 }, File.Load(out var problem));
        Assert.Null(problem);
        Assert.Equal(["sysmon-position.json"], Directory.GetFiles(folder).Select(Path.GetFileName));
    }

    [Fact]
    public void No_file_is_no_position_and_no_problem()
    {
        Assert.Null(File.Load(out var problem));
        Assert.Null(problem);
    }

    [Theory]
    [InlineData("")]
    [InlineData("{")]
    [InlineData("{\"recordId\":12}")]
    [InlineData("{\"recordId\":\"twelve\",\"timeCreatedUtc\":\"2026-11-12T18:10:55Z\"}")]
    [InlineData("{\"recordId\":12,\"timeCreatedUtc\":\"yesterday\"}")]
    [InlineData("{\"recordId\":-1,\"timeCreatedUtc\":\"2026-11-12T18:10:55Z\"}")]
    public void A_damaged_file_is_no_position_but_a_problem(string content)
    {
        System.IO.File.WriteAllText(File.Path, content);

        Assert.Null(File.Load(out var problem));
        Assert.False(string.IsNullOrEmpty(problem));
    }
}
