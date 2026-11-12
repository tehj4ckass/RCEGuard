using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// The guard loop across a stop and a start: it notes where it is in the log and reads what was
/// written in between. Runs against the Application log (read only), because the Sysmon log
/// needs administrator rights; its events match no rule, so nothing is reported or terminated.
/// </summary>
public sealed class GuardWorkerResumeTests : IDisposable
{
    private const string Log = "Application";
    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-worker-").FullName;

    public GuardWorkerResumeTests()
    {
        File.WriteAllText(Path.Combine(folder, "install-state.json"), """{"clientPath":"C:\\RCEGuardTest\\Wow.exe"}""");
    }

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(folder, recursive: true);
    }

    private LogPositionFile PositionFile => new(Path.Combine(folder, ServiceOptions.PositionFileName));

    /// <summary>Runs the worker until it has logged a line containing <paramref name="until"/>, then stops it.</summary>
    private async Task<List<string>> RunWorkerAsync(string until)
    {
        var logger = new ListLogger();
        var options = new ServiceOptions { DataDirectory = folder, LogName = Log, DryRun = true };
        var worker = new GuardWorker(options, logger, new Lifetime());
        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        while (!logger.Lines.Any(line => line.Contains(until)) && !logger.Lines.Any(line => line.Contains("cannot run")) && watch.ElapsedMilliseconds < 15_000)
        {
            await Task.Delay(50);
        }

        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        return [.. logger.Lines];
    }

    [Fact]
    public async Task The_first_start_reads_nothing_old_and_notes_the_newest_event()
    {
        var newestBefore = EventLogTail.Range(Log)!.Value.Newest;

        var lines = await RunWorkerAsync("Subscribed to");

        Assert.Contains(lines, line => line.Contains("No saved position"));
        Assert.DoesNotContain(lines, line => line.Contains("Caught up"));
        var saved = PositionFile.Load(out var problem);
        Assert.Null(problem);
        Assert.NotNull(saved);
        Assert.True(saved.RecordId >= newestBefore.RecordId);
    }

    [Fact]
    public async Task A_start_after_a_pause_reads_what_was_written_in_between_and_moves_the_position()
    {
        // As if the guard had stopped six events ago.
        var recent = ReadNewest(7);
        Assert.True(recent.Count == 7, "the Application log holds fewer than seven events");
        PositionFile.Save(recent[0]);

        var lines = await RunWorkerAsync("Caught up");

        Assert.Contains(lines, line => line.Contains($"after record {recent[0].RecordId}") && line.Contains("were written while RCEGuard was not running"));
        Assert.Contains(lines, line => line.Contains("Caught up"));
        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        var saved = PositionFile.Load(out _);
        Assert.NotNull(saved);
        Assert.True(saved.RecordId >= recent[^1].RecordId, $"position {saved.RecordId} is before the newest event {recent[^1].RecordId}");
    }

    [Fact]
    public async Task A_start_with_nothing_new_says_so()
    {
        // Another program may write to the Application log at any time; then the other message is right.
        PositionFile.Save(EventLogTail.Range(Log)!.Value.Newest);

        var lines = await RunWorkerAsync("Subscribed to");

        Assert.Contains(lines, line => line.Contains("nothing was written in the meantime") || line.Contains("were written while RCEGuard was not running"));
    }

    [Fact]
    public async Task A_position_from_another_log_makes_the_guard_read_the_whole_log()
    {
        // Same record id as an event in the log, but written at another time: the log was replaced.
        var newest = EventLogTail.Range(Log)!.Value.Newest;
        PositionFile.Save(newest with { TimeCreated = newest.TimeCreated.AddDays(-400) });

        var lines = await RunWorkerAsync("Subscribed to");

        Assert.Contains(lines, line => line.Contains("cleared or replaced"));
    }

    [Fact]
    public async Task A_damaged_position_file_is_reported_and_treated_as_a_first_start()
    {
        File.WriteAllText(PositionFile.Path, "{ not json");

        var lines = await RunWorkerAsync("Subscribed to");

        Assert.Contains(lines, line => line.Contains("cannot be read and is ignored"));
        Assert.Contains(lines, line => line.Contains("No saved position"));
        Assert.NotNull(PositionFile.Load(out var problem));
        Assert.Null(problem);
    }

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

    private sealed class ListLogger : ILogger<GuardWorker>
    {
        public ConcurrentQueue<string> Lines { get; } = new();

        public IDisposable? BeginScope<TState>(TState state)
            where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter) =>
            Lines.Enqueue($"{logLevel}: {formatter(state, exception)}");
    }

    private sealed class Lifetime : IHostApplicationLifetime
    {
        public CancellationToken ApplicationStarted => CancellationToken.None;

        public CancellationToken ApplicationStopping => CancellationToken.None;

        public CancellationToken ApplicationStopped => CancellationToken.None;

        public void StopApplication()
        {
        }
    }
}
