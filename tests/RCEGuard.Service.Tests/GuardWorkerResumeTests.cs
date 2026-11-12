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
    private Task<List<string>> RunWorkerAsync(string until) =>
        RunWorkerAsync(new GuardWorker(Options(Log), new ListLogger(), new Lifetime()), lines => lines.Any(line => line.Contains(until)));

    private ServiceOptions Options(string log) => new() { DataDirectory = folder, LogName = log, DryRun = true };

    /// <summary>Runs a worker until <paramref name="done"/> says so (or it gives up), then stops it.</summary>
    private static async Task<List<string>> RunWorkerAsync(GuardWorker worker, Func<IReadOnlyCollection<string>, bool> done, Action? afterSubscribing = null)
    {
        var logger = (ListLogger)worker.Logger;
        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        var acted = afterSubscribing is null;
        while (!done(logger.Lines) && !logger.Lines.Any(line => line.Contains("cannot run")) && watch.ElapsedMilliseconds < 20_000)
        {
            if (!acted && logger.Lines.Any(line => line.Contains("Subscribed to")))
            {
                acted = true;
                afterSubscribing!();
            }

            await Task.Delay(50);
        }

        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        return [.. logger.Lines];
    }

    [Fact]
    public async Task An_event_written_after_the_start_is_handled_and_moves_the_position()
    {
        // A log of the kind Sysmon writes; the Application log would not have shown the fault this test is for.
        var newestBefore = EventLogTail.Newest(ManifestLog.Name)!;
        PositionFile.Save(newestBefore);
        var worker = new GuardWorker(Options(ManifestLog.Name), new ListLogger(), new Lifetime());

        var lines = await RunWorkerAsync(
            worker,
            logged => PositionFile.Load(out var problem) is { } saved && saved.RecordId > newestBefore.RecordId,
            afterSubscribing: () => ManifestLog.WriteEvents());

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        var position = PositionFile.Load(out _);
        Assert.NotNull(position);
        Assert.True(position.RecordId > newestBefore.RecordId, $"the position stayed at {position.RecordId}: the event written after the start was not handled");
    }

    [Fact]
    public async Task A_subscription_that_delivers_nothing_while_the_log_grows_ends_the_guard()
    {
        PositionFile.Save(EventLogTail.Newest(ManifestLog.Name)!);
        var worker = new GuardWorker(Options(ManifestLog.Name), new ListLogger(), new Lifetime())
        {
            DeliveryGrace = TimeSpan.FromSeconds(1),
            // A subscription that Windows accepted and that stays silent.
            OpenTail = (_, _, _, _) => new MemoryStream(),
        };

        List<string> lines;
        try
        {
            lines = await RunWorkerAsync(worker, _ => false, afterSubscribing: () => ManifestLog.WriteEvents());
        }
        finally
        {
            // Outside a Windows service the worker reports the failure through the exit code of the process: here, the test run.
            Environment.ExitCode = 0;
        }

        Assert.Contains(lines, line => line.Contains("cannot run") && line.Contains("were not delivered"));
    }

    [Fact]
    public async Task A_quiet_log_does_not_end_the_guard()
    {
        // Nothing is written to the log of this test, so a silent subscription is right.
        PositionFile.Save(EventLogTail.Newest(ManifestLog.Name)!);
        var worker = new GuardWorker(Options(ManifestLog.Name), new ListLogger(), new Lifetime()) { DeliveryGrace = TimeSpan.FromSeconds(2) };
        var watch = Stopwatch.StartNew();

        var lines = await RunWorkerAsync(worker, _ => watch.ElapsedMilliseconds > 5000);

        // Another program may start Windows PowerShell during the test; its events are delivered, so that is no fault either.
        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
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

    private static List<LogPosition> ReadNewest(int count) => ManifestLog.ReadNewest(Log, count);

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
