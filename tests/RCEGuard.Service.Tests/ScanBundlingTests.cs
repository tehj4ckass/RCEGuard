using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Rules;
using RCEGuard.Core.State;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// A scan in the guard loop: the client opens many programs to read them, and the guard reports
/// one finding. The events are handed to the guard directly, with the time of now (as a live
/// event has it).
/// </summary>
public sealed class ScanBundlingTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";

    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-scan-").FullName;

    public void Dispose()
    {
        TestFolder.Delete(folder);
    }

    private static string Access(string target, string rights, DateTimeOffset time) =>
        $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"}" />
            <EventID>10</EventID>
            <TimeCreated SystemTime="{time.UtcDateTime:yyyy-MM-ddTHH:mm:ss.fffffff}Z" />
            <EventRecordID>79</EventRecordID>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>TESTPC</Computer>
          </System>
          <EventData>
            <Data Name="SourceProcessId">4000003</Data>
            <Data Name="SourceImage">{Client}</Data>
            <Data Name="TargetProcessId">4000100</Data>
            <Data Name="TargetImage">{target}</Data>
            <Data Name="GrantedAccess">{rights}</Data>
          </EventData>
        </Event>
        """;

    private GuardWorker Worker(params string[] events)
    {
        File.WriteAllText(
            Path.Combine(folder, "appsettings.json"),
            $$"""{ "killEnabled": false, "profiles": [ { "name": "Test", "clientPath": "{{Client.Replace(@"\", @"\\")}}" } ] }""");
        return new GuardWorker(new ServiceOptions { DataDirectory = folder, LogName = "Application" }, new ListLogger(), new Lifetime())
        {
            OpenFirewall = () => new FakeFirewall(),
            ListProcesses = () => [],
            DeliveryGrace = TimeSpan.FromSeconds(1),
            OpenTail = (_, _, onEntry, _) =>
            {
                // Record ids above anything in the real log: nothing in it counts as "not delivered".
                var recordId = long.MaxValue / 2;
                foreach (var xml in events)
                {
                    onEntry(new LogEntry(xml, new LogPosition(recordId++, DateTimeOffset.UtcNow)));
                }

                return new MemoryStream();
            },
        };
    }

    private static async Task<List<string>> RunAsync(GuardWorker worker, Func<IReadOnlyCollection<string>, bool> done, int timeoutMs = 20_000)
    {
        var logger = (ListLogger)worker.Logger;
        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        while (!done(logger.Lines) && !logger.Lines.Any(line => line.Contains("cannot run")) && watch.ElapsedMilliseconds < timeoutMs)
        {
            await Task.Delay(50);
        }

        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        return [.. logger.Lines];
    }

    private List<(string Severity, string Action, string Target)> StoredScans()
    {
        using var connection = new Microsoft.Data.Sqlite.SqliteConnection($"Data Source={Path.Combine(folder, "findings.db")}");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT severity, action, target FROM findings WHERE rule = 'R7';";
        using var reader = command.ExecuteReader();
        var rows = new List<(string, string, string)>();
        while (reader.Read())
        {
            rows.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2)));
        }

        return rows;
    }

    [Fact]
    public async Task A_scan_is_reported_as_one_finding_once_it_is_over()
    {
        var now = DateTimeOffset.UtcNow;
        var programs = Enumerable.Range(1, 12).Select(number => $@"C:\Programs\app{number}.exe").ToList();
        var events = programs.Select((program, index) => Access(program, "0x10", now.AddMilliseconds(index * 10))).ToArray();
        var watch = Stopwatch.StartNew();

        var lines = await RunAsync(Worker(events), logged => logged.Any(line => line.Contains("R7 ")));

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        var line = Assert.Single(lines, line => line.Contains("R7 "));
        Assert.Contains("R7 MEDIUM", line);
        Assert.Contains("opened 12 other programs to read their memory (0x10; 12 accesses within 1 s): app1.exe, app2.exe, app3.exe, app4.exe, app5.exe and 7 more", line);
        // Held back until the client has opened nothing more for a while, not reported with the first event.
        Assert.InRange(watch.Elapsed, TimeSpan.FromSeconds(2.5), TimeSpan.FromSeconds(15));
        var stored = Assert.Single(StoredScans());
        Assert.Equal("12 programs", stored.Target);
        Assert.Equal(("MEDIUM", "LOG"), (stored.Severity.ToUpperInvariant(), stored.Action.ToUpperInvariant()));
    }

    [Fact]
    public async Task An_access_that_alerts_is_reported_at_once_and_the_scan_around_it_stays_one_finding()
    {
        var now = DateTimeOffset.UtcNow;
        var watch = Stopwatch.StartNew();
        TimeSpan? alertedAfter = null;

        var lines = await RunAsync(
            Worker(
                Access(@"C:\Programs\a.exe", "0x10", now),
                Access(@"C:\WINDOWS\Explorer.EXE", "0x102a", now.AddMilliseconds(10)),
                Access(@"C:\Programs\b.exe", "0x10", now.AddMilliseconds(20))),
            logged =>
            {
                if (alertedAfter is null && logged.Any(line => line.Contains("R7 HIGH")))
                {
                    alertedAfter = watch.Elapsed;
                }

                return logged.Any(line => line.Contains("R7 MEDIUM"));
            });

        Assert.NotNull(alertedAfter);
        Assert.Contains(lines, line => line.Contains("R7 HIGH") && line.Contains("with rights to change it (0x102a"));
        var scan = Assert.Single(lines, line => line.Contains("R7 MEDIUM"));
        Assert.Contains("opened 2 other programs to read their memory (0x10; 2 accesses within 1 s): a.exe, b.exe", scan);
        Assert.True(lines.FindIndex(line => line.Contains("R7 HIGH")) < lines.FindIndex(line => line.Contains("R7 MEDIUM")));
    }

    [Fact]
    public async Task What_is_held_back_when_the_guard_stops_is_still_reported()
    {
        var now = DateTimeOffset.UtcNow;

        // Stops after a second: the events are in, but the scan does not count as over yet.
        var lines = await RunAsync(
            Worker(Access(@"C:\Programs\a.exe", "0x10", now), Access(@"C:\Programs\b.exe", "0x10", now)),
            _ => false,
            timeoutMs: 1_000);

        Assert.Single(lines, line => line.Contains("R7 MEDIUM") && line.Contains("opened 2 other programs"));
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
