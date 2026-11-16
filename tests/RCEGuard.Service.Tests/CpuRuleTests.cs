using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.State;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// R8 in the guard loop, with made-up processor times, and the real process list of Windows.
/// The events are handed to the guard directly.
/// </summary>
public sealed class CpuRuleTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";
    private const int ClientPid = 4000003;   // no process can have it: Windows only hands out multiples of four
    private static readonly DateTimeOffset ClientStarted = new(2026, 11, 12, 14, 4, 58, 424, TimeSpan.Zero);

    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-load-").FullName;

    public void Dispose()
    {
        TestFolder.Delete(folder);
    }

    private static string ClientEvent(int id) =>
        $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"}" />
            <EventID>{id}</EventID>
            <TimeCreated SystemTime="2026-11-12T14:04:58.4333175Z" />
            <EventRecordID>24</EventRecordID>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>TESTPC</Computer>
          </System>
          <EventData>
            <Data Name="RuleName">client-start</Data>
            <Data Name="UtcTime">2026-11-12 14:04:58.424</Data>
            <Data Name="ProcessGuid">{"{11111111-c78a-6af5-4888-030000006801}"}</Data>
            <Data Name="ProcessId">{ClientPid}</Data>
            <Data Name="Image">{Client}</Data>
          </EventData>
        </Event>
        """;

    private void WriteConfig(string settings) => File.WriteAllText(
        Path.Combine(folder, "appsettings.json"),
        $$"""{ {{settings}} "profiles": [ { "name": "Test", "clientPath": "{{Client.Replace(@"\", @"\\")}}", "learning": true } ] }""");

    private GuardWorker Worker(Func<IReadOnlyDictionary<int, ProcessTime>> times, params string[] events) =>
        new(new ServiceOptions { DataDirectory = folder, LogName = "Application" }, new ListLogger(), new Lifetime())
        {
            OpenFirewall = () => new FakeFirewall(),
            ReadProcessTimes = times,
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

    /// <summary>A client that has used <paramref name="cores"/> cores since the first look at it.</summary>
    private static Func<IReadOnlyDictionary<int, ProcessTime>> Busy(double cores, DateTimeOffset created, ConcurrentQueue<DateTimeOffset> looks)
    {
        var watch = new Stopwatch();
        return () =>
        {
            looks.Enqueue(DateTimeOffset.UtcNow);
            watch.Start();
            return new Dictionary<int, ProcessTime>
            {
                [ClientPid] = new(ClientPid, "Wow.exe", created, TimeSpan.FromSeconds(100 + (watch.Elapsed.TotalSeconds * cores))),
            };
        };
    }

    [Fact]
    public async Task A_client_that_keeps_several_cores_busy_is_reported_once_and_the_load_is_noted()
    {
        WriteConfig(""" "cpuAlertCores": 1.5, "cpuAlertSeconds": 5, """);
        var looks = new ConcurrentQueue<DateTimeOffset>();

        var lines = await RunAsync(
            Worker(Busy(3.0, ClientStarted, looks), ClientEvent(1)),
            // Two seconds past the alert: a second one must not follow while the load stays.
            logged => looks.Count >= 8 && logged.Any(line => line.Contains("R8 MEDIUM")));

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        Assert.Contains(lines, line => line.Contains("R8: a client that keeps more than 1.5 processor cores busy on average over 5 s is reported"));
        var alert = Assert.Single(lines, line => line.Contains("R8 MEDIUM"));
        Assert.Matches(@"R8 MEDIUM \[Test\] The game client kept 3\.0 processor cores busy on average over the last 5 s \(alert above 1\.5\) \| action: Alert -> none", alert);

        var learned = Assert.Single(new LearnedFile(Path.Combine(folder, LearnedFile.FileName)).Load(out _));
        Assert.InRange(learned.PeakCpuCores, 2.9, 3.1);
    }

    [Fact]
    public async Task A_client_below_the_threshold_is_measured_but_not_reported()
    {
        WriteConfig(""" "cpuAlertCores": 1.5, "cpuAlertSeconds": 5, """);
        var looks = new ConcurrentQueue<DateTimeOffset>();

        var lines = await RunAsync(Worker(Busy(1.0, ClientStarted, looks), ClientEvent(1)), _ => looks.Count >= 8);

        Assert.DoesNotContain(lines, line => line.Contains("R8 MEDIUM"));
        var learned = Assert.Single(new LearnedFile(Path.Combine(folder, LearnedFile.FileName)).Load(out _));
        Assert.InRange(learned.PeakCpuCores, 0.9, 1.1);
    }

    [Fact]
    public async Task A_process_that_only_shares_the_pid_or_has_ended_is_not_measured()
    {
        WriteConfig(""" "cpuAlertCores": 1.5, "cpuAlertSeconds": 5, """);
        var looks = new ConcurrentQueue<DateTimeOffset>();

        // Started a minute after the client of the event: another process has the pid now.
        var lines = await RunAsync(Worker(Busy(8.0, ClientStarted.AddMinutes(1), looks), ClientEvent(1)), _ => false, timeoutMs: 4_000);

        Assert.DoesNotContain(lines, line => line.Contains("R8 MEDIUM"));
        Assert.Single(looks);   // dropped at the first look, so there was no second one

        // The client started and ended: nothing is left to measure.
        looks.Clear();
        lines = await RunAsync(Worker(Busy(8.0, ClientStarted, looks), ClientEvent(1), ClientEvent(5)), _ => false, timeoutMs: 3_000);

        Assert.DoesNotContain(lines, line => line.Contains("R8 MEDIUM"));
        // At most one look, between reading the start and reading the end; none after that.
        Assert.InRange(looks.Count, 0, 1);
    }

    [Fact]
    public async Task With_zero_cores_the_rule_is_off()
    {
        WriteConfig(""" "cpuAlertCores": 0, """);
        var looks = new ConcurrentQueue<DateTimeOffset>();

        var lines = await RunAsync(Worker(Busy(8.0, ClientStarted, looks), ClientEvent(1)), _ => false, timeoutMs: 3_000);

        Assert.DoesNotContain(lines, line => line.Contains("R8"));
        // The process list is still read (the look at the connections needs the start times), but nothing is measured.
        Assert.NotEmpty(looks);
        Assert.Equal(0, Assert.Single(new LearnedFile(Path.Combine(folder, LearnedFile.FileName)).Load(out _)).PeakCpuCores);
    }

    [Fact]
    public void The_process_list_of_windows_has_this_process_with_its_start_and_processor_time()
    {
        using var self = Process.GetCurrentProcess();
        // Something to measure.
        var spin = Stopwatch.StartNew();
        while (spin.ElapsedMilliseconds < 200)
        {
        }

        var before = self.TotalProcessorTime;
        var times = ProcessTimes.Take();
        self.Refresh();
        var after = self.TotalProcessorTime;

        Assert.True(times.Count > 20, $"only {times.Count} processes");
        var mine = times[Environment.ProcessId];
        Assert.Equal(Path.GetFileName(Environment.ProcessPath), mine.Name, ignoreCase: true);
        Assert.InRange(mine.Cpu, before - TimeSpan.FromMilliseconds(50), after + TimeSpan.FromMilliseconds(50));
        Assert.InRange((mine.Created - new DateTimeOffset(self.StartTime)).Duration(), TimeSpan.Zero, TimeSpan.FromMilliseconds(100));
        Assert.Equal("System", times[4].Name);
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
