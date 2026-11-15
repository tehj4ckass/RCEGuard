using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Learning;
using RCEGuard.Core.State;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// Learning mode in the guard loop and the command that shows what was noted, with a stand-in
/// for Windows Firewall. The events are handed to the guard directly.
/// </summary>
public sealed class LearningModeTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";

    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-notes-").FullName;
    private readonly FakeFirewall firewall = new();

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(folder, recursive: true);
    }

    private static string Event(int id, string data) =>
        $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"}" />
            <EventID>{id}</EventID>
            <TimeCreated SystemTime="2026-11-12T14:05:03.8703468Z" />
            <EventRecordID>79</EventRecordID>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>TESTPC</Computer>
          </System>
          <EventData>
            <Data Name="ProcessId">4000003</Data>
            <Data Name="Image">{Client}</Data>
            {data}
          </EventData>
        </Event>
        """;

    private static string ConnectXml(string ip) => Event(
        3, $"""<Data Name="Initiated">true</Data><Data Name="DestinationIp">{ip}</Data><Data Name="DestinationPort">3724</Data>""");

    private static string QueryXml(string name, string results) => Event(
        22, $"""<Data Name="QueryName">{name}</Data><Data Name="QueryStatus">0</Data><Data Name="QueryResults">{results}</Data>""");

    private LearnedFile Learned => new(Path.Combine(folder, LearnedFile.FileName));

    private void WriteConfig(string settings) => File.WriteAllText(
        Path.Combine(folder, "appsettings.json"),
        $$"""{ "lockdown": true, "profiles": [ { "name": "Test", "clientPath": "{{Client.Replace(@"\", @"\\")}}" {{settings}} } ] }""");

    private ServiceOptions Options() => new() { DataDirectory = folder, LogName = "Application" };

    private GuardWorker Worker(params string[] events) => new(Options(), new ListLogger(), new Lifetime())
    {
        OpenFirewall = () => firewall,
        ResolveHost = (_, _) => Task.FromResult(new[] { IPAddress.Parse("203.0.113.7") }),
        DeliveryGrace = TimeSpan.FromSeconds(1),
        OpenTail = (_, _, onEntry, _) =>
        {
            // Record ids above anything in the real log: nothing in it counts as "not delivered".
            var recordId = long.MaxValue / 2;
            foreach (var xml in events.Append("<NotAnEvent/>"))
            {
                onEntry(new LogEntry(xml, new LogPosition(recordId++, DateTimeOffset.UtcNow)));
            }

            return new MemoryStream();
        },
    };

    private static async Task<List<string>> RunAsync(GuardWorker worker, Func<IReadOnlyCollection<string>, bool> done)
    {
        var logger = (ListLogger)worker.Logger;
        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        while (!done(logger.Lines) && !logger.Lines.Any(line => line.Contains("cannot run")) && watch.ElapsedMilliseconds < 20_000)
        {
            await Task.Delay(50);
        }

        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        return [.. logger.Lines];
    }

    [Fact]
    public async Task While_learning_nothing_is_terminated_locked_down_or_blocked_and_the_notes_are_saved()
    {
        WriteConfig(""", "learning": true, "firewall": true, "allowedRemote": ["198.51.100.0/24"] """);

        var lines = await RunAsync(
            Worker(
                QueryXml("logon.example.org", "::ffff:203.0.113.9;"),
                ConnectXml("203.0.113.9"),
                ConnectXml("198.51.100.7"),
                LockdownTests.ChildProcessEventXml),
            logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        Assert.Contains(lines, line => line.StartsWith("Warning: Learning mode is ON for 'Test'") && line.Contains("the firewall rule of the profile is not written"));
        Assert.Contains(lines, line => line.Contains("R1 CRITICAL") && line.Contains("not terminated (learning mode)"));
        Assert.DoesNotContain(lines, line => line.Contains("locked down:") || line.Contains("would lock down"));
        Assert.Contains(lines, line => line.Contains("R2 INFO") && line.Contains("Learning mode: the game client connected to 203.0.113.9:3724"));
        Assert.DoesNotContain(lines, line => line.Contains("R2 CRITICAL"));
        Assert.Empty(firewall.Rules);
        Assert.Empty(new LockdownFile(Path.Combine(folder, LockdownFile.FileName)).Load(out _));

        var learned = Assert.Single(Learned.Load(out var problem));
        Assert.Null(problem);
        Assert.Equal(["203.0.113.9:3724", "198.51.100.7:3724"], learned.Remotes.Select(remote => $"{remote.Address}:{remote.Port}"));
        Assert.Equal("logon.example.org", Assert.Single(learned.Hosts).Name);
    }

    [Fact]
    public async Task Without_the_switch_nothing_is_noted_and_the_client_is_dealt_with_as_always()
    {
        WriteConfig(string.Empty);

        var lines = await RunAsync(
            Worker(ConnectXml("203.0.113.9"), LockdownTests.ChildProcessEventXml),
            logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        Assert.DoesNotContain(lines, line => line.Contains("Learning mode"));
        Assert.Contains(lines, line => line.Contains("R2 CRITICAL"));
        Assert.Contains(lines, line => line.Contains("R1 CRITICAL") && line.Contains("locked down"));
        Assert.False(File.Exists(Learned.Path));
    }

    [Fact]
    public async Task Notes_from_before_are_continued_after_a_restart()
    {
        WriteConfig(""", "learning": true """);
        Learned.Save([new LearnedProfile { Profile = "Test", Sessions = 1, Remotes = [new LearnedRemote { Address = "203.0.113.9", Port = 3724, Count = 4 }] }]);

        await RunAsync(Worker(ConnectXml("203.0.113.9")), logged => logged.Any(line => line.Contains("R2 INFO")));

        Assert.Equal(5, Assert.Single(Assert.Single(Learned.Load(out _)).Remotes).Count);
    }

    [Fact]
    public async Task Notes_that_cannot_be_read_are_started_anew_with_a_warning()
    {
        WriteConfig(""", "learning": true """);
        File.WriteAllText(Learned.Path, "{ not json");

        var lines = await RunAsync(Worker(ConnectXml("203.0.113.9")), logged => logged.Any(line => line.Contains("R2 INFO")));

        Assert.Contains(lines, line => line.StartsWith("Warning: What the learning mode noted before") && line.Contains("started anew"));
        Assert.Equal(1, Assert.Single(Assert.Single(Learned.Load(out var problem)).Remotes).Count);
        Assert.Null(problem);
    }

    [Fact]
    public void The_command_shows_the_notes_and_the_suggestion()
    {
        WriteConfig(""", "learning": true, "allowedRemote": ["198.51.100.0/24"] """);
        Learned.Save(
        [
            new LearnedProfile
            {
                Profile = "Test",
                Sessions = 2,
                Remotes = [new LearnedRemote { Address = "203.0.113.9", Port = 3724, Count = 3 }, new LearnedRemote { Address = "192.0.2.200", Port = 80, Count = 1 }],
                Hosts = [new LearnedHost { Name = "logon.example.org", Addresses = ["203.0.113.9"], Count = 2 }],
            },
        ]);
        var output = new StringWriter();
        var error = new StringWriter();

        var exitCode = LearnedCommand.Run(Options() with { Learned = true }, output, error);

        Assert.Equal((0, string.Empty), (exitCode, error.ToString()));
        Assert.Contains("Profile 'Test'", output.ToString());
        Assert.Contains("\"allowedHostnames\": [\"logon.example.org\"],", output.ToString());
        Assert.Contains("\"allowedRemote\": [\"198.51.100.0/24\",\"192.0.2.200\"]", output.ToString());
    }

    [Theory]
    [InlineData(""", "learning": true """, "learning mode is ON, nothing was noted yet")]
    [InlineData("", "Learning mode is off; turn it on")]
    public void The_command_says_so_when_nothing_was_noted(string settings, string expected)
    {
        WriteConfig(settings);
        var output = new StringWriter();

        var exitCode = LearnedCommand.Run(Options() with { Learned = true }, output, new StringWriter());

        Assert.Equal(0, exitCode);
        Assert.Contains(expected, output.ToString());
    }

    [Fact]
    public void The_command_fails_with_a_reason_for_an_unknown_profile_and_for_notes_it_cannot_read()
    {
        WriteConfig(string.Empty);
        var error = new StringWriter();

        Assert.Equal(1, LearnedCommand.Run(Options() with { Learned = true, LearnedProfile = "Other" }, new StringWriter(), error));
        Assert.Contains("There is no profile 'Other'. Profiles: 'Test'.", error.ToString());

        File.WriteAllText(Learned.Path, "{ not json");
        error = new StringWriter();
        Assert.Equal(1, LearnedCommand.Run(Options() with { Learned = true }, new StringWriter(), error));
        Assert.Contains("cannot be read", error.ToString());
    }

    [Theory]
    [InlineData(new[] { "--learned" }, true, null)]
    [InlineData(new[] { "--learned", "Warmane" }, true, "Warmane")]
    [InlineData(new[] { "--learned", "--data-dir", "C:\\X" }, true, null)]
    [InlineData(new[] { "--dry-run" }, false, null)]
    public void The_learned_argument_takes_an_optional_profile_name(string[] args, bool learned, string? profile)
    {
        var options = ServiceOptions.Parse(args, out var error);

        Assert.NotNull(options);
        Assert.Empty(error);
        Assert.Equal((learned, profile), (options.Learned, options.LearnedProfile));
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
