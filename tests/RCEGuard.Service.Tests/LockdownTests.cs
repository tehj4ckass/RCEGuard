using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// The kill switch in the guard loop and the release command, with a stand-in for Windows Firewall.
/// The events are handed to the guard directly; the log it "reads" is the Application log (read only).
/// </summary>
public sealed class LockdownTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";

    /// <summary>
    /// A recorded "client started cmd.exe" (R1), with process ids no process can have (Windows only
    /// hands out multiples of four): the guard must find nothing to terminate on the machine of the test.
    /// </summary>
    private const string ChildProcessEvent =
        """
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}" />
            <EventID>1</EventID>
            <TimeCreated SystemTime="2026-11-12T14:04:58.4333175Z" />
            <EventRecordID>25</EventRecordID>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>TESTPC</Computer>
          </System>
          <EventData>
            <Data Name="RuleName">R1</Data>
            <Data Name="UtcTime">2026-11-12 14:04:58.424</Data>
            <Data Name="ProcessGuid">{11111111-c78a-6af5-4988-030000006801}</Data>
            <Data Name="ProcessId">4000001</Data>
            <Data Name="Image">C:\Windows\System32\cmd.exe</Data>
            <Data Name="CommandLine">"cmd.exe" /c echo RCEGuard child process test</Data>
            <Data Name="User">TESTPC\player</Data>
            <Data Name="IntegrityLevel">Medium</Data>
            <Data Name="ParentProcessGuid">{11111111-c78a-6af5-4888-030000006801}</Data>
            <Data Name="ParentProcessId">4000003</Data>
            <Data Name="ParentImage">C:\RCEGuardTest\Wow.exe</Data>
            <Data Name="ParentCommandLine">"C:\RCEGuardTest\Wow.exe" --spawn</Data>
            <Data Name="ParentUser">TESTPC\player</Data>
          </EventData>
        </Event>
        """;

    // Not "lockdown" in the name: the path is in the log lines the tests search.
    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-killswitch-").FullName;
    private readonly FakeFirewall firewall = new();

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(folder, recursive: true);
    }

    private LockdownFile Lockdown => new(Path.Combine(folder, LockdownFile.FileName));

    private void WriteConfig(string json) => File.WriteAllText(Path.Combine(folder, "appsettings.json"), json);

    private ServiceOptions Options(bool dryRun = false) => new() { DataDirectory = folder, LogName = "Application", DryRun = dryRun };

    /// <summary>A worker whose "log" delivers exactly the given events.</summary>
    private GuardWorker Worker(ServiceOptions options, params string[] events) => new(options, new ListLogger(), new Lifetime())
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

    private static async Task<List<string>> RunAsync(GuardWorker worker, Func<IReadOnlyCollection<string>, bool> done, Action? whenSubscribed = null)
    {
        var logger = (ListLogger)worker.Logger;
        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        var acted = whenSubscribed is null;
        while (!done(logger.Lines) && !logger.Lines.Any(line => line.Contains("cannot run")) && watch.ElapsedMilliseconds < 20_000)
        {
            if (!acted && logger.Lines.Any(line => line.Contains("Subscribed to")))
            {
                acted = true;
                whenSubscribed!();
            }

            await Task.Delay(50);
        }

        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        return [.. logger.Lines];
    }

    [Fact]
    public async Task A_finding_that_terminates_the_client_locks_its_profile_down()
    {
        WriteConfig($$"""{"lockdown":true,"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");

        var lines = await RunAsync(Worker(Options(), ChildProcessEvent), logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        Assert.Contains(lines, line => line.Contains("R1 CRITICAL") && line.Contains("locked down: the firewall blocks every outbound connection"));
        var rule = Assert.Single(firewall.Rules);
        Assert.Equal(("RCEGuard: Test", Client, "*"), (rule.Name, rule.ApplicationPath, rule.RemoteAddresses));
        Assert.Equal("R1", Assert.Single(Lockdown.Load(out _)).Rule);
    }

    [Fact]
    public async Task Without_the_switch_a_finding_locks_nothing()
    {
        WriteConfig($$"""{"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");

        var lines = await RunAsync(Worker(Options(), ChildProcessEvent), logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        Assert.Contains(lines, line => line.Contains("R1 CRITICAL"));
        var aboutLockdown = string.Join(" || ", lines.Where(line =>
            line.Contains("lock down", StringComparison.OrdinalIgnoreCase)
            || line.Contains("locked down", StringComparison.OrdinalIgnoreCase)
            || line.Contains("lockdown", StringComparison.OrdinalIgnoreCase)));
        Assert.Equal(string.Empty, aboutLockdown);
        Assert.Empty(firewall.Calls);
        Assert.False(File.Exists(Lockdown.Path));
    }

    [Theory]
    [InlineData(true, """ "killEnabled": true, """)]    // --dry-run
    [InlineData(false, """ "killEnabled": false, """)]  // configured not to terminate
    public async Task Where_nothing_is_terminated_nothing_is_locked_down(bool dryRun, string killSetting)
    {
        WriteConfig($$"""{ {{killSetting}} "lockdown":true,"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");

        var lines = await RunAsync(Worker(Options(dryRun), ChildProcessEvent), logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        Assert.Contains(lines, line => line.Contains("R1 CRITICAL") && line.Contains("would lock down the profile"));
        Assert.DoesNotContain(firewall.Rules, rule => rule.RemoteAddresses == "*");
        Assert.False(File.Exists(Lockdown.Path));
    }

    [Fact]
    public async Task The_guard_writes_the_rule_of_a_profile_with_firewall_at_its_start()
    {
        WriteConfig($$"""{"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}","allowedHostnames":["logon.example.org"],"firewall":true}]}""");

        var lines = await RunAsync(Worker(Options()), logged => logged.Any(line => line.Contains("Subscribed to")));

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        // 203.0.113.7 is what the stand-in for the name resolution returns.
        Assert.Contains("128.0.0.0-203.0.113.6,203.0.113.8-255.255.255.255", Assert.Single(firewall.Rules).RemoteAddresses);
        Assert.Contains(lines, line => line.Contains("Firewall rule 'RCEGuard: Test' written"));
    }

    [Fact]
    public async Task A_lockdown_is_in_place_again_after_a_restart_and_ends_when_it_is_released()
    {
        WriteConfig($$"""{"lockdown":true,"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");
        Lockdown.Save([new LockdownEntry("Test", DateTimeOffset.UtcNow.AddHours(-1), "R1", "Client started a child process")]);
        var lockedAtStart = false;
        var output = new StringWriter();
        var exitCode = -1;

        var lines = await RunAsync(
            Worker(Options()),
            logged => logged.Any(line => line.Contains("changed from outside")),
            whenSubscribed: () =>
            {
                lockedAtStart = firewall.Rules.Any(rule => rule.RemoteAddresses == "*");
                // The owner releases while the guard runs.
                exitCode = ReleaseCommand.RunAsync(Options() with { Release = true }, firewall, output, output).GetAwaiter().GetResult();
            });

        Assert.True(lockedAtStart, "the rule of the lockdown was not written at the start");
        Assert.Equal(0, exitCode);
        Assert.Contains("Released 'Test'", output.ToString());
        Assert.Contains("after R1: Client started a child process", output.ToString());
        Assert.Contains(lines, line => line.Contains("changed from outside"));
        Assert.Empty(firewall.Rules);
        Assert.Empty(Lockdown.Load(out _));
    }

    [Fact]
    public async Task Release_says_so_when_nothing_is_locked()
    {
        WriteConfig($$"""{"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");
        var output = new StringWriter();
        var error = new StringWriter();

        Assert.Equal(0, await ReleaseCommand.RunAsync(Options() with { Release = true }, firewall, output, error));
        Assert.Contains("No profile is in lockdown", output.ToString());

        Assert.Equal(1, await ReleaseCommand.RunAsync(Options() with { Release = true, ReleaseProfile = "Other" }, firewall, output, error));
        Assert.Contains("'Other' is not in lockdown", error.ToString());
        Assert.Empty(firewall.Calls);
    }

    [Fact]
    public async Task Release_of_one_profile_leaves_the_other_locked()
    {
        WriteConfig(
            """
            {"profiles":[
              {"name":"One","clientPath":"C:\\Games\\One\\Wow.exe","allowedRemote":["203.0.113.7"],"firewall":true},
              {"name":"Two","clientPath":"C:\\Games\\Two\\Wow.exe"}]}
            """);
        Lockdown.Save(
        [
            new LockdownEntry("One", DateTimeOffset.UtcNow, "R1", "first"),
            new LockdownEntry("Two", DateTimeOffset.UtcNow, "R4", "second"),
        ]);
        var output = new StringWriter();

        var exitCode = await ReleaseCommand.RunAsync(Options() with { Release = true, ReleaseProfile = "one" }, firewall, output, output);

        Assert.Equal(0, exitCode);
        Assert.Equal("Two", Assert.Single(Lockdown.Load(out _)).Profile);
        Assert.Equal(2, firewall.Rules.Count);
        Assert.NotEqual("*", firewall.Rules.Single(rule => rule.Name == "RCEGuard: One").RemoteAddresses);   // back to its allowlist
        Assert.Equal("*", firewall.Rules.Single(rule => rule.Name == "RCEGuard: Two").RemoteAddresses);
    }

    [Fact]
    public async Task Release_replaces_a_lockdown_state_that_cannot_be_read()
    {
        WriteConfig($$"""{"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");
        File.WriteAllText(Lockdown.Path, "{ not json");
        firewall.Put(new InstalledFirewallRule("RCEGuard: Test", "lockdown", Client, "*", true, true));
        var output = new StringWriter();

        var exitCode = await ReleaseCommand.RunAsync(Options() with { Release = true }, firewall, output, output);

        Assert.Equal(0, exitCode);
        Assert.Contains("cannot be read", output.ToString());
        Assert.Empty(Lockdown.Load(out var problem));
        Assert.Null(problem);
        Assert.Empty(firewall.Rules);
    }

    [Fact]
    public async Task Release_fails_with_a_reason_when_the_firewall_cannot_be_changed()
    {
        WriteConfig($$"""{"profiles":[{"name":"Test","clientPath":"{{Client.Replace(@"\", @"\\")}}"}]}""");
        Lockdown.Save([new LockdownEntry("Test", DateTimeOffset.UtcNow, "R1", "x")]);
        firewall.Fail = new UnauthorizedAccessException("Access is denied.");
        var error = new StringWriter();

        var exitCode = await ReleaseCommand.RunAsync(Options() with { Release = true }, firewall, new StringWriter(), error);

        Assert.Equal(1, exitCode);
        Assert.Contains("Access is denied", error.ToString());
        Assert.Contains("the firewall rule could not be changed", error.ToString());
    }

    [Theory]
    [InlineData(new[] { "--release" }, true, null)]
    [InlineData(new[] { "--release", "Warmane" }, true, "Warmane")]
    [InlineData(new[] { "--release", "--dry-run" }, true, null)]
    [InlineData(new[] { "--dry-run" }, false, null)]
    public void The_release_argument_takes_an_optional_profile_name(string[] args, bool release, string? profile)
    {
        var options = ServiceOptions.Parse(args, out var error);

        Assert.NotNull(options);
        Assert.Empty(error);
        Assert.Equal((release, profile), (options.Release, options.ReleaseProfile));
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
