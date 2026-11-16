using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// The commands that change the configuration (--set-mode, --allow), with a stand-in for the
/// restart of the Windows service and for the network. And what the guard keeps across such a
/// restart: the clients that are running.
/// </summary>
public sealed class ConfigCommandTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";

    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-config-").FullName;
    private int restarts;

    public void Dispose()
    {
        TestFolder.Delete(folder);
    }

    private string ConfigPath => Path.Combine(folder, GuardConfigFile.FileName);

    private void WriteConfig(string top = "", string profile = "") => File.WriteAllText(
        ConfigPath,
        $$"""{ {{top}} "profiles": [ { "name": "Test", "clientPath": "{{Client.Replace(@"\", @"\\")}}" {{profile}} } ] }""");

    private GuardConfig Config => GuardConfigJson.Parse(File.ReadAllText(ConfigPath));

    private RestartResult Restarted()
    {
        restarts++;
        return new RestartResult(false, "The guard service was restarted and uses the new configuration.");
    }

    private (int ExitCode, string Output, string Error) SetMode(string mode, Func<RestartResult>? restart = null, HttpMessageHandler? handler = null)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exitCode = ConfigCommand.SetModeAsync(new ServiceOptions { DataDirectory = folder, SetMode = mode }, output, error, restart ?? Restarted, handler).GetAwaiter().GetResult();
        return (exitCode, output.ToString(), error.ToString());
    }

    private (int ExitCode, string Output, string Error) Allow(string profile, string address)
    {
        var output = new StringWriter();
        var error = new StringWriter();
        var exitCode = ConfigCommand.AllowAsync(new ServiceOptions { DataDirectory = folder, AllowProfile = profile, AllowAddress = address }, output, error, Restarted).GetAwaiter().GetResult();
        return (exitCode, output.ToString(), error.ToString());
    }

    [Fact]
    public void Setting_a_mode_writes_the_file_keeps_the_one_from_before_and_restarts_the_service()
    {
        WriteConfig(top: """ "lockdown": true, """, profile: """, "allowedRemote": ["203.0.113.7"] """);
        var before = File.ReadAllText(ConfigPath);

        var (exitCode, output, error) = SetMode("report-only");

        Assert.Equal((0, string.Empty), (exitCode, error));
        Assert.Contains("The mode of the guard was changed from \"Protect\" to \"Report only\".", output);
        Assert.Contains("nothing is terminated", output);
        Assert.Contains("The guard service was restarted", output);
        Assert.Equal(1, restarts);
        Assert.Equal(GuardMode.ReportOnly, GuardModes.Of(Config));
        Assert.True(Config.Lockdown);
        Assert.Equal(["203.0.113.7"], Config.Profiles[0].AllowedRemote);
        Assert.Equal(before, File.ReadAllText(ConfigPath + ".bak"));
        Assert.Equal(["appsettings.json", "appsettings.json.bak"], Directory.GetFiles(folder).Select(Path.GetFileName).Order());

        Assert.Equal(GuardMode.Learning, SetModeAndRead("learning"));
        Assert.Equal(GuardMode.Protect, SetModeAndRead("protect"));
        Assert.Equal(3, restarts);
    }

    private GuardMode? SetModeAndRead(string mode)
    {
        Assert.Equal(0, SetMode(mode).ExitCode);
        return GuardModes.Of(Config);
    }

    [Fact]
    public void A_mode_that_is_set_already_changes_nothing_and_restarts_nothing()
    {
        WriteConfig();
        var written = File.GetLastWriteTimeUtc(ConfigPath);

        var (exitCode, output, _) = SetMode("protect");

        Assert.Equal(0, exitCode);
        Assert.Contains("The mode is \"Protect\" already. Nothing was changed.", output);
        Assert.Equal((0, written), (restarts, File.GetLastWriteTimeUtc(ConfigPath)));
        Assert.False(File.Exists(ConfigPath + ".bak"));
    }

    [Fact]
    public void Without_a_configuration_file_one_is_written_for_the_installed_client()
    {
        File.WriteAllText(Path.Combine(folder, GuardConfigFile.InstallStateName), $$"""{ "clientPath": "{{Client.Replace(@"\", @"\\")}}" }""");

        var (exitCode, output, _) = SetMode("learning");

        Assert.Equal(0, exitCode);
        Assert.Contains("to \"Learning\"", output);
        Assert.Contains($"The configuration was written to '{ConfigPath}'.", output);
        Assert.Equal(("Default", Client, true), (Config.Profiles[0].Name, Config.Profiles[0].ClientPath, Config.Profiles[0].Learning));
        Assert.False(File.Exists(ConfigPath + ".bak"));
    }

    [Fact]
    public void What_cannot_be_done_fails_with_the_reason_and_changes_nothing()
    {
        Assert.Equal(1, SetMode("protect").ExitCode);   // nothing installed in this folder

        WriteConfig();
        var before = File.ReadAllText(ConfigPath);
        var unknown = SetMode("off");
        Assert.Equal(1, unknown.ExitCode);
        Assert.Contains("'off' is not a mode. Modes: protect, report-only, learning.", unknown.Error);

        var noProfile = Allow("Other", "198.51.100.7");
        Assert.Equal(1, noProfile.ExitCode);
        Assert.Contains("There is no profile 'Other'. Profiles: 'Test'.", noProfile.Error);
        Assert.Contains("is not an IP address or CIDR range", Allow("Test", "logon.example.org").Error);

        File.WriteAllText(ConfigPath, "{ not json");
        Assert.Equal(1, SetMode("learning").ExitCode);
        Assert.Equal("{ not json", File.ReadAllText(ConfigPath));
        Assert.Equal(0, restarts);
        Assert.NotEqual("{ not json", before);
    }

    [Fact]
    public void A_restart_that_fails_is_an_error_although_the_file_was_written()
    {
        WriteConfig();

        var (exitCode, _, error) = SetMode("report-only", () => new RestartResult(true, "The configuration was written, but the guard service could not be restarted: Access is denied."));

        Assert.Equal(1, exitCode);
        Assert.Contains("could not be restarted", error);
        Assert.Equal(GuardMode.ReportOnly, GuardModes.Of(Config));
    }

    [Fact]
    public void An_address_is_added_once_and_the_service_restarted_for_it()
    {
        WriteConfig(profile: """, "allowedRemote": ["203.0.113.0/24"] """);

        var (exitCode, output, error) = Allow("test", "198.51.100.7");

        Assert.Equal((0, string.Empty), (exitCode, error));
        Assert.Contains("'198.51.100.7' was added to the allowed addresses of profile 'test'.", output);
        Assert.Equal(["203.0.113.0/24", "198.51.100.7"], Config.Profiles[0].AllowedRemote);
        Assert.Equal(1, restarts);

        var again = Allow("Test", "198.51.100.7");
        Assert.Equal(0, again.ExitCode);
        Assert.Contains("already. Nothing was changed.", again.Output);
        Assert.Contains("already", Allow("Test", "203.0.113.9").Output);
        Assert.Equal(1, restarts);
    }

    [Fact]
    public void A_change_is_reported_to_ntfy_if_a_topic_is_configured()
    {
        WriteConfig(top: """ "notify": { "ntfy": { "url": "https://ntfy.example.org/my-topic" } }, """);
        var http = new FakeHttp();

        var (exitCode, output, _) = SetMode("learning", handler: http);

        Assert.Equal(0, exitCode);
        Assert.Contains("The change was reported to ntfy at https://ntfy.example.org.", output);
        var sent = Assert.Single(http.Requests);
        Assert.Contains("The mode of the guard was changed from \"Protect\" to \"Learning\".", sent.Body);
        Assert.DoesNotContain("my-topic", output);
    }

    [Theory]
    [InlineData(new[] { "--set-mode", "learning" }, "learning", null, null)]
    [InlineData(new[] { "--allow", "My Client", "198.51.100.7" }, null, "My Client", "198.51.100.7")]
    public void The_arguments_are_read(string[] args, string? mode, string? profile, string? address)
    {
        var options = ServiceOptions.Parse(args, out var error);

        Assert.NotNull(options);
        Assert.Empty(error);
        Assert.Equal((mode, profile, address), (options.SetMode, options.AllowProfile, options.AllowAddress));
    }

    [Theory]
    [InlineData("--set-mode")]
    [InlineData("--allow", "Test")]
    public void Arguments_that_lack_a_value_are_refused(params string[] args)
    {
        Assert.Null(ServiceOptions.Parse(args, out var error));
        Assert.Contains("Unknown or incomplete argument", error);
    }

    // --- running clients across a restart of the guard ------------------------------------------------

    private const int ClientPid = 4000003;
    private static readonly DateTimeOffset ClientStarted = new(2026, 11, 12, 14, 4, 58, 424, TimeSpan.Zero);

    private static string ClientEvent(int id) =>
        $"""
        <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
          <System>
            <Provider Name="Microsoft-Windows-Sysmon" Guid="{"{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"}" />
            <EventID>{id}</EventID>
            <TimeCreated SystemTime="2026-11-12T14:04:58.4250000Z" />
            <EventRecordID>79</EventRecordID>
            <Channel>Microsoft-Windows-Sysmon/Operational</Channel>
            <Computer>TESTPC</Computer>
          </System>
          <EventData>
            <Data Name="UtcTime">2026-11-12 14:04:58.424</Data>
            <Data Name="ProcessGuid">{"{11111111-c78a-6af5-4888-030000006801}"}</Data>
            <Data Name="ProcessId">{ClientPid}</Data>
            <Data Name="Image">{Client}</Data>
            <Data Name="CommandLine">"{Client}"</Data>
            <Data Name="ParentImage">C:\Windows\explorer.exe</Data>
            <Data Name="ParentProcessId">4000001</Data>
          </EventData>
        </Event>
        """;

    private GuardWorker Worker(ConcurrentQueue<DateTimeOffset> looks, params string[] events) =>
        new(new ServiceOptions { DataDirectory = folder, LogName = "Application" }, new ListLogger(), new Lifetime())
        {
            OpenFirewall = () => new FakeFirewall(),
            ListProcesses = () => [],
            DeliveryGrace = TimeSpan.FromSeconds(1),
            ConnectionPollInterval = TimeSpan.FromMilliseconds(100),
            ReadConnections = () => [],
            ReadProcessTimes = () =>
            {
                looks.Enqueue(DateTimeOffset.UtcNow);
                return new Dictionary<int, ProcessTime> { [ClientPid] = new ProcessTime(ClientPid, "Wow.exe", ClientStarted, TimeSpan.FromSeconds(looks.Count)) };
            },
            OpenTail = (_, _, onEntry, _) =>
            {
                var recordId = long.MaxValue / 2;
                foreach (var xml in events)
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
    public async Task A_client_that_runs_is_looked_at_again_after_a_restart_of_the_guard()
    {
        WriteConfig(top: """ "cpuAlertCores": 0, """);
        var clientsFile = Path.Combine(folder, ServiceOptions.ClientsFileName);

        // First run: the client starts. The guard notes it and is stopped while the client runs.
        var first = new ConcurrentQueue<DateTimeOffset>();
        var lines = await RunAsync(Worker(first, ClientEvent(1)), _ => first.Count >= 2);
        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        Assert.True(File.Exists(clientsFile));

        // Second run: no event tells of the client, and it is looked at all the same.
        var second = new ConcurrentQueue<DateTimeOffset>();
        lines = await RunAsync(Worker(second), _ => second.Count >= 2);

        Assert.Contains(lines, line => line.Contains("1 client(s) that ran when the guard stopped are looked at again"));
        Assert.InRange(second.Count, 2, int.MaxValue);
    }

    [Fact]
    public async Task A_client_that_ended_is_not_kept_and_a_list_that_cannot_be_read_is_said()
    {
        WriteConfig(top: """ "cpuAlertCores": 0, """);
        var clientsFile = Path.Combine(folder, ServiceOptions.ClientsFileName);

        // Start, end, and something the guard says a line about: once that line is there, both events are handled.
        var looks = new ConcurrentQueue<DateTimeOffset>();
        await RunAsync(Worker(looks, ClientEvent(1), ClientEvent(5), "<NotAnEvent/>"), logged => logged.Any(line => line.Contains("Skipped an event")));
        Assert.False(File.Exists(clientsFile));

        File.WriteAllText(clientsFile, "{ not json");
        var lines = await RunAsync(Worker(looks), logged => logged.Any(line => line.Contains("waiting for events")));
        Assert.Contains(lines, line => line.StartsWith("Warning: The list of running clients") && line.Contains("could not be read"));
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
