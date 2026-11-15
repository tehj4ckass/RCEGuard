using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Rules;
using RCEGuard.Core.State;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>
/// The connection table of Windows as a second source for the connections of a client: the real
/// table of this machine, the choice of rows, and the guard loop with a made-up table.
/// </summary>
public sealed class ConnectionTableTests : IDisposable
{
    private const string Client = @"C:\RCEGuardTest\Wow.exe";
    private const int ClientPid = 4000003;   // no process can have it: Windows only hands out multiples of four
    private static readonly DateTimeOffset ClientStarted = new(2026, 11, 12, 14, 4, 58, 424, TimeSpan.Zero);

    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-table-").FullName;

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(folder, recursive: true);
    }

    // --- the real table ------------------------------------------------------------------------
    [Theory]
    [InlineData("127.0.0.1")]
    [InlineData("::1")]
    public void The_table_of_windows_has_a_connection_of_this_process_with_its_ports(string loopback)
    {
        var address = IPAddress.Parse(loopback);
        var listener = new TcpListener(address, 0);
        listener.Start();
        try
        {
            var serverPort = ((IPEndPoint)listener.LocalEndpoint).Port;
            using var client = new TcpClient(address.AddressFamily);
            client.Connect(address, serverPort);
            using var accepted = listener.AcceptTcpClient();
            var clientPort = ((IPEndPoint)client.Client.LocalEndPoint!).Port;

            var mine = TcpConnections.Take().Where(row => row.ProcessId == Environment.ProcessId).ToList();

            Assert.Contains(mine, row => row.Listening && row.LocalPort == serverPort);
            // The end that connected, and the end that accepted.
            Assert.Contains(mine, row => !row.Listening && row.LocalPort == clientPort && row.RemotePort == serverPort && row.RemoteAddress.Equals(address));
            Assert.Contains(mine, row => !row.Listening && row.LocalPort == serverPort && row.RemotePort == clientPort && row.RemoteAddress.Equals(address));
            // Both ends are on this machine: nothing of it is a connection to somewhere else.
            Assert.DoesNotContain(TcpConnections.OutboundOf(Environment.ProcessId, mine), endpoint => endpoint.Port == serverPort || endpoint.Port == clientPort);
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public void Only_connections_the_process_made_itself_to_another_machine_count()
    {
        var server = IPAddress.Parse("203.0.113.9");
        TcpConnection[] table =
        [
            new(100, Listening: false, 50001, server, 3724),                                // counts
            new(100, Listening: false, 50002, IPAddress.Parse("::ffff:198.51.100.7"), 443), // counts, as an IPv4 address
            new(100, Listening: false, 50003, IPAddress.Parse("2001:db8::1"), 443),         // counts
            new(100, Listening: true, 8080, IPAddress.Any, 0),                              // listening
            new(100, Listening: false, 8080, IPAddress.Parse("192.0.2.50"), 61000),         // accepted on the listening port
            new(100, Listening: false, 50004, IPAddress.Loopback, 9000),                    // this machine
            new(100, Listening: false, 50005, IPAddress.IPv6Loopback, 9000),                // this machine
            new(100, Listening: false, 50006, IPAddress.Any, 0),                            // not connected yet
            new(200, Listening: false, 50007, IPAddress.Parse("192.0.2.99"), 443),          // another process
        ];

        var outbound = TcpConnections.OutboundOf(100, table);

        Assert.Equal(
            [new RemoteEndpoint(server, 3724), new RemoteEndpoint(IPAddress.Parse("198.51.100.7"), 443), new RemoteEndpoint(IPAddress.Parse("2001:db8::1"), 443)],
            outbound);
        Assert.Empty(TcpConnections.OutboundOf(300, table));
    }

    // --- the guard loop ------------------------------------------------------------------------
    private static string Event(int id, string data) =>
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
            <Data Name="UtcTime">2026-11-12 14:04:58.424</Data>
            <Data Name="ProcessId">{ClientPid}</Data>
            <Data Name="Image">{Client}</Data>
            {data}
          </EventData>
        </Event>
        """;

    private static string ClientStart => Event(1, """<Data Name="ProcessGuid">{11111111-c78a-6af5-4888-030000006801}</Data>""");

    private static string Connect(string ip, int port) => Event(
        3, $"""<Data Name="Initiated">true</Data><Data Name="DestinationIp">{ip}</Data><Data Name="DestinationPort">{port}</Data>""");

    private void WriteConfig(string profileSettings = "") => File.WriteAllText(
        Path.Combine(folder, "appsettings.json"),
        $$"""{ "cpuAlertCores": 0, "profiles": [ { "name": "Test", "clientPath": "{{Client.Replace(@"\", @"\\")}}" {{profileSettings}} } ] }""");

    private static IReadOnlyDictionary<int, ProcessTime> ClientRuns() => new Dictionary<int, ProcessTime>
    {
        [ClientPid] = new(ClientPid, "Wow.exe", ClientStarted, TimeSpan.FromSeconds(1)),
    };

    private static TcpConnection ToServer(string ip, int port = 3724, int pid = ClientPid) =>
        new(pid, Listening: false, 50001, IPAddress.Parse(ip), port);

    private GuardWorker Worker(Func<IReadOnlyList<TcpConnection>> table, params string[] events) =>
        new(new ServiceOptions { DataDirectory = folder, LogName = "Application" }, new ListLogger(), new Lifetime())
        {
            OpenFirewall = () => new FakeFirewall(),
            ReadProcessTimes = ClientRuns,
            ReadConnections = table,
            ConnectionPollInterval = TimeSpan.FromMilliseconds(100),
            ConnectionGrace = TimeSpan.FromMilliseconds(600),
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

    /// <summary>Runs the guard until <paramref name="done"/>, and then for <paramref name="longerMs"/> more.</summary>
    private static async Task<List<string>> RunAsync(GuardWorker worker, Func<IReadOnlyCollection<string>, bool> done, int longerMs = 0, int timeoutMs = 20_000)
    {
        var logger = (ListLogger)worker.Logger;
        await worker.StartAsync(CancellationToken.None);
        var watch = Stopwatch.StartNew();
        while (!done(logger.Lines) && !logger.Lines.Any(line => line.Contains("cannot run")) && watch.ElapsedMilliseconds < timeoutMs)
        {
            await Task.Delay(50);
        }

        await Task.Delay(longerMs);
        await worker.StopAsync(CancellationToken.None);
        worker.Dispose();
        return [.. logger.Lines];
    }

    [Fact]
    public async Task A_connection_sysmon_did_not_record_is_found_in_the_table_and_judged_once()
    {
        WriteConfig();
        IReadOnlyList<TcpConnection> table = [ToServer("203.0.113.9"), ToServer("192.0.2.1", pid: 8888)];

        var lines = await RunAsync(Worker(() => table, ClientStart), logged => logged.Any(line => line.Contains("R2 CRITICAL")), longerMs: 1500);

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        Assert.Contains(lines, line => line.Contains("Connections of a running client are also read from the connection table of Windows"));
        var found = Assert.Single(lines, line => line.Contains("found in the connection table of Windows"));
        Assert.Contains($"(pid {ClientPid}) to 203.0.113.9 port 3724", found);
        var alert = Assert.Single(lines, line => line.Contains("R2 CRITICAL"));
        Assert.Contains("[Test] The game client connected to an address that is not on the allowlist: 203.0.113.9:3724", alert);
        Assert.DoesNotContain(lines, line => line.Contains("192.0.2.1"));   // the connection of another process
    }

    [Fact]
    public async Task A_connection_sysmon_recorded_is_not_reported_a_second_time_from_the_table()
    {
        WriteConfig();
        IReadOnlyList<TcpConnection> table = [ToServer("203.0.113.9")];

        var lines = await RunAsync(
            Worker(() => table, ClientStart, Connect("203.0.113.9", 3724)),
            logged => logged.Any(line => line.Contains("R2 CRITICAL")),
            longerMs: 2000);

        Assert.Single(lines, line => line.Contains("R2 CRITICAL"));
        Assert.DoesNotContain(lines, line => line.Contains("found in the connection table"));
    }

    [Fact]
    public async Task A_connection_to_an_allowed_address_is_found_and_leaves_no_finding()
    {
        WriteConfig(""", "allowedRemote": ["203.0.113.0/24"] """);
        IReadOnlyList<TcpConnection> table = [ToServer("203.0.113.9")];

        var lines = await RunAsync(Worker(() => table, ClientStart), logged => logged.Any(line => line.Contains("found in the connection table")), longerMs: 500);

        Assert.Single(lines, line => line.Contains("found in the connection table"));
        Assert.DoesNotContain(lines, line => line.Contains(" R2 "));
    }

    [Fact]
    public async Task While_learning_a_connection_from_the_table_is_noted_like_one_from_sysmon()
    {
        WriteConfig(""", "learning": true """);
        IReadOnlyList<TcpConnection> table = [ToServer("203.0.113.9"), ToServer("2001:db8::1", 443)];

        var lines = await RunAsync(Worker(() => table, ClientStart), logged => logged.Count(line => line.Contains("R2 INFO")) >= 2, longerMs: 300);

        Assert.Contains(lines, line => line.Contains("R2 INFO [Test] Learning mode: the game client connected to 203.0.113.9:3724"));
        Assert.Contains(lines, line => line.Contains("R2 INFO [Test] Learning mode: the game client connected to [2001:db8::1]:443"));
        var learned = Assert.Single(new LearnedFile(Path.Combine(folder, LearnedFile.FileName)).Load(out var problem));
        Assert.Null(problem);
        Assert.Equal(["2001:db8::1:443 x1", "203.0.113.9:3724 x1"], learned.Remotes.Select(remote => $"{remote.Address}:{remote.Port} x{remote.Count}").Order());
    }

    [Fact]
    public async Task A_connection_that_closes_again_at_once_is_left_to_sysmon()
    {
        WriteConfig();
        var looks = 0;
        // In the table for the first two looks only.
        IReadOnlyList<TcpConnection> Table() => Interlocked.Increment(ref looks) <= 2 ? [ToServer("203.0.113.9")] : [];

        var lines = await RunAsync(Worker(Table, ClientStart), _ => looks >= 15);

        Assert.DoesNotContain(lines, line => line.Contains("found in the connection table") || line.Contains(" R2 "));
    }

    [Fact]
    public async Task A_table_that_cannot_be_read_is_said_once_and_the_guard_keeps_running()
    {
        WriteConfig();
        var looks = 0;
        IReadOnlyList<TcpConnection> Table()
        {
            Interlocked.Increment(ref looks);
            throw new Win32Exception(5, "Access is denied (stand-in).");
        }

        var lines = await RunAsync(Worker(Table, ClientStart), _ => looks >= 5);

        Assert.DoesNotContain(lines, line => line.Contains("cannot run"));
        var warning = Assert.Single(lines, line => line.Contains("The connection table of Windows cannot be read"));
        Assert.StartsWith("Warning", warning);
        Assert.Contains("Access is denied (stand-in).", warning);
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
