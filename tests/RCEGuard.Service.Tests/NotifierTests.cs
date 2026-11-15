using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Notifications;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service.Tests;

/// <summary>Stand-in for the network: notes every request and answers as told.</summary>
internal sealed class FakeHttp : HttpMessageHandler
{
    private readonly ConcurrentQueue<(string Method, string Url, Dictionary<string, string> Headers, string Body)> requests = new();

    /// <summary>Answers for the next requests, in order; when used up, 200.</summary>
    public ConcurrentQueue<HttpStatusCode> Answers { get; } = new();

    /// <summary>If set, every request fails like a server that cannot be reached.</summary>
    public bool Unreachable { get; set; }

    public IReadOnlyList<(string Method, string Url, Dictionary<string, string> Headers, string Body)> Requests => [.. requests];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var headers = request.Headers.ToDictionary(header => header.Key, header => string.Join(",", header.Value), StringComparer.OrdinalIgnoreCase);
        var body = request.Content is null ? string.Empty : await request.Content.ReadAsStringAsync(cancellationToken);
        requests.Enqueue((request.Method.Method, request.RequestUri!.ToString(), headers, body));
        if (Unreachable)
        {
            throw new HttpRequestException("No such host is known. (ntfy.example.org:443)");
        }

        return new HttpResponseMessage(Answers.TryDequeue(out var status) ? status : HttpStatusCode.OK);
    }
}

/// <summary>Stand-in for the notifier of the guard loop: keeps what it was given.</summary>
internal sealed class FakeNotifier : INotifier
{
    public ConcurrentQueue<Notification> Sent { get; } = new();

    public void Send(Notification notification) => Sent.Enqueue(notification);

    public Task FlushAsync(TimeSpan timeout) => Task.CompletedTask;
}

public sealed class NotifierTests : IDisposable
{
    private const string Topic = "https://ntfy.example.org/my-topic";
    private static readonly TimeSpan[] NoWait = [TimeSpan.FromMilliseconds(1), TimeSpan.FromMilliseconds(1)];

    // Not "ntfy" or "notif" in the name: the path is in log lines the tests search.
    private readonly string folder = Directory.CreateTempSubdirectory("rceguard-push-").FullName;
    private readonly FakeHttp http = new();
    private readonly ConcurrentQueue<string> log = new();

    public void Dispose()
    {
        Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
        Directory.Delete(folder, recursive: true);
    }

    private NtfyNotifier Notifier(string? token = "tk_example") =>
        new(new NtfyConfig { Url = Topic, Token = token }, (level, message) => log.Enqueue($"{level}: {message}"), http, NoWait);

    private static Notification Urgent(string title = "RCEGuard: R1 CRITICAL [Test]") => new(title, "line one\nline two", NotificationPriority.Urgent);

    [Fact]
    public async Task A_notification_is_posted_to_the_topic_with_title_priority_and_token()
    {
        using var notifier = Notifier();

        notifier.Send(Urgent());
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        var request = Assert.Single(http.Requests);
        Assert.Equal(("POST", Topic, "line one\nline two"), (request.Method, request.Url, request.Body));
        Assert.Equal("RCEGuard: R1 CRITICAL [Test]", request.Headers["Title"]);
        Assert.Equal("urgent", request.Headers["Priority"]);
        Assert.Equal("Bearer tk_example", request.Headers["Authorization"]);
        Assert.Empty(log);
    }

    [Fact]
    public async Task Without_a_token_no_authorization_is_sent_and_other_priorities_keep_their_names()
    {
        using var notifier = Notifier(token: null);

        notifier.Send(new Notification("t", "b", NotificationPriority.High));
        notifier.Send(new Notification("t", "b", NotificationPriority.Default));
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, http.Requests.Count);
        Assert.All(http.Requests, request => Assert.False(request.Headers.ContainsKey("Authorization")));
        Assert.Equal(["high", "default"], http.Requests.Select(request => request.Headers["Priority"]));
    }

    [Fact]
    public async Task A_title_with_characters_a_header_cannot_carry_is_still_sent()
    {
        using var notifier = Notifier();

        notifier.Send(Urgent("RCEGuard: R1 CRITICAL [Wärmäne]"));
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        Assert.Equal("RCEGuard: R1 CRITICAL [W?rm?ne]", Assert.Single(http.Requests).Headers["Title"]);
    }

    [Fact]
    public async Task A_delivery_that_fails_is_tried_again_and_says_nothing_when_it_then_works()
    {
        http.Answers.Enqueue(HttpStatusCode.ServiceUnavailable);
        http.Answers.Enqueue(HttpStatusCode.BadGateway);
        using var notifier = Notifier();

        notifier.Send(Urgent());
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(3, http.Requests.Count);
        Assert.Empty(log);
    }

    [Fact]
    public async Task An_outage_is_logged_once_with_the_reason_and_without_the_topic_and_its_end_with_the_count()
    {
        http.Unreachable = true;
        using var notifier = Notifier();

        notifier.Send(Urgent("first"));
        notifier.Send(Urgent("second"));
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        var warning = Assert.Single(log);
        Assert.StartsWith("Warning", warning);
        Assert.Contains("'first' could not be delivered to ntfy at https://ntfy.example.org:", warning);
        Assert.Contains("No such host is known", warning);
        Assert.DoesNotContain("my-topic", warning);    // the topic name is what protects an open topic
        Assert.DoesNotContain("tk_example", warning);
        Assert.Equal(6, http.Requests.Count);          // three attempts each

        http.Unreachable = false;
        notifier.Send(Urgent("third"));
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        Assert.Equal(2, log.Count);
        Assert.Contains("again; 2 could not be delivered before", log.Last());
    }

    [Fact]
    public async Task A_server_that_refuses_is_reported_with_its_answer()
    {
        foreach (var _ in Enumerable.Range(0, 3))
        {
            http.Answers.Enqueue(HttpStatusCode.Forbidden);
        }

        using var notifier = Notifier();
        notifier.Send(Urgent());
        await notifier.FlushAsync(TimeSpan.FromSeconds(5));

        Assert.Contains("the server answered 403", Assert.Single(log));
    }

    [Fact]
    public async Task The_test_command_says_whether_the_server_took_the_notification()
    {
        var options = new ServiceOptions { DataDirectory = folder, NotifyTest = true };
        var config = Path.Combine(folder, "appsettings.json");
        var output = new StringWriter();
        var error = new StringWriter();

        File.WriteAllText(config, """{"profiles":[{"name":"Test","clientPath":"C:\\RCEGuardTest\\Wow.exe"}]}""");
        Assert.Equal(1, await NotifyTestCommand.RunAsync(options, output, error, http));
        Assert.Contains("No ntfy topic is turned on", error.ToString());
        Assert.Empty(http.Requests);

        File.WriteAllText(config, """{"notify":{"ntfy":{"url":"URL"}},"profiles":[{"name":"Test","clientPath":"C:\\RCEGuardTest\\Wow.exe"}]}""".Replace("URL", Topic));
        Assert.Equal(0, await NotifyTestCommand.RunAsync(options, output, error, http));
        Assert.Contains("The server took it", output.ToString());
        Assert.DoesNotContain("my-topic", output.ToString());
        Assert.Equal("RCEGuard: test notification", Assert.Single(http.Requests).Headers["Title"]);

        http.Answers.Enqueue(HttpStatusCode.Unauthorized);
        error = new StringWriter();
        Assert.Equal(1, await NotifyTestCommand.RunAsync(options, output, error, http));
        Assert.Contains("the server answered 401", error.ToString());
    }

    [Fact]
    public void The_test_argument_is_understood()
    {
        var options = ServiceOptions.Parse(["--notify-test", "--data-dir", folder], out var error);

        Assert.NotNull(options);
        Assert.Empty(error);
        Assert.True(options.NotifyTest);
    }

    // --- the guard loop ---------------------------------------------------------------------------

    private const string Client = @"C:\RCEGuardTest\Wow.exe";

    private void WriteConfig(string extra = "", string client = Client) => File.WriteAllText(
        Path.Combine(folder, "appsettings.json"),
        $$"""{ {{extra}} "profiles":[{"name":"Test","clientPath":"{{client.Replace(@"\", @"\\")}}"}]}""");

    private const string WithTopic = """ "notify":{"ntfy":{"url":"https://ntfy.example.org/my-topic"}}, """;

    /// <summary>
    /// The processes the guard finds running when it stops. None by default: a program named like the
    /// test client on the machine of the test (the simulator, or a real game client: Windows compares
    /// the names without case) would otherwise add a "stopping while the client runs" notification.
    /// </summary>
    private Func<IReadOnlyList<ProcessEntry>> runningProcesses = () => [];

    private GuardWorker Worker(FakeNotifier notifier, ServiceOptions? options = null, params string[] events) =>
        new(options ?? new ServiceOptions { DataDirectory = folder, LogName = "Application" }, new ListLogger(), new Lifetime())
        {
            ListProcesses = () => runningProcesses(),
            OpenFirewall = () => new FakeFirewall(),
            OpenNotifier = (_, _) => notifier,
            DeliveryGrace = TimeSpan.FromSeconds(1),
            OpenTail = (_, _, onEntry, _) =>
            {
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
    public async Task A_finding_that_terminates_the_client_is_sent_with_what_was_done()
    {
        WriteConfig(WithTopic);
        var notifier = new FakeNotifier();

        var lines = await RunAsync(Worker(notifier, null, LockdownTests.ChildProcessEventXml), logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        var sent = Assert.Single(notifier.Sent);
        Assert.Equal("RCEGuard: R1 CRITICAL [Test]", sent.Title);
        Assert.Contains("started another program", sent.Body);
        Assert.Contains("Action: ", sent.Body);
        Assert.Contains(lines, line => line.Contains("also sent to ntfy at https://ntfy.example.org") && !line.Contains("my-topic"));
    }

    [Fact]
    public async Task Without_an_ntfy_topic_nothing_is_sent_and_no_notifier_is_opened()
    {
        WriteConfig();
        var notifier = new FakeNotifier();

        await RunAsync(Worker(notifier, null, LockdownTests.ChildProcessEventXml), logged => logged.Any(line => line.Contains("R1 CRITICAL")));

        Assert.Empty(notifier.Sent);
    }

    [Fact]
    public async Task A_guard_that_was_not_stopped_the_regular_way_says_so_at_its_next_start()
    {
        WriteConfig(WithTopic);
        var marker = Path.Combine(folder, ServiceOptions.RunningMarkerName);
        File.WriteAllText(marker, "left behind by a run that was ended from outside");
        var notifier = new FakeNotifier();

        var lines = await RunAsync(Worker(notifier), logged => logged.Any(line => line.Contains("Subscribed to")));

        Assert.Contains(lines, line => line.StartsWith("Warning") && line.Contains("did not stop the regular way"));
        Assert.Equal("RCEGuard was ended unexpectedly", Assert.Single(notifier.Sent).Title);
        // This run stopped the regular way: the note is gone, and the next start is quiet.
        Assert.False(File.Exists(marker));
        var again = new FakeNotifier();
        var second = await RunAsync(Worker(again), logged => logged.Any(line => line.Contains("Subscribed to")));
        Assert.Empty(again.Sent);
        Assert.DoesNotContain(second, line => line.Contains("did not stop the regular way"));
    }

    [Fact]
    public async Task While_the_guard_runs_its_note_is_in_the_data_folder()
    {
        WriteConfig();
        var marker = Path.Combine(folder, ServiceOptions.RunningMarkerName);
        var seenWhileRunning = false;

        await RunAsync(Worker(new FakeNotifier()), logged =>
        {
            var subscribed = logged.Any(line => line.Contains("Subscribed to"));
            seenWhileRunning |= subscribed && File.Exists(marker);
            return subscribed;
        });

        Assert.True(seenWhileRunning, "the note was not there while the guard was running");
        Assert.False(File.Exists(marker));
    }

    [Fact]
    public async Task A_guard_that_cannot_run_says_so_and_does_not_count_as_ended_unexpectedly()
    {
        WriteConfig(WithTopic);
        var notifier = new FakeNotifier();
        var worker = new GuardWorker(new ServiceOptions { DataDirectory = folder, LogName = "Application" }, new ListLogger(), new Lifetime())
        {
            OpenFirewall = () => new FakeFirewall(),
            OpenNotifier = (_, _) => notifier,
            // The subscription breaks at once, as when the log is taken away.
            OpenTail = (_, _, _, onError) =>
            {
                onError(new InvalidOperationException("the log is gone (stand-in)"));
                return new MemoryStream();
            },
        };

        List<string> lines;
        try
        {
            lines = await RunAsync(worker, _ => false);
        }
        finally
        {
            Environment.ExitCode = 0;   // outside a Windows service the worker reports the failure through the exit code
        }

        Assert.Contains(lines, line => line.Contains("cannot run"));
        var sent = Assert.Single(notifier.Sent);
        Assert.Equal("RCEGuard cannot run", sent.Title);
        Assert.Contains("the log is gone (stand-in)", sent.Body);
        Assert.False(File.Exists(Path.Combine(folder, ServiceOptions.RunningMarkerName)));
    }

    [Fact]
    public async Task Stopping_the_guard_while_the_client_runs_is_reported()
    {
        // A harmless program stands in for the client: the guard only looks at the name of the running program.
        using var client = Process.Start(new ProcessStartInfo("cmd.exe", "/c ping -n 30 127.0.0.1 > nul") { CreateNoWindow = true, UseShellExecute = false })!;
        try
        {
            WriteConfig(WithTopic, client: Path.Combine(Environment.SystemDirectory, "cmd.exe"));
            runningProcesses = ProcessSnapshot.Take;   // the real list: this test is about it
            var notifier = new FakeNotifier();

            var lines = await RunAsync(Worker(notifier), logged => logged.Any(line => line.Contains("Subscribed to")));

            Assert.Contains(lines, line => line.StartsWith("Warning") && line.Contains("is stopping while cmd.exe is running"));
            Assert.Contains(notifier.Sent, sent => sent.Title == "RCEGuard is stopping while the client runs" && sent.Priority == NotificationPriority.Urgent);
        }
        finally
        {
            client.Kill(entireProcessTree: true);
        }
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
