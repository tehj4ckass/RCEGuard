using System.Diagnostics.Eventing.Reader;
using System.Net;
using System.Threading.Channels;
using RCEGuard.Core.Configuration;
using RCEGuard.Core.Rules;
using RCEGuard.Core.Sysmon;

namespace RCEGuard.Service;

/// <summary>
/// The guard loop: subscribes to the Sysmon log, evaluates every new event and acts on the findings.
/// Events are handled one at a time in log order, because the rule engine keeps state.
/// </summary>
public sealed class GuardWorker : BackgroundService
{
    private const string SysmonLog = "Microsoft-Windows-Sysmon/Operational";
    private static readonly TimeSpan HostRefreshInterval = TimeSpan.FromMinutes(10);

    private readonly ServiceOptions options;
    private readonly ILogger<GuardWorker> logger;
    private readonly IHostApplicationLifetime lifetime;
    private readonly Channel<string> events = Channel.CreateUnbounded<string>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>Creates the worker.</summary>
    public GuardWorker(ServiceOptions options, ILogger<GuardWorker> logger, IHostApplicationLifetime lifetime)
    {
        this.options = options;
        this.logger = logger;
        this.lifetime = lifetime;
    }

    /// <inheritdoc />
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await RunAsync(stoppingToken);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Normal shutdown.
        }
        catch (Exception ex)
        {
            // Fail loudly: a guard that silently watches nothing is worse than one that is not running.
            if (ex is ChannelClosedException { InnerException: { } cause })
            {
                ex = cause;
            }

            logger.LogCritical("RCEGuard cannot run: {Reason}", Explain(ex));
            Environment.ExitCode = 1;
            lifetime.StopApplication();
        }
    }

    private async Task RunAsync(CancellationToken stoppingToken)
    {
        var config = options.LoadConfig(out var configSource);
        // A replay is about old events: their pids mean nothing any more, so it never terminates anything.
        var killEnabled = config.KillEnabled && !options.DryRun && options.ReplayPath is null;
        var engine = new RuleEngine(config, Environment.SystemDirectory);
        var killer = new ProcessKiller(dryRun: !killEnabled);
        using var store = new FindingStore(Path.Combine(options.DataDirectory, "findings.db"));

        foreach (var profile in config.Profiles)
        {
            logger.LogInformation(
                "Watching '{Name}': {Client} ({Count} allowed remote entries, {Hosts} host names)",
                profile.Name, profile.ClientPath, profile.AllowedRemote.Count, profile.AllowedHostnames.Count);
        }

        logger.LogInformation("Configuration from {Source}; terminating processes is {State}", configSource, killEnabled ? "ON" : "OFF (dry run)");

        if (options.ReplayPath is not null)
        {
            Replay(options.ReplayPath, engine, killer, store);
            lifetime.StopApplication();
            return;
        }

        // Fail closed: the watcher itself accepts a missing or unreadable log and then just delivers nothing.
        // Asking for the log's properties throws in both cases.
        using (var session = new EventLogSession())
        {
            _ = session.GetLogInformation(SysmonLog, PathType.LogName);
        }

        using var watcher = new EventLogWatcher(new EventLogQuery(SysmonLog, PathType.LogName, "*"));
        watcher.EventRecordWritten += OnEventRecordWritten;
        watcher.Enabled = true;
        logger.LogInformation("Subscribed to {Log}; waiting for events", SysmonLog);

        var nextHostRefresh = DateTimeOffset.MinValue;
        while (!stoppingToken.IsCancellationRequested)
        {
            if (DateTimeOffset.UtcNow >= nextHostRefresh)
            {
                await RefreshHostsAsync(config, engine, stoppingToken);
                nextHostRefresh = DateTimeOffset.UtcNow + HostRefreshInterval;
            }

            using var wait = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
            wait.CancelAfter(TimeSpan.FromSeconds(30));
            string xml;
            try
            {
                xml = await events.Reader.ReadAsync(wait.Token);
            }
            catch (OperationCanceledException) when (!stoppingToken.IsCancellationRequested)
            {
                continue; // Only woke up to check the host refresh.
            }

            Handle(xml, engine, killer, store);
        }
    }

    private void Replay(string path, RuleEngine engine, ProcessKiller killer, FindingStore store)
    {
        if (!File.Exists(path))
        {
            throw new FileNotFoundException($"Events file not found: {path}");
        }

        var count = 0;
        foreach (var element in System.Xml.Linq.XDocument.Load(path).Root?.Elements() ?? [])
        {
            Handle(element.ToString(System.Xml.Linq.SaveOptions.DisableFormatting), engine, killer, store);
            count++;
        }

        logger.LogInformation("Replayed {Count} events from {Path}", count, path);
    }

    private void OnEventRecordWritten(object? sender, EventRecordWrittenEventArgs args)
    {
        if (args.EventException is not null)
        {
            // The subscription is broken (log removed, Sysmon uninstalled, access lost). Closing the
            // channel with the error ends the guard loop instead of leaving it waiting for nothing.
            events.Writer.TryComplete(args.EventException);
            return;
        }

        using var record = args.EventRecord;
        if (record is not null)
        {
            events.Writer.TryWrite(record.ToXml());
        }
    }

    private void Handle(string xml, RuleEngine engine, ProcessKiller killer, FindingStore store)
    {
        if (!SysmonEventParser.TryParse(xml, out var sysmonEvent, out var error))
        {
            logger.LogWarning("Skipped an event that could not be read: {Reason}", error);
            return;
        }

        foreach (var finding in engine.Evaluate(sysmonEvent!))
        {
            var taken = "none";
            if (finding.Action == FindingAction.Kill)
            {
                taken = string.Join("; ", finding.KillTargets.Select(killer.Kill));
            }

            store.Add(finding, taken);

            var delayMs = (long)(DateTimeOffset.UtcNow - finding.Time).TotalMilliseconds;
            var level = finding.Severity switch
            {
                Severity.Critical => LogLevel.Critical,
                Severity.High => LogLevel.Warning,
                _ => LogLevel.Information,
            };
            logger.Log(
                level,
                "{Rule} {Severity} [{Profile}] {Summary} | action: {Action} -> {Taken} | {Delay} ms after the event",
                finding.RuleId, finding.Severity.ToString().ToUpperInvariant(), finding.Profile, finding.Summary, finding.Action, taken, delayMs);
        }
    }

    private async Task RefreshHostsAsync(GuardConfig config, RuleEngine engine, CancellationToken cancellationToken)
    {
        foreach (var profile in config.Profiles.Where(p => p.AllowedHostnames.Count > 0))
        {
            var addresses = new List<IPAddress>();
            var failed = 0;
            foreach (var host in profile.AllowedHostnames)
            {
                try
                {
                    addresses.AddRange(await Dns.GetHostAddressesAsync(host, cancellationToken));
                }
                catch (Exception ex) when (ex is System.Net.Sockets.SocketException or ArgumentException)
                {
                    failed++;
                    logger.LogWarning("Host name '{Host}' of profile '{Profile}' could not be resolved: {Reason}", host, profile.Name, ex.Message);
                }
            }

            // Keep the previous addresses if nothing could be resolved (e.g. no network yet).
            if (addresses.Count > 0 || failed == 0)
            {
                engine.SetResolvedHosts(profile.Name, addresses);
            }
        }
    }

    private string Explain(Exception ex) => ex switch
    {
        UnauthorizedAccessException => "no access to the Sysmon log. Start the console as administrator, or run RCEGuard as a service.",
        EventLogNotFoundException => "the Sysmon log does not exist. Install the sensor with scripts\\install.ps1 first.",
        EventLogException => $"the Sysmon log cannot be read: {ex.Message}",
        FileNotFoundException or FormatException or System.Xml.XmlException => ex.Message,
        Microsoft.Data.Sqlite.SqliteException => $"the findings database in '{options.DataDirectory}' cannot be opened: {ex.Message}",
        _ => ex.ToString(),
    };
}
